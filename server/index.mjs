import express from "express";
import dotenv from "dotenv";
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { google } from "googleapis";
import { createClient } from "@supabase/supabase-js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI,
  FRONTEND_URL = "http://localhost:5173",
  SERVER_PORT = "8787",
  VIRUSTOTAL_API_KEY,
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
} = process.env;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REDIRECT_URI) {
  console.warn("Missing Google OAuth env vars. Set them in server/.env before connecting.");
}
if (!VIRUSTOTAL_API_KEY) {
  console.warn("Missing VirusTotal API key. Set VIRUSTOTAL_API_KEY in server/.env to enable scans.");
}
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.warn("Supabase not configured. Set SUPABASE_URL and SUPABASE_SERVICE_KEY to persist scans.");
}

const app = express();
app.use(express.json({ limit: "1mb" }));

const allowedOrigins = new Set(
  [FRONTEND_URL, "https://mail-guard-drab.vercel.app"].filter(Boolean)
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  return next();
});
const supabase =
  SUPABASE_URL && SUPABASE_SERVICE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
    : null;
const oauth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

const TOKEN_PATH = path.join(__dirname, "token.json");
let cachedToken = null;
let cachedEmail = null;
const vtCache = new Map();
const vtWindowMs = 60_000;
const vtMaxRequests = 4;
let vtWindowStart = Date.now();
let vtRequestCount = 0;

const loadToken = () => {
  try {
    const raw = fs.readFileSync(TOKEN_PATH, "utf-8");
    cachedToken = JSON.parse(raw);
    oauth2Client.setCredentials(cachedToken);
  } catch (error) {
    cachedToken = null;
  }
};

const saveToken = (token) => {
  cachedToken = token;
  fs.writeFileSync(TOKEN_PATH, JSON.stringify(token, null, 2));
};

loadToken();

const SCOPES = [
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/drive.readonly",
];

const ensureAuth = async (req, res, next) => {
  if (!cachedToken) {
    return res.status(401).json({ connected: false, error: "Not connected" });
  }
  oauth2Client.setCredentials(cachedToken);
  return next();
};

const gmail = google.gmail({ version: "v1", auth: oauth2Client });
const drive = google.drive({ version: "v3", auth: oauth2Client });

const decodeBase64 = (input) => {
  if (!input) return "";
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, "base64").toString("utf-8");
};

const extractUrls = (text) => {
  const matches = text.match(/https?:\/\/[^\s"'>)]+/gi);
  return matches ? matches : [];
};

const extractClickableUrls = (html) => {
  if (!html) return [];
  const matches = [...html.matchAll(/<a[^>]+href=["']([^"']+)["']/gi)].map((m) => m[1]);
  return matches.filter((href) => href.startsWith("http://") || href.startsWith("https://"));
};

const extractDriveFileId = (url) => {
  if (!url) return null;
  const fileMatch = url.match(/https?:\/\/drive\.google\.com\/file\/d\/([^/]+)/i);
  if (fileMatch) return fileMatch[1];
  const openMatch = url.match(/https?:\/\/drive\.google\.com\/open\?id=([^&]+)/i);
  if (openMatch) return openMatch[1];
  const ucMatch = url.match(/https?:\/\/drive\.google\.com\/uc\?id=([^&]+)/i);
  if (ucMatch) return ucMatch[1];
  return null;
};


const getDomain = (url) => {
  try {
    const parsed = new URL(url);
    return parsed.hostname.replace(/^www\./, "");
  } catch (error) {
    return "";
  }
};

const parseFromHeader = (value) => {
  if (!value) return { name: "Unknown", email: "unknown" };
  const match = value.match(/^(.*)<([^>]+)>/);
  if (match) {
    return { name: match[1].trim().replace(/"/g, ""), email: match[2].trim() };
  }
  return { name: value, email: value };
};

const flattenParts = (payload) => {
  if (!payload) return [];
  const parts = [payload];
  if (payload.parts) {
    payload.parts.forEach((part) => {
      parts.push(...flattenParts(part));
    });
  }
  return parts;
};

const findBestBody = (parts, mimeType) => {
  const match = parts.find((part) => part?.mimeType === mimeType && part?.body?.data);
  return match ? decodeBase64(match.body.data) : "";
};

const scoreEmail = ({
  senderDomain,
  subject,
  bodyText,
  linkDomains,
  attachmentTypes,
  attachmentCount,
}) => {
  let score = 8;
  const reasons = [];

  const loweredSubject = subject.toLowerCase();
  const loweredBody = bodyText.toLowerCase();

  const urgencySignals = ["urgent", "action required", "verify", "password", "invoice", "payment", "failed"];
  if (urgencySignals.some((signal) => loweredSubject.includes(signal) || loweredBody.includes(signal))) {
    score += 16;
    reasons.push("Urgent or credential-related language detected.");
  }

  const shorteners = ["bit.ly", "tinyurl.com", "short.link", "t.co", "cutt.ly"];
  if (linkDomains.some((domain) => shorteners.includes(domain))) {
    score += 22;
    reasons.push("URL shortener hides destination.");
  }

  const suspiciousAttachments = ["exe", "js", "vbs", "bat", "cmd", "scr", "ps1", "docm", "xlsm"];
  if (attachmentTypes.some((type) => suspiciousAttachments.includes(type))) {
    score += 28;
    reasons.push("Potentially dangerous attachment type detected.");
  }

  if (attachmentCount > 0) {
    score += 8;
    reasons.push("Email contains attachments.");
  }

  if (linkDomains.length > 0) {
    score += Math.min(linkDomains.length * 6, 18);
    reasons.push("External links detected in the message.");
  }

  if (senderDomain && linkDomains.some((domain) => domain && !domain.endsWith(senderDomain))) {
    score += 14;
    reasons.push("Link domain does not match sender domain.");
  }

  if (score < 10) {
    reasons.push("No high-risk indicators detected.");
  }

  return { score: Math.min(score, 100), reasons };
};

const vtHeaders = () => ({
  "x-apikey": VIRUSTOTAL_API_KEY,
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const vtWithinLimit = () => {
  const now = Date.now();
  if (now - vtWindowStart > vtWindowMs) {
    vtWindowStart = now;
    vtRequestCount = 0;
  }
  if (vtRequestCount >= vtMaxRequests) return false;
  vtRequestCount += 1;
  return true;
};

const vtWaitForSlot = async () => {
  while (!vtWithinLimit()) {
    await sleep(1000);
  }
};

const vtCacheGet = (key) => {
  const hit = vtCache.get(key);
  if (!hit) return null;
  if (Date.now() > hit.expiresAt) {
    vtCache.delete(key);
    return null;
  }
  return hit.value;
};

const vtCacheSet = (key, value, ttlMs = 24 * 60 * 60 * 1000) => {
  vtCache.set(key, { value, expiresAt: Date.now() + ttlMs });
};

const vtFetchAnalysis = async (analysisId) => {
  await vtWaitForSlot();
  const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
    headers: vtHeaders(),
  });
  if (!res.ok) {
    throw new Error(`VT analysis fetch failed: ${res.status}`);
  }
  const data = await res.json();
  return data?.data?.attributes || {};
};

const vtWaitForAnalysis = async (analysisId) => {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const attrs = await vtFetchAnalysis(analysisId);
    if (attrs.status === "completed") return attrs;
    await sleep(1200);
  }
  return vtFetchAnalysis(analysisId);
};

const vtVerdictFromStats = (stats) => {
  if (!stats) return { verdict: "Unknown", score: 0 };
  if (stats.malicious > 0) return { verdict: "Dangerous", score: stats.malicious };
  if (stats.suspicious > 0) return { verdict: "Suspicious", score: stats.suspicious };
  return { verdict: "Safe", score: 0 };
};

app.get("/auth/google", (req, res) => {
  const loginHint = req.query.login_hint ? String(req.query.login_hint) : undefined;
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    include_granted_scopes: true,
    login_hint: loginHint,
  });

  res.redirect(url);
});

app.get("/auth/google/callback", async (req, res) => {
  const code = req.query.code ? String(req.query.code) : null;
  if (!code) {
    return res.status(400).send("Missing code");
  }

  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    saveToken(tokens);
    cachedEmail = null;
    return res.redirect(303, `${FRONTEND_URL}/?connected=1`);
  } catch (error) {
    console.error(error);
    return res.status(500).send("Failed to authenticate");
  }
});

app.post("/auth/logout", (req, res) => {
  cachedToken = null;
  cachedEmail = null;
  if (fs.existsSync(TOKEN_PATH)) {
    fs.unlinkSync(TOKEN_PATH);
  }
  res.json({ connected: false });
});

app.get("/api/status", async (req, res) => {
  if (!cachedToken) {
    return res.json({ connected: false });
  }

  try {
    oauth2Client.setCredentials(cachedToken);
    if (!cachedEmail) {
      const profile = await gmail.users.getProfile({ userId: "me" });
      cachedEmail = profile.data.emailAddress || null;
    }
    return res.json({ connected: true, email: cachedEmail });
  } catch (error) {
    return res.status(401).json({ connected: false, error: "Token invalid" });
  }
});

app.get("/api/messages", ensureAuth, async (req, res) => {
  try {
    const list = await gmail.users.messages.list({
      userId: "me",
      maxResults: 12,
      q: "newer_than:7d",
    });

    const messageIds = list.data.messages || [];
    const fullMessages = await Promise.all(
      messageIds.map(async (message) => {
        const result = await gmail.users.messages.get({
          userId: "me",
          id: message.id,
          format: "full",
        });
        return result.data;
      })
    );

    const mapped = fullMessages.map((message) => {
      const headers = message.payload?.headers || [];
      const headerMap = headers.reduce((acc, header) => {
        acc[header.name.toLowerCase()] = header.value || "";
        return acc;
      }, {});

      const fromHeader = parseFromHeader(headerMap.from || "Unknown");
      const senderDomain = fromHeader.email.split("@").pop() || "unknown";
      const subject = headerMap.subject || "(No subject)";
      const receivedAt = headerMap.date || "";
      const snippet = message.snippet || "";

      const parts = flattenParts(message.payload);
      const textParts = parts.filter((part) => part?.mimeType === "text/plain" && part?.body?.data);
      const htmlParts = parts.filter((part) => part?.mimeType === "text/html" && part?.body?.data);
      const bodyText = textParts.map((part) => decodeBase64(part.body.data)).join(" ");
      const bodyHtml = htmlParts.map((part) => decodeBase64(part.body.data)).join(" ");
      const combinedBody = `${snippet} ${bodyText} ${bodyHtml}`;

      const attachments = parts.filter((part) => part?.filename);
      const attachmentTypes = attachments
        .map((part) => part.filename.split(".").pop()?.toLowerCase())
        .filter(Boolean);

      const urls = extractUrls(combinedBody);
      const linkDomains = Array.from(new Set(urls.map(getDomain).filter(Boolean)));

      const { score, reasons } = scoreEmail({
        senderDomain,
        subject,
        bodyText: combinedBody,
        linkDomains,
        attachmentTypes,
        attachmentCount: attachments.length,
      });

      return {
        id: message.id,
        sender: fromHeader.name,
        senderDomain,
        subject,
        preview: snippet,
        bodyText,
        bodyHtml,
        receivedAt,
        linkCount: urls.length,
        attachmentCount: attachments.length,
        attachmentTypes,
        linkDomains,
        riskScore: score,
        reasons,
      };
    });

    res.json({ messages: mapped });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

app.post("/api/scan/:id", ensureAuth, async (req, res) => {
  if (!VIRUSTOTAL_API_KEY) {
    return res.status(500).json({ error: "VirusTotal API key not configured" });
  }

  const messageId = req.params.id;

  try {
    if (!cachedEmail) {
      const profile = await gmail.users.getProfile({ userId: "me" });
      cachedEmail = profile.data.emailAddress || null;
    }

    if (supabase && cachedEmail) {
      const { data, error } = await supabase
        .from("scan_results")
        .select("message_id, verdict, stats, url_results, file_results, created_at")
        .eq("account_email", cachedEmail)
        .eq("message_id", messageId)
        .limit(1)
        .maybeSingle();

      if (error) {
        console.warn("Supabase read failed", error);
      } else if (data) {
        return res.json({
          messageId,
          urlCount: data.url_results?.length || 0,
          fileCount: data.file_results?.length || 0,
          urlResults: data.url_results || [],
          fileResults: data.file_results || [],
          verdict: data.verdict,
          stats: data.stats,
          cached: true,
        });
      }
    }

    const result = await gmail.users.messages.get({
      userId: "me",
      id: messageId,
      format: "full",
    });
    const message = result.data;
    const snippet = message.snippet || "";

    const parts = flattenParts(message.payload);
    const bodyText = findBestBody(parts, "text/plain");
    const bodyHtml = findBestBody(parts, "text/html");
    const combinedBody = `${snippet} ${bodyText} ${bodyHtml}`;

    const clickableUrls = extractClickableUrls(bodyHtml);
    const fallbackUrls = extractUrls(`${snippet} ${bodyText}`);
    const urls = Array.from(new Set([...clickableUrls, ...fallbackUrls])).slice(0, 5);

    const driveFiles = [];
    for (const url of urls) {
      const fileId = extractDriveFileId(url);
      if (fileId) {
        driveFiles.push({ url, fileId });
      }
    }

    const urlResults = [];
    for (const url of urls) {
      const cached = vtCacheGet(`url:${url}`);
      if (cached) {
        urlResults.push({ url, stats: cached.stats, verdict: cached.verdict, cached: true });
        continue;
      }
      if (supabase) {
        const { data, error } = await supabase
          .from("scan_url_cache")
          .select("verdict, stats")
          .eq("url", url)
          .maybeSingle();
        if (error) {
          console.warn("Supabase url cache read failed", error);
        } else if (data) {
          const payload = { verdict: data.verdict, stats: data.stats };
          vtCacheSet(`url:${url}`, payload);
          urlResults.push({ url, stats: data.stats, verdict: data.verdict, cached: true });
          continue;
        }
      }
      await vtWaitForSlot();
      const form = new FormData();
      form.append("url", url);
      const submit = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: vtHeaders(),
        body: form,
      });
      if (!submit.ok) {
        urlResults.push({ url, error: `submit failed: ${submit.status}` });
        continue;
      }
      const submitData = await submit.json();
      const analysisId = submitData?.data?.id;
      if (!analysisId) {
        urlResults.push({ url, error: "no analysis id" });
        continue;
      }
      const attrs = await vtWaitForAnalysis(analysisId);
      const stats = attrs.stats || {};
      const verdict = vtVerdictFromStats(stats);
      const payload = { stats, verdict: verdict.verdict };
      vtCacheSet(`url:${url}`, payload);
      urlResults.push({ url, stats, verdict: verdict.verdict });
      if (supabase) {
        const { error } = await supabase
          .from("scan_url_cache")
          .upsert({ url, verdict: verdict.verdict, stats }, { onConflict: "url" });
        if (error) {
          console.warn("Supabase url cache write failed", error);
        }
      }
    }

    const attachments = parts.filter((part) => {
      if (!part?.filename || !part?.body?.attachmentId) return false;
      if (part?.disposition === "inline") return false;
      if (part?.mimeType && part.mimeType.startsWith("image/")) return false;
      return true;
    });
    const fileResults = [];
    for (const attachment of attachments) {
      const size = attachment?.body?.size || 0;
      if (size > 32 * 1024 * 1024) {
        fileResults.push({
          name: attachment.filename,
          error: "file too large for VirusTotal API (over 32MB)",
        });
        continue;
      }

      const attachmentData = await gmail.users.messages.attachments.get({
        userId: "me",
        messageId,
        id: attachment.body.attachmentId,
      });
      const raw = attachmentData?.data?.data || "";
      const buffer = Buffer.from(raw.replace(/-/g, "+").replace(/_/g, "/"), "base64");
      const hash = crypto.createHash("sha256").update(buffer).digest("hex");
      const cached = vtCacheGet(`file:${hash}`);
      if (cached) {
        fileResults.push({
          name: attachment.filename,
          stats: cached.stats,
          verdict: cached.verdict,
          cached: true,
        });
        continue;
      }
      if (supabase) {
        const { data, error } = await supabase
          .from("scan_file_cache")
          .select("verdict, stats")
          .eq("sha256", hash)
          .maybeSingle();
        if (error) {
          console.warn("Supabase file cache read failed", error);
        } else if (data) {
          const payload = { verdict: data.verdict, stats: data.stats };
          vtCacheSet(`file:${hash}`, payload);
          fileResults.push({
            name: attachment.filename,
            stats: data.stats,
            verdict: data.verdict,
            cached: true,
          });
          continue;
        }
      }
      await vtWaitForSlot();
      const form = new FormData();
      form.append("file", new Blob([buffer]), attachment.filename || "attachment");

      const submit = await fetch("https://www.virustotal.com/api/v3/files", {
        method: "POST",
        headers: vtHeaders(),
        body: form,
      });

      if (!submit.ok) {
        fileResults.push({ name: attachment.filename, error: `submit failed: ${submit.status}` });
        continue;
      }
      const submitData = await submit.json();
      const analysisId = submitData?.data?.id;
      if (!analysisId) {
        fileResults.push({ name: attachment.filename, error: "no analysis id" });
        continue;
      }
      const attrs = await vtWaitForAnalysis(analysisId);
      const stats = attrs.stats || {};
      const verdict = vtVerdictFromStats(stats);
      const payload = { stats, verdict: verdict.verdict };
      vtCacheSet(`file:${hash}`, payload);
      fileResults.push({ name: attachment.filename, stats, verdict: verdict.verdict });
      if (supabase) {
        const { error } = await supabase.from("scan_file_cache").upsert(
          { sha256: hash, filename: attachment.filename, verdict: verdict.verdict, stats },
          { onConflict: "sha256" }
        );
        if (error) {
          console.warn("Supabase file cache write failed", error);
        }
      }
    }

    for (const driveItem of driveFiles) {
      try {
        const fileMeta = await drive.files.get({
          fileId: driveItem.fileId,
          fields: "name,size,mimeType",
        });
        const size = Number(fileMeta.data.size || 0);
        if (size > 32 * 1024 * 1024) {
          fileResults.push({ name: fileMeta.data.name || driveItem.fileId, error: "drive file too large" });
          continue;
        }
        const driveRes = await drive.files.get(
          { fileId: driveItem.fileId, alt: "media" },
          { responseType: "arraybuffer" }
        );
        const buffer = Buffer.from(driveRes.data);
        const hash = crypto.createHash("sha256").update(buffer).digest("hex");

        const cached = vtCacheGet(`file:${hash}`);
        if (cached) {
          fileResults.push({
            name: fileMeta.data.name || driveItem.fileId,
            stats: cached.stats,
            verdict: cached.verdict,
            cached: true,
            source: "drive",
          });
          continue;
        }
        if (supabase) {
          const { data, error } = await supabase
            .from("scan_file_cache")
            .select("verdict, stats")
            .eq("sha256", hash)
            .maybeSingle();
          if (error) {
            console.warn("Supabase file cache read failed", error);
          } else if (data) {
            const payload = { verdict: data.verdict, stats: data.stats };
            vtCacheSet(`file:${hash}`, payload);
            fileResults.push({
              name: fileMeta.data.name || driveItem.fileId,
              stats: data.stats,
              verdict: data.verdict,
              cached: true,
              source: "drive",
            });
            continue;
          }
        }

        await vtWaitForSlot();
        const form = new FormData();
        form.append("file", new Blob([buffer]), fileMeta.data.name || "drive-file");
        const submit = await fetch("https://www.virustotal.com/api/v3/files", {
          method: "POST",
          headers: vtHeaders(),
          body: form,
        });
        if (!submit.ok) {
          fileResults.push({
            name: fileMeta.data.name || driveItem.fileId,
            error: `drive submit failed: ${submit.status}`,
            source: "drive",
          });
          continue;
        }
        const submitData = await submit.json();
        const analysisId = submitData?.data?.id;
        if (!analysisId) {
          fileResults.push({ name: fileMeta.data.name || driveItem.fileId, error: "no analysis id", source: "drive" });
          continue;
        }
        const attrs = await vtWaitForAnalysis(analysisId);
        const stats = attrs.stats || {};
        const verdict = vtVerdictFromStats(stats);
        const payload = { stats, verdict: verdict.verdict };
        vtCacheSet(`file:${hash}`, payload);
        fileResults.push({
          name: fileMeta.data.name || driveItem.fileId,
          stats,
          verdict: verdict.verdict,
          source: "drive",
        });
        if (supabase) {
          const { error } = await supabase.from("scan_file_cache").upsert(
            { sha256: hash, filename: fileMeta.data.name, verdict: verdict.verdict, stats },
            { onConflict: "sha256" }
          );
          if (error) {
            console.warn("Supabase file cache write failed", error);
          }
        }
      } catch (err) {
        fileResults.push({
          name: driveItem.fileId,
          error: "drive access failed",
          source: "drive",
        });
      }
    }

    const combinedStats = [...urlResults, ...fileResults].reduce(
      (acc, item) => {
        const stats = item.stats || {};
        acc.malicious += stats.malicious || 0;
        acc.suspicious += stats.suspicious || 0;
        return acc;
      },
      { malicious: 0, suspicious: 0 }
    );
    const overall = vtVerdictFromStats(combinedStats);

    if (supabase && cachedEmail) {
      const insertPayload = {
        account_email: cachedEmail,
        message_id: messageId,
        verdict: overall.verdict,
        stats: combinedStats,
        url_results: urlResults,
        file_results: fileResults,
      };
      const { error } = await supabase
        .from("scan_results")
        .upsert(insertPayload, { onConflict: "account_email,message_id", ignoreDuplicates: true });
      if (error) {
        console.warn("Supabase insert failed", error);
      }
    }

    const cachedAny = [...urlResults, ...fileResults].some((item) => item.cached);

    return res.json({
      messageId,
      urlCount: urls.length,
      fileCount: attachments.length,
      urlResults,
      fileResults,
      verdict: overall.verdict,
      stats: combinedStats,
      cached: cachedAny,
    });
  } catch (error) {
    console.error(error);
    if (String(error?.message) === "rate_limit") {
      return res.status(429).json({ error: "VirusTotal rate limit exceeded" });
    }
    return res.status(500).json({ error: "Failed to scan message" });
  }
});

app.post("/api/scan/status", ensureAuth, async (req, res) => {
  if (!supabase) {
    return res.json({ results: [] });
  }
  const ids = Array.isArray(req.body?.ids) ? req.body.ids : [];
  if (ids.length === 0) {
    return res.json({ results: [] });
  }
  try {
    if (!cachedEmail) {
      const profile = await gmail.users.getProfile({ userId: "me" });
      cachedEmail = profile.data.emailAddress || null;
    }
    if (!cachedEmail) {
      return res.json({ results: [] });
    }
    const { data, error } = await supabase
      .from("scan_results")
      .select("message_id, verdict, stats")
      .eq("account_email", cachedEmail)
      .in("message_id", ids);
    if (error) {
      console.warn("Supabase scan status read failed", error);
      return res.json({ results: [] });
    }
    return res.json({ results: data || [] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to load scan status" });
  }
});

app.get("/api/db/health", async (req, res) => {
  if (!supabase) {
    return res.status(500).json({ ok: false, error: "supabase_not_configured" });
  }
  try {
    const { data, error } = await supabase
      .from("scan_results")
      .select("id", { count: "exact", head: true });
    if (error) {
      return res.status(500).json({ ok: false, error: error.message });
    }
    return res.json({ ok: true, count: data?.length ?? 0 });
  } catch (err) {
    return res.status(500).json({ ok: false, error: "db_health_failed" });
  }
});

app.post("/api/db/write-test", async (req, res) => {
  if (!supabase) {
    return res.status(500).json({ ok: false, error: "supabase_not_configured" });
  }
  try {
    const payload = {
      account_email: "test@example.com",
      message_id: `test-${Date.now()}`,
      verdict: "Safe",
      stats: { malicious: 0, suspicious: 0 },
      url_results: [],
      file_results: [],
    };
    const { data, error } = await supabase.from("scan_results").insert(payload).select("id");
    if (error) {
      return res.status(500).json({ ok: false, error: error.message });
    }
    return res.json({ ok: true, inserted: data?.[0]?.id ?? null });
  } catch (err) {
    return res.status(500).json({ ok: false, error: "db_write_failed" });
  }
});

app.listen(Number(SERVER_PORT), () => {
  console.log(`MailGuard server listening on ${SERVER_PORT}`);
});
