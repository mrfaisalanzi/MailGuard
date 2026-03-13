import { useEffect, useMemo, useState } from "react";

type RiskLevel = "Safe" | "Suspicious" | "Dangerous";

type EmailItem = {
  id: string;
  sender: string;
  senderDomain: string;
  subject: string;
  preview: string;
  bodyText?: string;
  bodyHtml?: string;
  receivedAt: string;
  linkCount: number;
  attachmentCount: number;
  attachmentTypes: string[];
  linkDomains: string[];
  riskScore: number;
  reasons: string[];
};

type ScanVerdict = "Safe" | "Suspicious" | "Dangerous" | "Unknown";

type ScanResult = {
  verdict: ScanVerdict;
  stats?: { malicious?: number; suspicious?: number };
  error?: string;
  cached?: boolean;
};

const EMPTY_EMAILS: EmailItem[] = [];

const RISK_BANDS: { label: RiskLevel; min: number; max: number; description: string }[] = [
  { label: "Safe", min: 0, max: 29, description: "Low risk. Normal business patterns." },
  { label: "Suspicious", min: 30, max: 69, description: "Potential phishing signals detected." },
  { label: "Dangerous", min: 70, max: 100, description: "High probability of malicious intent." },
];

export default function App() {
  const [connected, setConnected] = useState(false);
  const [accountEmail, setAccountEmail] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [language, setLanguage] = useState<"en" | "ar">("en");
  const [busy, setBusy] = useState(false);
  const [emails, setEmails] = useState<EmailItem[]>(EMPTY_EMAILS);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [scanResults, setScanResults] = useState<Record<string, ScanResult>>({});
  const [scanningIds, setScanningIds] = useState<Set<string>>(new Set());
  const [scanProgressMap, setScanProgressMap] = useState<Record<string, number>>({});
  const [scanHydrated, setScanHydrated] = useState(false);

  const isArabic = language === "ar";

  const uiText = {
    brand: "MAILGUARD",
    tagline: isArabic ? "حماية بريدك تبدأ بتسجيل الدخول" : "Protect your inbox by signing in",
    note: isArabic
      ? "نستخدم تسجيل الدخول عبر Google فقط. لن نقوم بتخزين كلمة المرور."
      : "We only use Google sign-in. Your password is never stored.",
    connected: isArabic ? "متصل" : "Connected",
    notConnected: isArabic ? "غير متصل" : "Not connected",
    continueWithGoogle: isArabic ? "المتابعة باستخدام Gmail" : "Continue with Gmail",
    disconnect: isArabic ? "تسجيل الخروج" : "Disconnect",
    emailLabel: isArabic ? "الحساب" : "Account",
    error: isArabic ? "تعذر الاتصال بمزود Gmail." : "Unable to reach the Gmail connector.",
    inboxTitle: isArabic ? "البريد الوارد" : "Inbox",
    inboxSubtitle: isArabic ? "مرتبة حسب التاريخ (الأحدث أولاً)" : "Sorted by date (newest first).",
    refresh: isArabic ? "تحديث البريد" : "Refresh Gmail",
    refreshing: isArabic ? "جاري التحديث..." : "Refreshing...",
    sender: isArabic ? "المرسل" : "Sender",
    subject: isArabic ? "الموضوع" : "Subject",
    signals: isArabic ? "الإشارات" : "Signals",
    risk: isArabic ? "المخاطر" : "Risk",
    scan: isArabic ? "فحص" : "Scan",
    scanning: isArabic ? "جاري الفحص..." : "Scanning...",
    scanFailed: isArabic ? "فشل الفحص" : "Scan failed",
    verdictSafe: isArabic ? "آمن" : "Safe",
    verdictSuspicious: isArabic ? "مشبوه" : "Suspicious",
    verdictDangerous: isArabic ? "خطر" : "Dangerous",
    verdictUnknown: isArabic ? "غير معروف" : "Unknown",
    cached: isArabic ? "تم الفحص" : "Scanned",
    emptyTitle: isArabic ? "لا توجد رسائل بعد" : "No messages loaded yet.",
    emptyHint: isArabic
      ? "اتصل بـ Gmail ثم اضغط تحديث البريد لعرض الرسائل."
      : "Connect Gmail and click Refresh Gmail to fetch your inbox.",
    links: isArabic ? "روابط" : "links",
    files: isArabic ? "ملفات" : "files",
  } as const;

  const filteredEmails = useMemo(() => {
    return emails
      .map((item) => ({ ...item }))
      .sort((a, b) => {
        const aTime = Date.parse(a.receivedAt);
        const bTime = Date.parse(b.receivedAt);
        if (Number.isNaN(aTime) && Number.isNaN(bTime)) return 0;
        if (Number.isNaN(aTime)) return 1;
        if (Number.isNaN(bTime)) return -1;
        return bTime - aTime;
      });
  }, [emails]);

  const refreshStatus = async () => {
    try {
      const res = await fetch("/api/status");
      if (!res.ok) throw new Error("status_failed");
      const data = (await res.json()) as { connected: boolean; email?: string };
      setConnected(data.connected);
      setAccountEmail(data.email ?? null);
      setError(null);
    } catch (err) {
      setError(uiText.error);
    }
  };

  const loadScanStatus = async (ids: string[]) => {
    if (!ids.length) return;
    const statusRes = await fetch("/api/scan/status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids }),
    });
    if (statusRes.ok) {
      const statusData = (await statusRes.json()) as {
        results: { message_id: string; verdict: ScanVerdict; stats?: { malicious?: number; suspicious?: number } }[];
      };
      const mapped: Record<string, ScanResult> = {};
      statusData.results.forEach((row) => {
        mapped[row.message_id] = { verdict: row.verdict, stats: row.stats, cached: true };
      });
      setScanResults((prev) => ({ ...prev, ...mapped }));
      setScanHydrated(true);
    }
  };

  const fetchMessages = async () => {
    setLoadingMessages(true);
    setError(null);
    try {
      const res = await fetch("/api/messages");
      if (!res.ok) throw new Error("messages_failed");
      const data = (await res.json()) as { messages: EmailItem[] };
      setEmails(data.messages);
      const ids = data.messages.map((item) => item.id);
      await loadScanStatus(ids);
    } catch (err) {
      setError(isArabic ? "تعذر تحميل الرسائل." : "Unable to load Gmail messages.");
    } finally {
      setLoadingMessages(false);
    }
  };

  useEffect(() => {
    void refreshStatus();
  }, []);

  useEffect(() => {
    if (connected) {
      void fetchMessages();
    }
  }, [connected]);

  useEffect(() => {
    if (!connected || scanHydrated || emails.length === 0) return;
    const ids = emails.map((item) => item.id);
    void loadScanStatus(ids);
  }, [connected, emails, scanHydrated]);

  const handleConnect = () => {
    window.location.href = "/auth/google";
  };

  const handleDisconnect = async () => {
    setBusy(true);
    await fetch("/auth/logout", { method: "POST" });
    setConnected(false);
    setAccountEmail(null);
    setEmails(EMPTY_EMAILS);
    setScanResults({});
    setScanningIds(new Set());
    setScanProgressMap({});
    setScanHydrated(false);
    setBusy(false);
  };

  const handleScan = async (id: string) => {
    if (!connected || scanningIds.has(id)) return;
    setScanningIds((prev) => new Set(prev).add(id));
    setScanResults((prev) => ({
      ...prev,
      [id]: { verdict: "Unknown" },
    }));

    const progressTimer = window.setInterval(() => {
      setScanProgressMap((prev) => {
        const current = prev[id] ?? 1;
        const next = Math.min(current + 7, 95);
        return { ...prev, [id]: next };
      });
    }, 350);

    try {
      const res = await fetch(`/api/scan/${id}`, { method: "POST" });
      const data = (await res.json()) as ScanResult & { error?: string };
      if (!res.ok) throw new Error("scan_failed");
      setScanResults((prev) => ({ ...prev, [id]: data }));
      setScanProgressMap((prev) => ({ ...prev, [id]: 100 }));
    } catch (err) {
      setScanResults((prev) => ({ ...prev, [id]: { verdict: "Unknown", error: "failed" } }));
      setScanProgressMap((prev) => ({ ...prev, [id]: 100 }));
    } finally {
      window.clearInterval(progressTimer);
      setScanningIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  if (!connected) {
    return (
      <div className="landing" dir={isArabic ? "rtl" : "ltr"}>
        <header className="landing-header">
          <div className="brand-wrap">
            <span className="brand-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" role="presentation" focusable="false">
                <path
                  d="M12 3.5c2.3 2 4.9 2.7 7 3v6.3c0 4-2.7 6.9-7 8.7-4.3-1.8-7-4.7-7-8.7V6.5c2.1-.3 4.7-1 7-3Z"
                  fill="currentColor"
                />
              </svg>
            </span>
            <span className="brand-text">{uiText.brand}</span>
          </div>
          <div className="header-actions">
            <span className={`status-chip ${connected ? "online" : "offline"}`}>
              {connected ? uiText.connected : uiText.notConnected}
            </span>
            <button className="ghost" onClick={() => setLanguage(isArabic ? "en" : "ar")}>
              {isArabic ? "English" : "العربية"}
            </button>
          </div>
        </header>

        <main className="landing-main">
          <div className="hero-card">
            <div className="hero-line" aria-hidden="true" />
            <p className="hero-title">{uiText.brand}</p>
            <p className="hero-tagline">{uiText.tagline}</p>
            <p className="hero-note">{uiText.note}</p>

            {error ? <p className="error">{error}</p> : null}

            <div className="hero-actions">
              <button className="primary" onClick={handleConnect}>
                {uiText.continueWithGoogle}
              </button>
            </div>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="inbox" dir={isArabic ? "rtl" : "ltr"}>
      <header className="landing-header inbox-header">
        <div className="brand-wrap">
          <span className="brand-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" role="presentation" focusable="false">
              <path
                d="M12 3.5c2.3 2 4.9 2.7 7 3v6.3c0 4-2.7 6.9-7 8.7-4.3-1.8-7-4.7-7-8.7V6.5c2.1-.3 4.7-1 7-3Z"
                fill="currentColor"
              />
            </svg>
          </span>
          <span className="brand-text">{uiText.brand}</span>
        </div>
        <div className="header-actions">
          <span className={`status-chip ${connected ? "online" : "offline"}`}>
            {connected ? uiText.connected : uiText.notConnected}
          </span>
          {accountEmail ? <span className="account-pill">{accountEmail}</span> : null}
          <button className="ghost" onClick={() => setLanguage(isArabic ? "en" : "ar")}>
            {isArabic ? "English" : "العربية"}
          </button>
        </div>
      </header>

      <main className="inbox-main">
        <section className="inbox-card">
          <div className="inbox-top">
            <div>
              <h2>{uiText.inboxTitle}</h2>
              <p className="helper">{uiText.inboxSubtitle}</p>
              {error ? <p className="error">{error}</p> : null}
            </div>
            <div className="inbox-actions">
              <button className="secondary" onClick={fetchMessages} disabled={loadingMessages}>
                {loadingMessages ? uiText.refreshing : uiText.refresh}
              </button>
              <button className="ghost" onClick={handleDisconnect} disabled={busy}>
                {uiText.disconnect}
              </button>
            </div>
          </div>

          <div className="table">
            <div className="table-head">
              <span>{uiText.sender}</span>
              <span>{uiText.subject}</span>
              <span>{uiText.signals}</span>
              <span>{uiText.risk}</span>
              <span>{uiText.scan}</span>
            </div>
            {filteredEmails.length === 0 ? (
              <div className="empty-state">
                <p>{uiText.emptyTitle}</p>
                <span>{uiText.emptyHint}</span>
              </div>
            ) : (
              filteredEmails.map((item) => {
                const scan = scanResults[item.id];
                const scanning = scanningIds.has(item.id);
                const alreadyScanned = Boolean(scan && !scan.error);
                const scanProgress = scanProgressMap[item.id] ?? 0;
                const verdictLabel =
                  scan?.verdict === "Safe"
                    ? uiText.verdictSafe
                    : scan?.verdict === "Suspicious"
                      ? uiText.verdictSuspicious
                      : scan?.verdict === "Dangerous"
                        ? uiText.verdictDangerous
                        : scan?.verdict
                          ? uiText.verdictUnknown
                          : null;
                const scanClass =
                  scan?.verdict === "Safe"
                    ? "risk-safe"
                    : scan?.verdict === "Suspicious"
                      ? "risk-suspicious"
                      : scan?.verdict === "Dangerous"
                        ? "risk-dangerous"
                        : "risk-unknown";
                const rowStatus =
                  scan?.verdict === "Safe"
                    ? "safe"
                    : scan?.verdict === "Suspicious"
                      ? "suspicious"
                      : scan?.verdict === "Dangerous"
                        ? "danger"
                        : "unknown";
                return (
                  <button
                    key={item.id}
                    className={`row ${scan?.verdict === "Dangerous" ? "row-danger" : ""}`}
                    type="button"
                  >
                    <div className="sender-col">
                      <span className={`row-status ${rowStatus}`} aria-hidden="true" />
                      <div className="sender-line">
                        <span className="avatar">{item.sender.slice(0, 1).toUpperCase()}</span>
                        <div>
                          <p className="sender">{item.sender}</p>
                          <span className="meta">{item.senderDomain}</span>
                        </div>
                      </div>
                    </div>
                    <div>
                      <p className="subject">{item.subject}</p>
                      <span className="meta">{item.preview}</span>
                    </div>
                    <div className="signals">
                      <span>
                        {item.linkCount} {uiText.links}
                      </span>
                      <span>
                        {item.attachmentCount} {uiText.files}
                      </span>
                    </div>
                    <div className="risk-slot">
                      {scan ? (
                        <div className={`risk-pill ${scanClass}`}>
                          <strong>{verdictLabel}</strong>
                        </div>
                      ) : (
                        <span className="meta">—</span>
                      )}
                    </div>
                    <div className="scan-cell">
                      <button
                        className="secondary"
                        type="button"
                        disabled={scanning || alreadyScanned}
                        onClick={(event) => {
                          event.stopPropagation();
                          void handleScan(item.id);
                        }}
                      >
                        {scanning ? uiText.scanning : alreadyScanned ? uiText.cached : uiText.scan}
                      </button>
                      {scan ? (
                        <span className={`vt-badge ${scan.verdict ? scan.verdict.toLowerCase() : ""}`}>
                          {scan.error ? `${uiText.scanFailed}` : verdictLabel}
                        </span>
                      ) : null}
                      {scanning || scanProgress > 0 ? (
                        <div className="scan-progress-inline">
                          <div className="scan-bar">
                            <div className="scan-bar-fill" style={{ width: `${scanProgress}%` }} />
                          </div>
                          <span>{scanProgress}%</span>
                        </div>
                      ) : null}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </section>
      </main>
    </div>
  );
}


