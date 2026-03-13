'use client'

import { useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { createClient } from '@/lib/supabase/client'
import gsap from 'gsap'

export default function DashboardPage() {
  const router = useRouter()
  const [user, setUser] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const containerRef = useRef<HTMLDivElement>(null)
  const cardRef = useRef<HTMLDivElement>(null)
  const userIdRef = useRef<HTMLDivElement>(null)
  const emailRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    const supabase = createClient()
    
    const checkUser = async () => {
      const { data: { session } } = await supabase.auth.getSession()
      
      if (!session) {
        router.push('/login')
      } else {
        setUser(session.user)
        setLoading(false)
      }
    }

    checkUser()

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) {
        setUser(session.user)
        setLoading(false)
      } else {
        router.push('/login')
      }
    })

    return () => subscription.unsubscribe()
  }, [router])

  useEffect(() => {
    if (!loading && user && containerRef.current) {
      const tl = gsap.timeline()
      
      gsap.set(cardRef.current, { opacity: 0, scale: 0.95, y: 20 })
      gsap.set([userIdRef.current, emailRef.current], { opacity: 0, x: -20 })
      gsap.set(buttonRef.current, { opacity: 0, y: 10 })
      
      tl.to(cardRef.current, {
        opacity: 1,
        scale: 1,
        y: 0,
        duration: 0.6,
        ease: 'power2.out',
      })
      .to([userIdRef.current, emailRef.current], {
        opacity: 1,
        x: 0,
        duration: 0.5,
        stagger: 0.15,
        ease: 'power2.out',
      }, '-=0.3')
      .to(buttonRef.current, {
        opacity: 1,
        y: 0,
        duration: 0.4,
        ease: 'power2.out',
      }, '-=0.2')
    }
  }, [loading, user])

  const handleSignOut = async () => {
    const supabase = createClient()
    await supabase.auth.signOut()
    router.push('/login')
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100">
        <div className="animate-pulse text-slate-600 text-lg">Loading...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 p-4">
      <div ref={containerRef} className="w-full max-w-2xl">
        <div
          ref={cardRef}
          className="bg-white rounded-3xl shadow-2xl p-12 border border-slate-200"
        >
          <div className="text-center mb-12">
            <h1 className="text-5xl font-bold text-slate-900 mb-2">Dashboard</h1>
            <p className="text-slate-500 text-lg">Welcome back!</p>
          </div>

          <div className="space-y-8">
            <div
              ref={userIdRef}
              className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-2xl p-6 border border-blue-100"
            >
              <div className="flex items-start gap-4">
                <div className="bg-blue-500 rounded-xl p-3 mt-1">
                  <svg
                    className="w-6 h-6 text-white"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2"
                    />
                  </svg>
                </div>
                <div className="flex-1 min-w-0">
                  <h2 className="text-sm font-semibold text-slate-600 uppercase tracking-wide mb-2">
                    User ID
                  </h2>
                  <p className="text-slate-900 font-mono text-sm break-all bg-white px-4 py-3 rounded-lg border border-blue-200">
                    {user?.id}
                  </p>
                </div>
              </div>
            </div>

            <div
              ref={emailRef}
              className="bg-gradient-to-r from-emerald-50 to-teal-50 rounded-2xl p-6 border border-emerald-100"
            >
              <div className="flex items-start gap-4">
                <div className="bg-emerald-500 rounded-xl p-3 mt-1">
                  <svg
                    className="w-6 h-6 text-white"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                    />
                  </svg>
                </div>
                <div className="flex-1 min-w-0">
                  <h2 className="text-sm font-semibold text-slate-600 uppercase tracking-wide mb-2">
                    Email Address
                  </h2>
                  <p className="text-slate-900 font-medium text-lg bg-white px-4 py-3 rounded-lg border border-emerald-200">
                    {user?.email}
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-12 flex justify-center">
            <button
              ref={buttonRef}
              onClick={handleSignOut}
              className="bg-gradient-to-r from-slate-700 to-slate-900 text-white font-semibold py-4 px-8 rounded-xl hover:from-slate-800 hover:to-black transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5"
            >
              Sign Out
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
