'use client'

import { useEffect, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { createClient } from '@/lib/supabase/client'
import GoogleIcon from '@/components/GoogleIcon'
import gsap from 'gsap'

export default function LoginPage() {
  const router = useRouter()
  const containerRef = useRef<HTMLDivElement>(null)
  const titleRef = useRef<HTMLHeadingElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!containerRef.current) return
    
    const tl = gsap.timeline()
    
    gsap.set(containerRef.current, { opacity: 0, scale: 0.95, y: 20 })
    gsap.set(titleRef.current, { opacity: 0, y: -30 })
    gsap.set(buttonRef.current, { opacity: 0, y: 20 })
    
    tl.to(containerRef.current, {
      opacity: 1,
      scale: 1,
      y: 0,
      duration: 0.6,
      ease: 'power2.out',
    })
    .to(titleRef.current, {
      opacity: 1,
      y: 0,
      duration: 0.5,
      ease: 'power2.out',
    }, '-=0.3')
    .to(buttonRef.current, {
      opacity: 1,
      y: 0,
      duration: 0.5,
      ease: 'power2.out',
    }, '-=0.2')
  }, [])

  const handleGoogleSignIn = async () => {
    const supabase = createClient()
    
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: `${window.location.origin}/auth/callback`,
      },
    })

    if (error) {
      console.error('Error signing in:', error.message)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100">
      <div
        ref={containerRef}
        className="w-full max-w-md px-8"
      >
        <div className="bg-white rounded-2xl shadow-xl p-12 border border-slate-200">
          <h1
            ref={titleRef}
            className="text-4xl font-bold text-center mb-12 text-slate-900"
          >
            Welcome
          </h1>

          <button
            ref={buttonRef}
            onClick={handleGoogleSignIn}
            className="w-full flex items-center justify-center gap-3 bg-white border-2 border-slate-300 text-slate-700 font-semibold py-4 px-6 rounded-xl hover:bg-slate-50 hover:border-slate-400 transition-all duration-200 shadow-sm hover:shadow-md"
          >
            <GoogleIcon />
            <span>Sign in with Google</span>
          </button>
        </div>
      </div>
    </div>
  )
}
