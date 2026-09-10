/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // ─── Severity palette (shared with SeverityBadge.tsx) ───────────────
        sev: {
          critical: '#7f1d1d',
          high: '#b91c1c',
          medium: '#d97706',
          low: '#2563eb',
          none: '#475569',
        },

        // ─── PRIMESEC PALETTE ────────────────────────────────────────────────
        prime: {
          950: '#030712',  // Deepest Background (Near Black)
          900: '#0a0f1a',  // Main Canvas
          800: '#111827',  // Card Base / Sidebar
          700: '#1f2937',  // Hover / Border Base
          600: '#374151',  // Subtle Borders / Dividers
        },

        // ACCENT: Electric Cyan — PrimeSec Signature
        acc: {
          DEFAULT: '#00f5d4',
          600:     '#00d4b8',
          700:     '#00b39e',
          glow:   'rgba(0, 245, 212, 0.4)',
          subtle: 'rgba(0, 245, 212, 0.08)',
        },

        // SECONDARY ACCENT: Warning / Orange (Critical severity)
        'acc-warm': {
          DEFAULT: '#ff6b35',
          glow:   'rgba(255, 107, 53, 0.4)',
        },

        // Semantic text tokens
        text: {
          primary:   '#ffffff',
          secondary: '#9ca3af', // gray-400
          muted:     '#6b7280', // gray-500
          inverse:   '#030712',
        },

        // Border tokens (semi-transparent)
        border:        'rgba(255, 255, 255, 0.06)',
        'border-strong': 'rgba(255, 255, 255, 0.12)',
      },

      // ─── Typography ────────────────────────────────────────────────────────
      fontFamily: {
        sans:    ['var(--font-geist-sans)', 'Inter', 'system-ui', 'sans-serif'],
        mono:    ['var(--font-geist-mono)', 'JetBrains Mono', 'monospace'],
        display: ['var(--font-space-grotesk)', 'Inter', 'sans-serif'],
      },

      // ─── Background Images ─────────────────────────────────────────────────
      backgroundImage: {
        'grid-pattern':
          'linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), ' +
          'linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)',
        'radial-glow':
          'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0, 245, 212, 0.15), transparent)',
        'card-shine':
          'linear-gradient(135deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0) 50%)',
      },

      // ─── Background Sizes ─────────────────────────────────────────────────
      backgroundSize: {
        'grid': '40px 40px',
      },

      // ─── Box Shadows ───────────────────────────────────────────────────────
      boxShadow: {
        'glow-cyan':    '0 0 40px -10px rgba(0, 245, 212, 0.25)',
        'glow-cyan-sm': '0 0 20px -5px  rgba(0, 245, 212, 0.15)',
        'glow-warm':    '0 0 40px -10px rgba(255, 107, 53, 0.25)',
        glass:          '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
        'inner-glass':  'inset 0 1px 0 0 rgba(255, 255, 255, 0.05)',
      },

      // ─── Transition Durations ──────────────────────────────────────────────
      transitionDuration: {
        fast:   '150ms',
        normal: '250ms',
        slow:   '400ms',
      },

      // ─── Transition Timing Functions ──────────────────────────────────────
      transitionTimingFunction: {
        expo: 'cubic-bezier(0.16, 1, 0.3, 1)', // Premium spring-like easing
      },

      // ─── Border Radius ─────────────────────────────────────────────────────
      borderRadius: {
        '2xl': '1rem',
        '3xl': '1.5rem',
      },

      // ─── Keyframes & Animations ────────────────────────────────────────────
      keyframes: {
        'glow-pulse': {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0.5' },
        },
        'scan-line': {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'fade-up': {
          '0%':   { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in-right': {
          '0%':   { opacity: '0', transform: 'translateX(16px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        // Hero card gentle float
        'float': {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%':      { transform: 'translateY(-10px)' },
        },
        // LogoMarquee infinite horizontal scroll
        'marquee': {
          '0%':   { transform: 'translateX(0%)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        // TechnicalFlow SVG connector draw-in
        'draw-line': {
          '0%':   { strokeDashoffset: '1000' },
          '100%': { strokeDashoffset: '0' },
        },
        // AttackMap node pulse
        'pulse-dot': {
          '0%, 100%': { transform: 'scale(1)',   opacity: '1' },
          '50%':      { transform: 'scale(1.8)', opacity: '0' },
        },
        // Mobile drawer slide in from right
        'drawer-in': {
          '0%':   { transform: 'translateX(100%)' },
          '100%': { transform: 'translateX(0%)' },
        },
      },
      animation: {
        'glow-pulse':      'glow-pulse 2s ease-in-out infinite',
        'scan-line':       'scan-line 3s linear infinite',
        'float':           'float 6s ease-in-out infinite',
        'marquee':         'marquee 30s linear infinite',
        'draw-line':       'draw-line 1.5s ease forwards',
        'pulse-dot':       'pulse-dot 2s ease-out infinite',
        'drawer-in':       'drawer-in 0.3s cubic-bezier(0.16,1,0.3,1) forwards',
        'fade-up':         'fade-up 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards',
        'slide-in-right':  'slide-in-right 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards',
      },
    },
  },
  plugins: [],
}
