/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#080a0f",
          card: "#0f1420",
          border: "#1f2937",
          blue: "#38bdf8",
          green: "#34d399",
          red: "#f87171",
          yellow: "#fbbf24",
          text: "#e5e7eb",
          muted: "#94a3b8"
        }
      },
      boxShadow: {
        'neon-blue': '0 1px 2px rgba(0,0,0,0.06)',
        'neon-green': '0 1px 2px rgba(0,0,0,0.06)',
        'neon-red': '0 1px 2px rgba(0,0,0,0.06)',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace']
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
