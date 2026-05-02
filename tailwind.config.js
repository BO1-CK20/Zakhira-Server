/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'fire-red': '#e63946',
        'dark-bg': '#0a0a0a',
        'glass-bg': 'rgba(26, 26, 26, 0.7)',
      },
      backdropBlur: {
        'glass': '12px',
      },
    },
  },
  plugins: [],
}
