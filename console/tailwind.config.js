/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#0a0a0b",
          900: "#111113",
          800: "#1a1a1d",
          700: "#26262a",
          600: "#3a3a40",
          500: "#5a5a63",
          400: "#8a8a94",
          300: "#b8b8c0",
          200: "#e2e2e5",
          100: "#f2f2f4",
        },
        spot: {
          green: "#3fd68e",
          amber: "#f5b83a",
          red: "#f26161",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "SF Mono", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
