/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Warm off-white surface stack — inspo-1 (Codex) + inspo-2 (Devin).
        paper: {
          50: "#fbfaf8",   // page bg (warm off-white)
          100: "#f6f4f0",  // nav rail
          200: "#efece6",  // list column
          300: "#e6e2d9",  // hairline borders
          400: "#d3cec4",  // stronger borders / dividers
          500: "#b3ada0",  // muted labels
          600: "#8a8578",  // secondary text
          700: "#5a5750",  // body text
          800: "#33322e",  // headings
          900: "#1a1a17",  // strongest text
        },
        // Severity + accent palette — restrained, muted.
        sev: {
          critical: "#c8422b",
          high:     "#d97141",
          medium:   "#c99a1e",
          low:      "#6a8f5a",
        },
        accent: {
          DEFAULT: "#3c8f5c",  // deep muted green
          soft:    "#e6f0e2",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "SF Pro Text",
          "sans-serif",
        ],
        mono: ["JetBrains Mono", "SF Mono", "Menlo", "monospace"],
      },
      fontSize: {
        // Tighter, denser ramp — closer to product UIs.
        "2xs": ["10px", "14px"],
        xs: ["11px", "16px"],
        sm: ["13px", "18px"],
        base: ["14px", "20px"],
        lg: ["16px", "22px"],
        xl: ["18px", "26px"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(30, 25, 15, 0.04), 0 1px 1px rgba(30, 25, 15, 0.03)",
        pop: "0 4px 20px rgba(30, 25, 15, 0.08)",
      },
    },
  },
  plugins: [],
};
