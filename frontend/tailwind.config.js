/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0b1220",
        panel: "#101a2d",
        panel2: "#0f172a",
        line: "#1e293b",
        line2: "#273449",
        muted: "#94a3b8",
        accent: "#22d3ee",
        accent2: "#38bdf8",
        danger: "#ff3b5c",
        warn: "#ffc04d",
        ok: "#34d399",
      },
      fontFamily: {
        sans: ["ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34,211,238,.25), 0 0 24px rgba(34,211,238,.08)",
      },
    },
  },
  plugins: [],
};
