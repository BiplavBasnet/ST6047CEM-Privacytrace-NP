/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: {
          50: "#f2f6f6",
          100: "#e2ebea",
          200: "#c4d5d3",
          300: "#96b5b1",
          400: "#658f8a",
          500: "#476f6b",
          600: "#365955",
          700: "#294743",
          800: "#213936",
          900: "#172826",
        },
        brand: {
          DEFAULT: "#294743",
          fg: "#ffffff",
          soft: "#e9f2f1",
        },
        accent: {
          DEFAULT: "#0f766e",
          fg: "#ffffff",
          soft: "#dff3f0",
        },
        surface: {
          DEFAULT: "#f4f6f7",
          card: "#ffffff",
          raised: "#fbfcfc",
        },
        ink: {
          DEFAULT: "#17211f",
          muted: "#62706d",
          subtle: "#87938f",
        },
      },
      borderRadius: {
        lg: "0.5rem",
        xl: "0.5rem",
      },
      boxShadow: {
        card: "0 1px 2px rgba(23, 33, 31, 0.04), 0 0 0 1px rgba(23, 33, 31, 0.02)",
        "card-hover": "0 10px 28px rgba(23, 33, 31, 0.08), 0 0 0 1px rgba(23, 33, 31, 0.03)",
        panel: "0 16px 40px rgba(23, 33, 31, 0.14), 0 0 0 1px rgba(23, 33, 31, 0.04)",
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "IBM Plex Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "Liberation Mono",
          "Courier New",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
