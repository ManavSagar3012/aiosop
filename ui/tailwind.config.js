/** @type {import('tailwindcss').Config} */
// Design tokens reference the canonical CSS variables defined in the
// `:root` block of src/styles.css (single source of truth — see Task 1).
// This block intentionally has NO hex literals: every color utility the
// app uses resolves to `var(--token)`, so a class name and a CSS variable
// can never disagree. Consumed by the Tailwind v4 PostCSS plugin via
// `@config "../tailwind.config.js"` in src/styles.css.
export default {
  darkMode: "class",
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        surface: "var(--surface-container-lowest)",
        "surface-variant": "var(--surface-variant)",
        "surface-container-lowest": "var(--surface-container-lowest)",
        "surface-container-low": "var(--surface-container-low)",
        "surface-container": "var(--surface-container)",
        "surface-container-high": "var(--surface-container-high)",
        "surface-container-highest": "var(--surface-container-highest)",
        "on-surface": "var(--on-surface)",
        "on-surface-variant": "var(--on-surface-variant)",
        primary: "var(--primary)",
        "primary-fixed": "var(--primary-fixed)",
        "primary-container": "var(--primary-container)",
        "on-primary": "var(--on-primary)",
        "on-primary-fixed": "var(--on-primary)",
        "on-primary-container": "var(--on-primary-container)",
        secondary: "var(--secondary)",
        "secondary-fixed": "var(--secondary)",
        "secondary-container": "var(--secondary-container)",
        "on-secondary-container": "var(--on-secondary-container)",
        tertiary: "var(--tertiary)",
        error: "var(--error)",
        "error-container": "var(--error-container)",
        "on-error-container": "var(--on-error-container)",
        warning: "var(--warning)",
        "warning-container": "var(--warning-container)",
        outline: "var(--outline)",
        "outline-variant": "var(--outline-variant)",
      },
      borderRadius: {
        // Faithful to the prior v3 CDN rendering: design is sharp-cornered.
        none: "0",
        sm: "0.125rem",
        DEFAULT: "0px",
        md: "0.375rem",
        lg: "0px",
        xl: "0px",
        "2xl": "0px",
        "3xl": "0px",
        full: "9999px",
      },
      spacing: {
        "container-max": "1440px",
        gutter: "16px",
        unit: "4px",
        margin: "24px",
      },
      fontFamily: {
        "body-md": ["Inter"],
        "display-lg": ["Inter"],
        "display-lg-mobile": ["Inter"],
        "headline-md": ["Inter"],
        "label-caps": ["JetBrains Mono"],
        "code-sm": ["JetBrains Mono"],
      },
      fontSize: {
        "body-md": ["14px", { lineHeight: "20px", fontWeight: "400" }],
        "display-lg": ["32px", { lineHeight: "40px", letterSpacing: "-0.02em", fontWeight: "800" }],
        "display-lg-mobile": ["24px", { lineHeight: "32px", fontWeight: "700" }],
        "headline-md": ["20px", { lineHeight: "28px", letterSpacing: "0.01em", fontWeight: "600" }],
        "label-caps": ["11px", { lineHeight: "14px", letterSpacing: "0.15em", fontWeight: "700" }],
        "code-sm": ["12px", { lineHeight: "16px", fontWeight: "400" }],
      },
    },
  },
  plugins: [],
}
