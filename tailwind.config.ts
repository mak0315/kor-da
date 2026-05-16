/** @type {import('tailwindcss').Config} */
const config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        t0: "#0F3028",
        t1: "#1C4D40",
        t2: "#276654",
        t3: "#3A9070",
        t4: "#78C4A8",
        tbg: "#E6F5F0",
        tbg2: "#C8EAE0",
        g0: "#8C5A10",
        g1: "#B87420",
        g2: "#D9921A",
        g3: "#E9A825",
        g4: "#F5C85A",
        gbg: "#FDF4E0",
        s: "#F7F3EC",
        s2: "#EDE7DB",
        s3: "#DED5C5",
        cream: "#FDFAF5",
        ink: "#1A1810",
        i2: "#342E24",
        i3: "#6A6050",
        i4: "#9A9080",
        i5: "#C5BBAE",
        ok: "#1A7A40",
        okbg: "#ECF7F0",
        err: "#BE3535",
        errbg: "#FEF0F0",
        warn: "#B07010",
        wbg: "#FDF4E0",
        wa: "#19A855",
      },
      fontFamily: {
        serif: ["var(--font-playfair)", "serif"],
        sans: ["var(--font-jakarta)", "system-ui", "sans-serif"],
        urdu: ["var(--font-urdu)", "serif"],
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "gradient-conic":
          "conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))",
      },
      borderRadius: {
        r1: "4px",
        r2: "8px",
        r3: "12px",
        r4: "16px",
        r5: "22px",
        r6: "32px",
      },
    },
  },
  plugins: [],
};
export default config;
