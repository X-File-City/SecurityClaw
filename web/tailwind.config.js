export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        shell: '#050709',
        panel: '#0b1116',
        panel2: '#0f1820',
        border: '#1d2d39',
        text: '#d6e7ef',
        dim: '#7e97a6',
        neon: '#00ff99',
        cyan: '#00d9ff',
        blue: '#53a7ff',
        amber: '#ffcc66',
        danger: '#ff5d7a',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
