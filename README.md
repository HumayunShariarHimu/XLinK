# XLinK — Cybersecurity Research Lab

A mobile-responsive, monochrome cybersecurity education project. XLinK demonstrates common suspicious-link and malware-delivery patterns using local, fictional simulations.

## Features

- **Local URL structure inspection:** parses the submitted string in the browser and reports visible structural indicators such as scheme, host, punycode, user-info, path keywords, and non-default ports.
- **Phishing-flow simulation:** step-through model showing a deceptive message, destination mismatch, credential capture attempt, and potential account abuse.
- **Redirect-chain simulation:** illustrates how a destination can change across multiple hops.
- **Malware-delivery simulation:** explains the path from a lure to file delivery and defensive containment without downloading or executing a file.
- **Responsive monochrome UI:** black/white animated visual system, keyboard focus states, reduced-motion support, and mobile layouts.
- **Vercel-ready:** configured to build with Vite and publish the `dist` directory.

## Safety and accuracy boundaries

This is a **training simulator**, not a full threat-intelligence scanner. The URL inspector does not contact the submitted URL, resolve DNS, check reputation feeds, inspect TLS certificates, follow redirects, download files, or run malware. Results are structural clues, not a verdict that a URL is safe or malicious.

No credentials are collected. No malware is included. No attack traffic is generated. The scenarios are fictional and do not perform live attacks.

## Requirements

- Node.js 18+ (Node.js 20+ recommended)
- npm

## Run locally

```bash
npm install
npm run dev
```

Open the local address printed by Vite.

## Production build

```bash
npm run build
npm run preview
```

Vite writes the production site to `dist/`.

## Deploy to Vercel

1. Upload/push the project to a GitHub repository.
2. In Vercel, import that repository.
3. Keep the detected framework as **Vite** (or use the included `vercel.json`).
4. Build command: `npm run build`.
5. Output directory: `dist`.
6. Deploy.

The project is static; it does not require API keys, OAuth, a database, or server secrets.

## Project structure

```text
XLinK/
├── index.html
├── package.json
├── vercel.json
├── .gitignore
├── README.md
├── public/
│   └── favicon.svg
└── src/
    ├── main.js
    └── style.css
```

## License

MIT — see `LICENSE`.
