# PasteSafe

**The clipboard that redacts itself before AI sees it.**

Built for [#BuildHybridAI 2026](https://firebasehybridaihackathon.devpost.com/)
($30,000 prize pool). Web/Chrome app — Best Web/Chrome + Grand Prize track.

Anyone who pastes logs, code, chats, or bug reports into an AI tool risks
leaking secrets: AWS keys, GitHub tokens, private keys, passwords, emails,
customer PII. PasteSafe puts a privacy gate **on the device** first, then
lets the cloud do the heavy analysis — on redacted text only.

## How it works

1. **Paste** a log, bug report, or chat transcript.
2. **Redact on-device** — a deterministic local scanner (regex + Luhn check)
   finds AWS keys, GitHub tokens, JWTs, PEM private keys, Stripe keys,
   passwords, emails, phone numbers, national IDs, and card numbers.
   Zero network, zero cost, instant. Each finding becomes a
   `[REDACTED:TYPE-N]` placeholder.
3. **Semantic sweep (on-device first)** — Firebase AI Logic hybrid
   inference runs a privacy scan + short summary on Gemini Nano when
   available, falling back to the cloud otherwise. The UI badge shows
   where the response *actually* ran (`response.inferenceSource`).
   If Nano is unavailable, PasteSafe **fails closed**: it warns you that
   the sweep would send the original text to the cloud and asks first.
4. **Review & approve** the redacted text.
5. **Analyze in cloud** — only redacted text, only on your tap. Cloud
   Gemini (`gemini-3.5-flash-lite`) returns a structured triage: severity,
   CVSS 4.0 vector draft, category, summary, remediation steps.
6. **Save & export** — reports (redacted text only) are stored per-user in
   Firestore, or in this browser in demo mode. Export as Markdown.

A **request log** proves what left the device and when: before redaction
the total is always 0 bytes.

## Hybrid inference — why it matters

| Step | Engine | Why there |
|---|---|---|
| Deterministic secret scan | Local JS | Instant, offline, $0 |
| Semantic PII sweep | On-device Gemini Nano 4 (Chrome) | Private data never leaves the device |
| Full triage | Cloud Gemini | Needs the bigger model |
| Fallback | Cloud, clearly labelled | Same experience on any device |

The on-device model is the gatekeeper; the cloud never sees a secret.
Inference mode is switchable in the UI: Prefer on-device, Only
on-device, Prefer cloud, Only in cloud.

## Tech

- Vite + React + TypeScript
- Firebase AI Logic (Hybrid Inference SDK, Gemini Developer API)
- Firebase App Check (debug provider in dev), Auth (anonymous + Google),
  Firestore (owner-only rules), Remote Config (model names + routing),
  Hosting

## Run it

```bash
npm install
npm run dev        # http://localhost:5173
npm test           # Vitest unit tests (redaction engine)
npm run build
```

### Demo mode (no Firebase needed)

Without Firebase config the app runs fully offline: local redaction works,
and triage uses a clearly labelled keyword-based **mock**. Nothing is sent
anywhere.

### Connect Firebase (free tier, no billing upgrade)

1. Create a Firebase project (free Spark plan) and a Web app.
2. Provision AI Logic — **required**, otherwise requests fail with
   `PERMISSION_DENIED`:
   ```bash
   npx -y firebase-tools@latest init ailogic
   ```
3. Enable Anonymous + Google sign-in, create a Firestore database,
   and set the App Check debug token (dev) in the Firebase Console.
4. Copy `.env.example` to `.env` and fill in the `VITE_FIREBASE_*` values:
   ```bash
   npx -y firebase-tools@latest apps:sdkconfig WEB <APP_ID> --project <PROJECT_ID>
   ```
5. Deploy:
   ```bash
   npm run build
   npx -y firebase-tools@latest deploy --only hosting,firestore:rules,remoteconfig
   ```

Model names are read from Remote Config (`cloud_model`,
`inference_mode`, `on_device_max_chars`) — change them without redeploying.
Never use a Gemini 1.x/2.x model name; the default cloud model is
`gemini-3.5-flash-lite`.

**Never commit `.env` or an App Check debug token.** Tokens are injected
via gitignored env files only.

## Project structure

```
src/
  lib/
    redact.ts     # deterministic local secret scanner + tests
    hybrid.ts     # Firebase AI Logic hybrid wrapper (sweep + triage)
    firebase.ts   # Firebase bootstrap, Auth, Remote Config
    store.ts      # Firestore / localStorage report storage
    exporter.ts   # Markdown export
    samples.ts    # demo pastes (all secrets fake)
  App.tsx         # full paste → redact → approve → triage → save flow
firebase.json     # Hosting (SPA) + Firestore + Remote Config
firestore.rules   # owner-only, redacted-text-only reports
remote_config.json
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
