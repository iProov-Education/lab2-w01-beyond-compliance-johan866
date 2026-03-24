# Lab 06 — Mobile Wallet Track (Optional)

Lab ID: `06` · Timebox: 30-45 minutes

Goal: run one mobile wallet fork from your laptop against a reachable `LearningLab` backend so you can see the iProov gate in a real wallet presentation flow.

This is an advanced optional track.
It is not required for Labs 00-05.

## What this lab really is

Keep the scope small.

You are not rewriting a wallet from scratch.

You are identifying the exact places where a vanilla wallet needs an iProov gate:

- one config change to turn the gate on and point at the issuer
- one presentation-gate file that pauses the flow until iProov succeeds
- one callback or resume path that lets the wallet continue after the ceremony

The workshop wallet forks already contain those changes.
Your job is to run one fork locally and inspect the small set of files that differ from the vanilla wallet.

## Important: this lab is laptop-only

Do not try to run the wallet track entirely inside GitHub Codespaces.

For this lab:

- the wallet clone helper runs in a local terminal on your laptop
- the wallet app runs in Xcode or Android Studio on your laptop
- the backend can be either:
  - a running local `LearningLab` checkout on your laptop, or
  - a running backend in Codespaces or on a public URL

The wallet only needs a backend URL it can actually reach.

## Choose one platform

Clone and run only one wallet:

- iOS
- Android

Do not clone both unless an instructor asks you to.

## Step 1: make sure you have a local `LearningLab` checkout

If you have only used Codespaces so far, clone your own student repo onto your laptop first:

```bash
git clone <your-learninglab-repo-url> LearningLab
cd LearningLab
```

If you already have a local checkout, just open a terminal there.

## Step 2: clone exactly one wallet fork

From the local `LearningLab` folder on your laptop, run one of these:

```bash
node scripts/setup-wallet-forks.js --platform ios
```

```bash
node scripts/setup-wallet-forks.js --platform android
```

Preview only:

```bash
node scripts/setup-wallet-forks.js --dry-run
```

What this does:

- clones the chosen wallet beside `LearningLab`
- keeps the mobile repo separate from the Node lab repo
- avoids submodules and nested repos

If the script tells you that you are in Codespaces, stop and rerun it from a local terminal on your laptop.

## Step 3: choose the backend URL

There is no single fixed class URL baked into the repo.

Use whichever issuer URL your wallet can actually reach:

- backend in Codespaces:
  - copy the forwarded Port `3001` URL from the `PORTS` panel
  - it will look like `https://<codespace-name>-3001.app.github.dev`
- backend on your laptop:
  - iOS simulator: `http://localhost:3001`
  - Android emulator: `http://10.0.2.2:3001`
  - physical device on the same Wi-Fi: `http://<your-mac-lan-ip>:3001`
- shared workshop backend:
  - use the public HTTPS issuer URL the instructor gives you

Only use `localhost` when the issuer is running on the same laptop as the simulator.

If you also need the verifier URL, use the same rule with Port `3002`.

## Step 4: make sure the backend is alive

Before opening the wallet, confirm the issuer is reachable.

For a local backend:

```bash
pnpm dev
curl -s http://localhost:3001/.well-known/openid-credential-issuer | jq
curl -s http://localhost:3001/iproov/config | jq
```

For a Codespaces or public backend, replace `http://localhost:3001` with the actual issuer URL you copied in Step 3.

Interpret `/iproov/config` like this:

- `realCeremonyEnabled=false`
  - the issuer is in demo mode
  - the wallet should use the web fallback flow
- `realCeremonyEnabled=true`
  - the issuer has real iProov credentials
  - the iOS native SDK path can be used on a physical iPhone

## Step 5: follow the platform runbook

After cloning the wallet, open:

- [STUDENT_WALLET_RUNBOOK.md](../STUDENT_WALLET_RUNBOOK.md)

Use that runbook for:

- platform-specific file locations
- the exact vanilla-wallet patch points to inspect
- iOS and Android setup
- where to paste the issuer base URL
- expected iProov flow
- troubleshooting

## Codespaces note

For this workshop, the real iProov credentials stay in the backend, not in the wallet repo.

That means:

- do not paste iProov secrets into the wallet repos
- do not edit wallet repos to add backend secrets
- if your backend is running in Codespaces, copy the forwarded HTTPS URL from that backend Codespace

## You are done when

- the wallet reaches the presentation loading step
- the iProov gate runs before the presentation is sent
- the presentation resumes only after the iProov step succeeds

## If something fails

- wallet clone/setup issues:
  - use `node scripts/setup-wallet-forks.js --dry-run` first
- wallet script says Codespaces:
  - move to a local terminal on your laptop and rerun the command there
- simulator or emulator cannot reach the issuer:
  - use the base URL rules in [STUDENT_WALLET_RUNBOOK.md](../STUDENT_WALLET_RUNBOOK.md)
- phone app cannot reach the backend:
  - use a public HTTPS URL or your Mac LAN IP, not `localhost`
- iProov confusion:
  - backend secrets stay in the backend repo or Codespace, never in the wallet repo
