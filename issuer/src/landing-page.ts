export function renderIssuerLandingPage(input: {
  statusListId: string
  demoMode: boolean
  useOhttp: boolean
  ohttpRelayUrl: string
}) {
  const relayState = input.useOhttp && input.ohttpRelayUrl ? `on via ${input.ohttpRelayUrl}` : 'off'

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Issuer</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:2rem;max-width:960px;margin:auto;line-height:1.5}
    code{background:#f6f8fa;padding:0.2rem 0.4rem;border-radius:4px}
    ul{padding-left:1.25rem}
  </style>
</head>
<body>
  <h1>Issuer</h1>
  <p>The issuer service is running. This is an API-first service, so the main student work happens through the lab steps and API endpoints below.</p>
  <p>Demo mode: <code>${input.demoMode ? 'on' : 'off'}</code>. OHTTP relay: <code>${relayState}</code>.</p>
  <h2>Useful endpoints</h2>
  <ul>
    <li><a href="/.well-known/openid-credential-issuer"><code>/.well-known/openid-credential-issuer</code></a> for issuer metadata</li>
    <li><a href="/.well-known/jwks.json"><code>/.well-known/jwks.json</code></a> for signing keys</li>
    <li><a href="/statuslist/${input.statusListId}.json"><code>/statuslist/${input.statusListId}.json</code></a> for the revocation list</li>
  </ul>
  <h2>Next step</h2>
  <p>Keep <code>pnpm dev</code> running, open the forwarded <code>3002</code> port for the verifier, then continue with <code>labs/README-lab-00-start.md</code>.</p>
</body>
</html>`
}
