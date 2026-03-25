import { randomUUID } from 'node:crypto'
import QRCode from 'qrcode'

const SESSION_TTL_MS = 15 * 60_000
const QR_SIZE = 280
const EUDI_PID_MDOC_DOCTYPE = 'eu.europa.ec.eudi.pid.1'
const EUDI_PID_MDOC_NAMESPACE = EUDI_PID_MDOC_DOCTYPE
const X509_SAN_DNS_CLIENT_ID_SCHEME = 'x509_san_dns'

type WalletClaimQuery = {
  id: string
  path: string[]
}

type MdocWalletCredentialQuery = {
  id: string
  format: 'mso_mdoc'
  meta: { doctype_value: string }
  claims: WalletClaimQuery[]
}

type WalletCredentialQuery = MdocWalletCredentialQuery

export type WalletVerifierProfile = {
  baseUrl: string
  clientId: string
  requestClientId: string
  legalName: string
}

export type WalletRpOutcome = {
  status: 'pending' | 'complete' | 'error'
  receivedAt?: string
  mode?: 'verified' | 'inspected'
  error?: string
  errorDescription?: string
  issuer?: string
  vct?: string
  claims?: Record<string, unknown>
  kbJwt?: Record<string, unknown> | null
  payload?: Record<string, unknown> | null
  presentationSubmission?: unknown
  raw?: Record<string, unknown>
  warning?: string
}

export type WalletRpSession = {
  id: string
  createdAt: string
  expiresAt: string
  state: string
  nonce: string
  clientId: string
  requestClientId: string
  legalName: string
  verifierApi: string
  requestUri: string
  responseUri: string
  resultUri: string
  deepLink: string
  outcome: WalletRpOutcome
}

export type WalletDirectPostBody = {
  vp_token?: unknown
  state?: string
  presentation_submission?: unknown
  error?: string
  error_description?: string
  [key: string]: unknown
}

export type WalletRequestObject = {
  client_id: string
  client_id_scheme: 'x509_san_dns'
  response_uri: string
  response_type: 'vp_token'
  response_mode: 'direct_post'
  nonce: string
  state: string
  dcql_query: {
    credentials: WalletCredentialQuery[]
    credential_sets: Array<{
      options: string[][]
      purpose?: string
    }>
  }
  client_metadata: {
    vp_formats_supported: {
      'mso_mdoc': Record<string, never>
    }
  }
}

export type WalletClaimSummary = {
  claims: Record<string, unknown>
  over21Derived: boolean | null
}

export type WalletPresentationSelection<T> = {
  credential: string
  result: T
  skippedErrors: string[]
}

export function deriveWalletVerifierProfile(baseUrl: string): WalletVerifierProfile {
  const url = new URL(baseUrl)
  return {
    baseUrl: url.origin,
    clientId: url.host,
    requestClientId: `${X509_SAN_DNS_CLIENT_ID_SCHEME}:${url.host}`,
    legalName: 'iProov Verifier'
  }
}

export function createWalletSession(baseUrl: string, now = Date.now()): WalletRpSession {
  const profile = deriveWalletVerifierProfile(baseUrl)
  const id = randomUUID()
  const state = randomUUID()
  const nonce = randomUUID()
  const requestUri = `${profile.baseUrl}/wallet/request.jwt/${id}`
  const responseUri = `${profile.baseUrl}/wallet/direct_post/${id}`
  const resultUri = `${profile.baseUrl}/wallet/session/${id}`
  return {
    id,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
    state,
    nonce,
    clientId: profile.clientId,
    requestClientId: profile.requestClientId,
    legalName: profile.legalName,
    verifierApi: profile.baseUrl,
    requestUri,
    responseUri,
    resultUri,
    deepLink: buildWalletDeepLink(profile.clientId, profile.requestClientId, requestUri),
    outcome: { status: 'pending' }
  }
}

export function buildWalletDeepLink(clientId: string, requestClientId: string, requestUri: string) {
  return `eudi-openid4vp://${clientId}?client_id=${encodeURIComponent(requestClientId)}&client_id_scheme=${encodeURIComponent(X509_SAN_DNS_CLIENT_ID_SCHEME)}&request_uri=${encodeURIComponent(requestUri)}`
}

export function buildWalletRequestObject(session: WalletRpSession, walletNonce?: string): WalletRequestObject & { wallet_nonce?: string } {
  return {
    client_id: session.requestClientId,
    client_id_scheme: X509_SAN_DNS_CLIENT_ID_SCHEME,
    response_uri: session.responseUri,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    nonce: session.nonce,
    state: session.state,
    dcql_query: buildWalletDcqlQuery(),
    client_metadata: {
      vp_formats_supported: {
        'mso_mdoc': {}
      }
    },
    ...(walletNonce ? { wallet_nonce: walletNonce } : {})
  }
}

export function buildWalletDcqlQuery() {
  const pidMdocVariants: WalletCredentialQuery[] = [
    {
      id: 'pid-mdoc-age-over-21-and-nationality',
      format: 'mso_mdoc',
      meta: { doctype_value: EUDI_PID_MDOC_DOCTYPE },
      claims: [
        { id: 'age_over_21', path: [EUDI_PID_MDOC_NAMESPACE, 'age_over_21'] },
        { id: 'nationality', path: [EUDI_PID_MDOC_NAMESPACE, 'nationality'] }
      ]
    },
    {
      id: 'pid-mdoc-birth_date-and-nationality',
      format: 'mso_mdoc',
      meta: { doctype_value: EUDI_PID_MDOC_DOCTYPE },
      claims: [
        { id: 'birth_date', path: [EUDI_PID_MDOC_NAMESPACE, 'birth_date'] },
        { id: 'nationality', path: [EUDI_PID_MDOC_NAMESPACE, 'nationality'] }
      ]
    }
  ]

  return {
    credentials: pidMdocVariants,
    credential_sets: [
      {
        options: [
          ...pidMdocVariants.map((credential) => [credential.id])
        ],
        purpose:
          'Use the PID mdoc path for the public wallet demo. If the credential exposes birth_date instead of age_over_21, the verifier derives the over-21 decision locally.'
      }
    ]
  }
}

export function summarizeWalletClaims(claims: Record<string, unknown>, now = new Date()): WalletClaimSummary {
  const normalized: Record<string, unknown> = { ...claims }
  const nationalityValues = normalizeNationalityClaim(
    claims.nationalities ?? claims.nationality
  )
  if (nationalityValues.length > 0) {
    normalized.nationalities = nationalityValues
    normalized.nationality = nationalityValues[0]
  }

  const birthdate = normalizeBirthdateClaim(claims.birthdate ?? claims.birth_date)
  if (birthdate) {
    normalized.birthdate = birthdate
  }

  const directAgeOver21 = normalizeBooleanClaim(claims.age_over_21)
  const derivedAgeOver21 =
    directAgeOver21 ?? (birthdate ? isAtLeast21(birthdate, now) : null)

  if (derivedAgeOver21 !== null) {
    normalized.age_over_21 = derivedAgeOver21
  }
  if (directAgeOver21 === null && birthdate) {
    normalized.age_over_21_source = 'derived_from_birthdate'
  }

  return {
    claims: normalized,
    over21Derived: directAgeOver21 === null ? derivedAgeOver21 : null
  }
}

export async function renderWalletQrSvg(content: string) {
  return QRCode.toString(content, {
    errorCorrectionLevel: 'M',
    margin: 1,
    type: 'svg',
    width: QR_SIZE
  })
}

export function normalizeWalletDirectPostBody(body: unknown): WalletDirectPostBody {
  if (!body || typeof body !== 'object') return {}
  const normalized: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(body)) {
    normalized[key] = normalizeNestedValue(value)
  }
  return normalized as WalletDirectPostBody
}

export function extractPresentedCredentials(vpToken: unknown): string[] {
  if (!vpToken) return []
  if (typeof vpToken === 'string') return [vpToken]
  if (Array.isArray(vpToken)) {
    return vpToken.flatMap((item) => extractPresentedCredentials(item))
  }
  if (typeof vpToken === 'object') {
    const tokenRecord = vpToken as Record<string, unknown>
    if (typeof tokenRecord.credential === 'string') return [tokenRecord.credential]
    if (typeof tokenRecord.sd_jwt === 'string') return [tokenRecord.sd_jwt]
    return Object.values(tokenRecord).flatMap((item) => extractPresentedCredentials(item))
  }
  return []
}

export async function pickFirstSuccessfulWalletPresentation<T>(
  credentials: string[],
  inspect: (credential: string) => Promise<T>
): Promise<WalletPresentationSelection<T>> {
  const skippedErrors: string[] = []
  for (const credential of credentials) {
    try {
      return {
        credential,
        result: await inspect(credential),
        skippedErrors
      }
    } catch (error: any) {
      skippedErrors.push(error?.message || 'wallet_presentation_inspection_failed')
    }
  }
  throw new Error(skippedErrors[0] || 'wallet_presentation_inspection_failed')
}

export function renderWalletSessionPage(session: WalletRpSession, qrSvg: string) {
  const requestedClaims = [
    'PID (MSO mdoc): age_over_21 + nationality, or birth_date + nationality under the PID namespace'
  ]
  const statusCopy =
    session.outcome.status === 'pending'
      ? 'Waiting for the wallet to submit a presentation.'
      : session.outcome.status === 'error'
        ? 'The wallet sent an error or an invalid response.'
        : session.outcome.mode === 'verified'
          ? 'Presentation received and cryptographically verified.'
          : 'Presentation received and parsed, but only structural inspection was possible.'
  const heroTone =
    session.outcome.status === 'complete'
      ? 'success'
      : session.outcome.status === 'error'
        ? 'error'
        : 'pending'
  const heroTitle =
    session.outcome.status === 'complete'
      ? 'Successful Authentication'
      : session.outcome.status === 'error'
        ? 'Authentication Failed'
        : 'Scan This QR Code With The Wallet'
  const heroLead =
    session.outcome.status === 'complete'
      ? 'The wallet presentation was received and the requested PID claims were accepted.'
      : statusCopy
  const completedSummary = session.outcome.status === 'complete' ? renderCompletedWalletOutcome(session) : ''
  const technicalDetails = renderWalletTechnicalDetails(session)
  const pendingCards = session.outcome.status === 'complete'
    ? ''
    : `
    <section class="grid">
      <article class="card">
        <h2>Scan</h2>
        <div class="qr">${qrSvg}</div>
        <p><a href="${escapeHtml(session.deepLink)}">Open the wallet deep link directly</a></p>
        <p><strong>Request URI:</strong><br /><code>${escapeHtml(session.requestUri)}</code></p>
        <p><strong>Response URI:</strong><br /><code>${escapeHtml(session.responseUri)}</code></p>
      </article>
      <article class="card">
        <h2>Verifier Setup</h2>
        <p>If your wallet fork uses preregistered verifier settings, use these values:</p>
        <ul>
          <li><strong>Client ID:</strong> <code>${escapeHtml(session.clientId)}</code></li>
          <li><strong>Verifier API:</strong> <code>${escapeHtml(session.verifierApi)}</code></li>
          <li><strong>Legal Name:</strong> <code>${escapeHtml(session.legalName)}</code></li>
        </ul>
        <p><strong>Requested claims:</strong></p>
        <ul>${requestedClaims.map((claim) => `<li>${escapeHtml(claim)}</li>`).join('')}</ul>
      </article>
      <article class="card">
        <h2>Session</h2>
        <p><strong>Session ID:</strong> <code>${escapeHtml(session.id)}</code></p>
        <p><strong>State:</strong> <code>${escapeHtml(session.state)}</code></p>
        <p><strong>Nonce:</strong> <code>${escapeHtml(session.nonce)}</code></p>
        <p><strong>Created:</strong> <code>${escapeHtml(session.createdAt)}</code></p>
        <p><strong>Expires:</strong> <code>${escapeHtml(session.expiresAt)}</code></p>
      </article>
      <article class="card">
        <h2>Latest Result</h2>
        <pre>${escapeHtml(JSON.stringify(session.outcome, null, 2))}</pre>
      </article>
    </section>`

  const autoRefresh =
    session.outcome.status === 'pending'
      ? '<meta http-equiv="refresh" content="5" />'
      : ''

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  ${autoRefresh}
  <title>Wallet RP Session</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #17212b;
      --muted: #667788;
      --line: #d8dee7;
      --paper: #f7f5ef;
      --accent: #c65d2e;
      --accent-soft: #fff3ec;
    }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(198,93,46,0.10), transparent 28rem),
        linear-gradient(180deg, #faf7f1, #f3efe8);
    }
    main {
      max-width: 1080px;
      margin: 0 auto;
      padding: 2rem 1.25rem 3rem;
    }
    h1, h2 {
      font-family: "IBM Plex Serif", Georgia, serif;
      margin: 0 0 0.75rem;
    }
    p, li {
      line-height: 1.5;
    }
    .hero, .card {
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.88);
      backdrop-filter: blur(10px);
      border-radius: 20px;
      box-shadow: 0 12px 30px rgba(23,33,43,0.07);
    }
    .hero.pending {
      border-color: var(--line);
    }
    .hero.success {
      border-color: rgba(45, 125, 74, 0.25);
      background: linear-gradient(160deg, rgba(246, 255, 248, 0.96), rgba(231, 247, 236, 0.96));
    }
    .hero.error {
      border-color: rgba(172, 53, 69, 0.18);
      background: linear-gradient(160deg, rgba(255, 248, 249, 0.96), rgba(255, 237, 240, 0.96));
    }
    .hero {
      padding: 1.5rem;
      margin-bottom: 1rem;
    }
    .hero-lead {
      font-size: 1.15rem;
      max-width: 58rem;
      margin-bottom: 0.9rem;
    }
    .summary-grid {
      display: grid;
      gap: 0.85rem;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      margin-top: 1rem;
    }
    .summary-card {
      background: rgba(255,255,255,0.82);
      border: 1px solid rgba(32, 63, 91, 0.1);
      border-radius: 16px;
      padding: 1rem;
    }
    .summary-label {
      display: block;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #5a6c80;
      margin-bottom: 0.35rem;
      font-weight: 700;
    }
    .summary-value {
      display: block;
      font-size: 1.2rem;
      font-weight: 700;
      color: #142434;
      line-height: 1.3;
    }
    .summary-note {
      display: block;
      margin-top: 0.35rem;
      color: #4c5d70;
      font-size: 0.92rem;
    }
    .technical {
      margin-top: 1rem;
    }
    details {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255,255,255,0.8);
      padding: 0.8rem 1rem;
    }
    summary {
      cursor: pointer;
      font-weight: 700;
    }
    details > *:not(summary) {
      margin-top: 0.85rem;
    }
    .grid {
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    }
    .card {
      padding: 1.25rem;
    }
    .qr {
      display: inline-block;
      padding: 0.75rem;
      background: white;
      border-radius: 16px;
      border: 1px solid var(--line);
    }
    .pill {
      display: inline-block;
      padding: 0.35rem 0.7rem;
      border-radius: 999px;
      font-size: 0.9rem;
      font-weight: 600;
      background: var(--accent-soft);
      color: var(--accent);
      margin-bottom: 0.75rem;
    }
    code {
      background: #eef2f6;
      padding: 0.15rem 0.35rem;
      border-radius: 6px;
      word-break: break-all;
    }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      overflow-wrap: anywhere;
      background: #0d1620;
      color: #f3f8ff;
      padding: 1rem;
      border-radius: 14px;
      font-size: 0.9rem;
    }
    a {
      color: var(--accent);
    }
  </style>
</head>
<body>
  <main>
    <section class="hero ${heroTone}">
      <span class="pill">Wallet RP Session</span>
      <h1>${escapeHtml(heroTitle)}</h1>
      <p class="hero-lead">${escapeHtml(heroLead)}</p>
      <p>This verifier asks for proof that the holder is over 21 plus nationality from a PID mdoc. If the credential exposes <code>birth_date</code> instead of <code>age_over_21</code>, the verifier derives the over-21 result locally after receiving the presentation.</p>
      ${completedSummary}
    </section>
    ${pendingCards}
    ${technicalDetails}
  </main>
</body>
</html>`
}

function normalizeNestedValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeNestedValue(entry))
  }
  if (typeof value !== 'string') return value
  const trimmed = value.trim()
  if (!trimmed) return value
  const looksJson =
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  if (!looksJson) return value
  try {
    return JSON.parse(trimmed)
  } catch {
    return value
  }
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function renderCompletedWalletOutcome(session: WalletRpSession) {
  const claims = session.outcome.claims ?? {}
  const birthdate = normalizeBirthdateClaim(claims.birthdate ?? claims.birth_date)
  const ageOver21 = normalizeBooleanClaim(claims.age_over_21)
  const nationalities = normalizeNationalityClaim(claims.nationalities ?? claims.nationality)
  const credentialLabel = formatCredentialLabel(session.outcome.vct)
  const disclosureNote =
    claims.age_over_21_source === 'derived_from_birthdate'
      ? 'Derived locally from the disclosed birth date.'
      : session.outcome.mode === 'verified'
        ? 'Cryptographically verified from the presentation.'
        : 'Accepted from the wallet presentation.'

  const cards = [
    {
      label: 'Result',
      value: 'Successful authentication',
      note: session.outcome.mode === 'verified' ? 'Presentation verified.' : 'Presentation inspected successfully.'
    },
    {
      label: 'Credential',
      value: credentialLabel,
      note: 'PID document presented from the wallet.'
    },
    ageOver21 === null
      ? null
      : {
          label: 'Over 21',
          value: ageOver21 ? 'Yes' : 'No',
          note: disclosureNote
        },
    nationalities.length === 0
      ? null
      : {
          label: nationalities.length > 1 ? 'Nationalities' : 'Nationality',
          value: nationalities.map((code) => formatNationality(code)).join(', '),
          note: 'Shared from the PID presentation.'
        },
    birthdate
      ? {
          label: 'Birth date',
          value: birthdate,
          note: 'Used for the local over-21 decision.'
        }
      : null
  ].filter((card): card is { label: string; value: string; note: string } => Boolean(card))

  return `
    <div class="summary-grid">
      ${cards
        .map(
          (card) => `
            <article class="summary-card">
              <span class="summary-label">${escapeHtml(card.label)}</span>
              <span class="summary-value">${escapeHtml(card.value)}</span>
              <span class="summary-note">${escapeHtml(card.note)}</span>
            </article>
          `
        )
        .join('')}
    </div>
  `
}

function renderWalletTechnicalDetails(session: WalletRpSession) {
  const detailSummary =
    session.outcome.status === 'complete'
      ? 'Technical details'
      : session.outcome.status === 'error'
        ? 'Error details'
        : 'Session details'
  return `
    <section class="technical">
      <details>
        <summary>${escapeHtml(detailSummary)}</summary>
        <p><strong>Session ID:</strong> <code>${escapeHtml(session.id)}</code></p>
        <p><strong>State:</strong> <code>${escapeHtml(session.state)}</code></p>
        <p><strong>Nonce:</strong> <code>${escapeHtml(session.nonce)}</code></p>
        <p><strong>Created:</strong> <code>${escapeHtml(session.createdAt)}</code></p>
        <p><strong>Expires:</strong> <code>${escapeHtml(session.expiresAt)}</code></p>
        <p><strong>Request URI:</strong><br /><code>${escapeHtml(session.requestUri)}</code></p>
        <p><strong>Response URI:</strong><br /><code>${escapeHtml(session.responseUri)}</code></p>
        <pre>${escapeHtml(JSON.stringify(session.outcome, null, 2))}</pre>
      </details>
    </section>
  `
}

function formatCredentialLabel(value: unknown) {
  if (value === 'eu.europa.ec.eudi.pid.1') return 'EU PID (MSO mdoc)'
  if (typeof value === 'string' && value.trim().length > 0) return value.trim()
  return 'Wallet credential'
}

function formatNationality(value: string) {
  const code = value.trim().toUpperCase()
  if (!code) return value
  try {
    const regionNames = new Intl.DisplayNames(['en'], { type: 'region' })
    const label = regionNames.of(code)
    if (label && label !== code) return `${label} (${code})`
  } catch {
    // Fall back to the raw code if ICU data is unavailable.
  }
  return code
}

function normalizeNationalityClaim(value: unknown) {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    return [value.trim()]
  }
  return []
}

function normalizeBirthdateClaim(value: unknown) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return null
  return trimmed
}

function normalizeBooleanClaim(value: unknown) {
  if (typeof value === 'boolean') return value
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase()
    if (['true', 'yes', 'y', '1'].includes(normalized)) return true
    if (['false', 'no', 'n', '0'].includes(normalized)) return false
  }
  return null
}

function isAtLeast21(birthdate: string, now: Date) {
  const date = new Date(`${birthdate}T00:00:00Z`)
  if (Number.isNaN(date.getTime())) return null
  let years = now.getUTCFullYear() - date.getUTCFullYear()
  const monthDelta = now.getUTCMonth() - date.getUTCMonth()
  const dayDelta = now.getUTCDate() - date.getUTCDate()
  if (monthDelta < 0 || (monthDelta === 0 && dayDelta < 0)) {
    years -= 1
  }
  return years >= 21
}
