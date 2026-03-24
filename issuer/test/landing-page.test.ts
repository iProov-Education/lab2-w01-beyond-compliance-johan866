import assert from 'node:assert/strict'
import test from 'node:test'
import { renderIssuerLandingPage } from '../src/landing-page.ts'

test('renderIssuerLandingPage links to issuer metadata and next steps', () => {
  const html = renderIssuerLandingPage({
    statusListId: '1',
    demoMode: true,
    useOhttp: false,
    ohttpRelayUrl: ''
  })

  assert.match(html, /Issuer<\/h1>/)
  assert.match(html, /\/\.well-known\/openid-credential-issuer/)
  assert.match(html, /\/\.well-known\/jwks\.json/)
  assert.match(html, /\/statuslist\/1\.json/)
  assert.match(html, /labs\/README-lab-00-start\.md/)
  assert.match(html, /forwarded <code>3002<\/code> port/)
})
