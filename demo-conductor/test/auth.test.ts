import assert from 'node:assert/strict'
import test from 'node:test'
import { createAuthCookie, createOpenAuthUser, readAuthCookie, renderLoginPage } from '../src/auth.ts'

test('createOpenAuthUser builds an open session profile and auth cookies round-trip', () => {
  const user = createOpenAuthUser('guest-123')
  const cookie = createAuthCookie(user, 'secret-key', false)

  assert.deepEqual(user, {
    id: 'guest-123',
    email: null,
    name: 'Open demo session',
    picture: null,
    mode: 'open'
  })
  assert.deepEqual(readAuthCookie(cookie, 'secret-key'), user)
})

test('renderLoginPage offers the open login fallback alongside Google sign-in', () => {
  const html = renderLoginPage({
    googleClientId: 'test-client-id',
    googleEnabled: true
  })

  assert.match(html, /Continue without Google/)
  assert.match(html, /fetch\('\/auth\/open'/)
  assert.match(html, /Google sign-in keeps sessions separate, but it is optional/)
})
