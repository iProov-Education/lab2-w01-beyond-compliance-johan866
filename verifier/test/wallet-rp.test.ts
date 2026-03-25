import assert from 'node:assert/strict'
import test from 'node:test'
import {
  buildWalletRequestObject,
  createWalletSession,
  extractPresentedCredentials,
  normalizeWalletDirectPostBody,
  pickFirstSuccessfulWalletPresentation,
  renderWalletSessionPage,
  summarizeWalletClaims
} from '../src/wallet-rp.ts'

test('createWalletSession builds an x509 SAN DNS deep link for the public verifier', () => {
  const session = createWalletSession('https://verifier.ipid.me', Date.UTC(2026, 2, 23, 12, 0, 0))

  assert.equal(session.clientId, 'verifier.ipid.me')
  assert.equal(session.requestClientId, 'x509_san_dns:verifier.ipid.me')
  assert.equal(session.legalName, 'iProov Verifier')
  assert.match(session.requestUri, /^https:\/\/verifier\.ipid\.me\/wallet\/request\.jwt\//)
  assert.match(session.responseUri, /^https:\/\/verifier\.ipid\.me\/wallet\/direct_post\//)
  assert.match(session.resultUri, /^https:\/\/verifier\.ipid\.me\/wallet\/session\//)
  assert.match(
    session.deepLink,
    /^eudi-openid4vp:\/\/verifier\.ipid\.me\?client_id=x509_san_dns%3Averifier\.ipid\.me&client_id_scheme=x509_san_dns&request_uri=https%3A%2F%2Fverifier\.ipid\.me%2Fwallet%2Frequest\.jwt%2F/
  )
})

test('buildWalletRequestObject asks only for PID mdoc claim variants that prove over-21 plus nationality', () => {
  const session = createWalletSession('https://verifier.ipid.me')
  const request = buildWalletRequestObject(session)

  assert.equal(request.client_id, 'x509_san_dns:verifier.ipid.me')
  assert.equal(request.client_id_scheme, 'x509_san_dns')
  assert.equal(request.response_uri, session.responseUri)
  assert.equal(request.response_type, 'vp_token')
  assert.equal(request.response_mode, 'direct_post')
  assert.equal(request.nonce, session.nonce)
  assert.equal(request.state, session.state)
  assert.equal(request.dcql_query.credentials.length, 2)

  const mdocVariant = request.dcql_query.credentials.find((credential) => credential.id === 'pid-mdoc-birth_date-and-nationality')
  assert.ok(mdocVariant)
  assert.deepEqual(mdocVariant.meta, { doctype_value: 'eu.europa.ec.eudi.pid.1' })
  assert.deepEqual(mdocVariant.claims, [
    { id: 'birth_date', path: ['eu.europa.ec.eudi.pid.1', 'birth_date'] },
    { id: 'nationality', path: ['eu.europa.ec.eudi.pid.1', 'nationality'] }
  ])

  assert.deepEqual(request.dcql_query.credential_sets, [
    {
      options: [
        ['pid-mdoc-age-over-21-and-nationality'],
        ['pid-mdoc-birth_date-and-nationality']
      ],
      purpose:
        'Use the PID mdoc path for the public wallet demo. If the credential exposes birth_date instead of age_over_21, the verifier derives the over-21 decision locally.'
    }
  ])

  assert.deepEqual(request.client_metadata.vp_formats_supported, { mso_mdoc: {} })
})

test('summarizeWalletClaims derives over-21 from birthdate and normalizes nationalities', () => {
  const summary = summarizeWalletClaims(
    {
      birthdate: '1994-10-21',
      nationalities: ['SE']
    },
    new Date('2026-03-24T00:00:00Z')
  )

  assert.equal(summary.over21Derived, true)
  assert.deepEqual(summary.claims, {
    birthdate: '1994-10-21',
    nationalities: ['SE'],
    nationality: 'SE',
    age_over_21: true,
    age_over_21_source: 'derived_from_birthdate'
  })
})

test('normalizeWalletDirectPostBody parses JSON strings and extractPresentedCredentials flattens tokens', () => {
  const normalized = normalizeWalletDirectPostBody({
    vp_token: '{"pid-sd-jwt":["credential-one"],"pid-mdoc":["credential-two"]}',
    presentation_submission: '{"id":"submission-1"}',
    state: 'session-state'
  })

  assert.deepEqual(normalized.presentation_submission, { id: 'submission-1' })
  assert.deepEqual(extractPresentedCredentials(normalized.vp_token), ['credential-one', 'credential-two'])
  assert.deepEqual(
    extractPresentedCredentials([{ credential: 'credential-three' }, { sd_jwt: 'credential-four' }]),
    ['credential-three', 'credential-four']
  )
})

test('pickFirstSuccessfulWalletPresentation skips malformed candidates until one succeeds', async () => {
  const inspected: string[] = []
  const selection = await pickFirstSuccessfulWalletPresentation(
    ['bad-one', 'bad-two', 'good-three'],
    async (credential) => {
      inspected.push(credential)
      if (credential !== 'good-three') throw new Error(`unsupported:${credential}`)
      return { mode: 'verified' as const }
    }
  )

  assert.deepEqual(inspected, ['bad-one', 'bad-two', 'good-three'])
  assert.equal(selection.credential, 'good-three')
  assert.deepEqual(selection.result, { mode: 'verified' })
  assert.deepEqual(selection.skippedErrors, ['unsupported:bad-one', 'unsupported:bad-two'])
})

test('pickFirstSuccessfulWalletPresentation throws a stable error when every candidate fails', async () => {
  await assert.rejects(
    pickFirstSuccessfulWalletPresentation(['bad-one', 'bad-two'], async (credential) => {
      throw new Error(`unsupported:${credential}`)
    }),
    /unsupported:bad-one/
  )
})

test('renderWalletSessionPage shows a prominent human-readable summary for completed sessions', () => {
  const session = createWalletSession('https://verifier.ipid.me', Date.UTC(2026, 2, 24, 15, 0, 0))
  session.outcome = {
    status: 'complete',
    mode: 'inspected',
    vct: 'eu.europa.ec.eudi.pid.1',
    claims: {
      nationality: 'SE',
      birth_date: '1963-04-30',
      nationalities: ['SE'],
      birthdate: '1963-04-30',
      age_over_21: true,
      age_over_21_source: 'derived_from_birthdate'
    },
    payload: {
      format: 'mso_mdoc',
      docType: 'eu.europa.ec.eudi.pid.1'
    },
    kbJwt: null,
    warning: 'mdoc inspection only | age_over_21 derived from PID birthdate'
  }

  const html = renderWalletSessionPage(session, '<svg></svg>')

  assert.match(html, /Successful Authentication/)
  assert.match(html, /Successful authentication/)
  assert.match(html, /Over 21/)
  assert.match(html, /Sweden \(SE\)/)
  assert.match(html, /1963-04-30/)
  assert.match(html, /Technical details/)
  assert.doesNotMatch(html, /<h2>Latest Result<\/h2>/)
})
