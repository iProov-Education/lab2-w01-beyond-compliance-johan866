import assert from 'node:assert/strict'
import test from 'node:test'
import { hashDisclosure, parseDisclosure, reconstructSdJwtClaims, splitPresentedSdJwt } from '../src/sd-jwt.ts'

function encodeDisclosure(value: unknown[]) {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

function encodeJwt(payload: Record<string, unknown>) {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'vc+sd-jwt' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${body}.`
}

test('parseDisclosure accepts both object and array disclosure shapes', () => {
  const objectDisclosure = parseDisclosure(encodeDisclosure(['salt-1', 'birthdate', '1994-10-21']))
  const arrayDisclosure = parseDisclosure(encodeDisclosure(['salt-2', 'SE']))

  assert.deepEqual(objectDisclosure, {
    kind: 'object',
    salt: 'salt-1',
    name: 'birthdate',
    value: '1994-10-21',
    encoded: encodeDisclosure(['salt-1', 'birthdate', '1994-10-21']),
    hash: hashDisclosure(encodeDisclosure(['salt-1', 'birthdate', '1994-10-21']))
  })
  assert.deepEqual(arrayDisclosure, {
    kind: 'array',
    salt: 'salt-2',
    value: 'SE',
    encoded: encodeDisclosure(['salt-2', 'SE']),
    hash: hashDisclosure(encodeDisclosure(['salt-2', 'SE']))
  })
})

test('reconstructSdJwtClaims materializes disclosed array entries from placeholder hashes', () => {
  const birthdateDisclosure = encodeDisclosure(['salt-1', 'birthdate', '1994-10-21'])
  const nationalityDisclosure = encodeDisclosure(['salt-2', 'SE'])
  const payload = {
    iss: 'https://issuer.example',
    vct: 'urn:eudi:pid:1',
    _sd: [hashDisclosure(birthdateDisclosure)],
    nationalities: [{ '...': hashDisclosure(nationalityDisclosure) }]
  }

  const result = reconstructSdJwtClaims(payload, [birthdateDisclosure, nationalityDisclosure])

  assert.deepEqual(result.payload, {
    iss: 'https://issuer.example',
    vct: 'urn:eudi:pid:1',
    birthdate: '1994-10-21',
    nationalities: ['SE']
  })
  assert.deepEqual(result.claims, {
    birthdate: '1994-10-21',
    nationalities: ['SE']
  })
})

test('splitPresentedSdJwt keeps disclosures separate from an optional key-binding jwt', () => {
  const disclosure = encodeDisclosure(['salt-1', 'birthdate', '1994-10-21'])
  const kbJwt = encodeJwt({ aud: 'https://verifier.example', nonce: 'nonce-1' })
  const combined = `${encodeJwt({ iss: 'https://issuer.example' })}~${disclosure}~${kbJwt}`

  const result = splitPresentedSdJwt(combined)

  assert.equal(result.sdJwt, encodeJwt({ iss: 'https://issuer.example' }))
  assert.deepEqual(result.disclosures, [disclosure])
  assert.equal(result.keyBindingJwt, kbJwt)
})
