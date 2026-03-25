import { createHash } from 'node:crypto'

type ObjectDisclosure = {
  kind: 'object'
  salt: string
  name: string
  value: unknown
  encoded: string
  hash: string
}

type ArrayDisclosure = {
  kind: 'array'
  salt: string
  value: unknown
  encoded: string
  hash: string
}

export type ParsedDisclosure = ObjectDisclosure | ArrayDisclosure

const RESERVED_SD_JWT_CLAIMS = new Set([
  'iss',
  'iat',
  'nbf',
  'exp',
  'sub',
  'aud',
  'jti',
  'vct',
  'cnf',
  'credentialStatus',
  'status',
  '_sd',
  '_sd_alg'
])

export function hashDisclosure(disclosure: string) {
  return createHash('sha256').update(disclosure).digest('base64url')
}

export function parseDisclosure(disclosure: string): ParsedDisclosure {
  const decoded = Buffer.from(disclosure, 'base64url').toString('utf8')
  const arr = JSON.parse(decoded)
  if (!Array.isArray(arr)) {
    throw new Error('invalid_disclosure')
  }
  if (arr.length === 3 && typeof arr[1] === 'string') {
    return {
      kind: 'object',
      salt: String(arr[0]),
      name: arr[1],
      value: arr[2],
      encoded: disclosure,
      hash: hashDisclosure(disclosure)
    }
  }
  if (arr.length === 2) {
    return {
      kind: 'array',
      salt: String(arr[0]),
      value: arr[1],
      encoded: disclosure,
      hash: hashDisclosure(disclosure)
    }
  }
  throw new Error('invalid_disclosure')
}

export function splitPresentedSdJwt(credential: string) {
  const segments = credential.split('~').filter(Boolean)
  const [sdJwt, ...tail] = segments
  if (!sdJwt) throw new Error('missing_sd_jwt')
  const disclosures: string[] = []
  let keyBindingJwt: string | null = null
  for (const segment of tail) {
    if (!keyBindingJwt && looksLikeJwt(segment) && !isDisclosure(segment)) {
      keyBindingJwt = segment
      continue
    }
    disclosures.push(segment)
  }
  if (disclosures.length === 0) throw new Error('missing_disclosures')
  return { sdJwt, disclosures, keyBindingJwt }
}

export function reconstructSdJwtClaims(payload: Record<string, unknown>, disclosures: string[]) {
  const parsedDisclosures = disclosures.map((disclosure) => parseDisclosure(disclosure))
  const disclosureByHash = new Map(parsedDisclosures.map((disclosure) => [disclosure.hash, disclosure]))
  const consumed = new Set<string>()
  const materializedPayload = materializeSdJwtValue(payload, disclosureByHash, consumed)
  if (!materializedPayload || typeof materializedPayload !== 'object' || Array.isArray(materializedPayload)) {
    throw new Error('invalid_sd_jwt_payload')
  }
  if (consumed.size !== disclosureByHash.size) {
    throw new Error('disclosure_mismatch')
  }
  const claims = Object.fromEntries(
    Object.entries(materializedPayload).filter(([key]) => !RESERVED_SD_JWT_CLAIMS.has(key))
  )
  return {
    payload: materializedPayload,
    claims
  }
}

function materializeSdJwtValue(
  value: unknown,
  disclosureByHash: Map<string, ParsedDisclosure>,
  consumed: Set<string>
): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => {
      const arrayHash = getArrayDisclosureHash(entry)
      if (!arrayHash) {
        return materializeSdJwtValue(entry, disclosureByHash, consumed)
      }
      const disclosure = disclosureByHash.get(arrayHash)
      if (!disclosure) throw new Error('disclosure_mismatch')
      if (disclosure.kind !== 'array') throw new Error('invalid_disclosure')
      consumed.add(arrayHash)
      return materializeSdJwtValue(disclosure.value, disclosureByHash, consumed)
    })
  }

  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>
    const materialized: Record<string, unknown> = {}
    for (const [key, entry] of Object.entries(record)) {
      if (key === '_sd') continue
      materialized[key] = materializeSdJwtValue(entry, disclosureByHash, consumed)
    }
    const disclosedHashes = Array.isArray(record._sd)
      ? record._sd.filter((entry): entry is string => typeof entry === 'string')
      : []
    for (const disclosedHash of disclosedHashes) {
      const disclosure = disclosureByHash.get(disclosedHash)
      if (!disclosure) throw new Error('disclosure_mismatch')
      if (disclosure.kind !== 'object') throw new Error('invalid_disclosure')
      consumed.add(disclosedHash)
      materialized[disclosure.name] = materializeSdJwtValue(disclosure.value, disclosureByHash, consumed)
    }
    return materialized
  }

  return value
}

function getArrayDisclosureHash(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const record = value as Record<string, unknown>
  if (Object.keys(record).length !== 1) return null
  return typeof record['...'] === 'string' ? record['...'] : null
}

function looksLikeJwt(value: string) {
  return value.split('.').length === 3
}

function isDisclosure(value: string) {
  try {
    parseDisclosure(value)
    return true
  } catch {
    return false
  }
}
