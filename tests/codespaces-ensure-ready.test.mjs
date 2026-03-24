import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import codespacesEnsureReady from '../scripts/codespaces-ensure-ready.js'

const { listMissingPaths } = codespacesEnsureReady

async function createWorkspace(pathsToCreate) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'codespaces-ready-'))

  for (const relativePath of pathsToCreate) {
    const absolutePath = path.join(root, relativePath)
    await fs.mkdir(path.dirname(absolutePath), { recursive: true })
    await fs.writeFile(absolutePath, 'placeholder\n')
  }

  return root
}

test('listMissingPaths reports missing setup artifacts', async () => {
  const root = await createWorkspace(['issuer/.env'])

  try {
    const missing = await listMissingPaths(root)

    assert.deepEqual(
      missing.map((entry) => entry.relativePath).sort(),
      [
        'issuer/node_modules/.bin/tsx',
        'verifier/.env',
        'verifier/node_modules/.bin/tsx'
      ]
    )
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
})

test('listMissingPaths returns an empty list when the workspace is ready', async () => {
  const root = await createWorkspace([
    'issuer/.env',
    'verifier/.env',
    'issuer/node_modules/.bin/tsx',
    'verifier/node_modules/.bin/tsx'
  ])

  try {
    const missing = await listMissingPaths(root)
    assert.deepEqual(missing, [])
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
})
