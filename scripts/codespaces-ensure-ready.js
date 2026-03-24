#!/usr/bin/env node

const fs = require('node:fs/promises')
const path = require('node:path')
const { spawn } = require('node:child_process')

const ROOT = path.resolve(__dirname, '..')

const REQUIRED_PATHS = [
  { label: 'issuer tsx binary', relativePath: 'issuer/node_modules/.bin/tsx' },
  { label: 'verifier tsx binary', relativePath: 'verifier/node_modules/.bin/tsx' },
  { label: 'issuer env file', relativePath: 'issuer/.env' },
  { label: 'verifier env file', relativePath: 'verifier/.env' }
]

async function exists(targetPath) {
  try {
    await fs.access(targetPath)
    return true
  } catch {
    return false
  }
}

async function listMissingPaths(rootDir = ROOT) {
  const missing = []

  for (const required of REQUIRED_PATHS) {
    const absolutePath = path.join(rootDir, required.relativePath)
    if (!(await exists(absolutePath))) {
      missing.push(required)
    }
  }

  return missing
}

function runStep(command, args, rootDir = ROOT) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: rootDir,
      stdio: 'inherit',
      shell: false
    })

    child.on('error', reject)
    child.on('exit', (code) => {
      if (code === 0) {
        resolve()
        return
      }

      reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`))
    })
  })
}

async function ensureCodespaceReady(rootDir = ROOT) {
  const missing = await listMissingPaths(rootDir)

  if (!missing.length) {
    console.log('[codespaces] workspace already ready')
    return { changed: false, missing }
  }

  console.log(
    `[codespaces] missing prerequisites: ${missing
      .map((entry) => entry.relativePath)
      .join(', ')}`
  )
  console.log('[codespaces] running setup')

  await runStep('corepack', ['enable'], rootDir)
  await runStep('corepack', ['prepare', 'pnpm@9.7.0', '--activate'], rootDir)
  await runStep('pnpm', ['install', '-r', '--frozen-lockfile'], rootDir)
  await runStep('pnpm', ['env:setup'], rootDir)

  const remaining = await listMissingPaths(rootDir)
  if (remaining.length) {
    throw new Error(
      `workspace still missing prerequisites after setup: ${remaining
        .map((entry) => entry.relativePath)
        .join(', ')}`
    )
  }

  return { changed: true, missing }
}

async function main() {
  await ensureCodespaceReady()
}

if (require.main === module) {
  main().catch((error) => {
    console.error('[codespaces] FAILED:', error?.message || error)
    process.exitCode = 1
  })
}

module.exports = {
  REQUIRED_PATHS,
  ensureCodespaceReady,
  listMissingPaths
}
