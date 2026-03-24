import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const scriptUrl = pathToFileURL(path.join(__dirname, '..', 'scripts', 'setup-wallet-forks.js')).href
const mod = await import(scriptUrl)
const api = mod.default ?? mod

test('parseArgs defaults to cloning all wallets beside LearningLab over https', () => {
  assert.deepEqual(api.parseArgs([]), {
    platform: 'all',
    dir: null,
    protocol: 'https',
    dryRun: false,
    allowCodespaces: false,
    help: false
  })
})

test('assertLocalTerminalEnvironment rejects Codespaces by default', () => {
  assert.throws(
    () => api.assertLocalTerminalEnvironment({}, { CODESPACES: 'true' }),
    /local terminal on your laptop/i
  )
})

test('assertLocalTerminalEnvironment allows explicit Codespaces override', () => {
  assert.doesNotThrow(() => api.assertLocalTerminalEnvironment({ allowCodespaces: true }, { CODESPACES: 'true' }))
})

test('createClonePlan resolves sibling wallet directories with https clone URLs', () => {
  const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-plan-root-'))
  const plan = api.createClonePlan(
    {
      platform: 'ios',
      dir: '../wallets',
      protocol: 'https',
      dryRun: false
    },
    repoRoot
  )

  assert.equal(plan.targetRoot, path.resolve(repoRoot, '../wallets'))
  assert.deepEqual(plan.repos, [
    {
      name: 'eudi-app-ios-wallet-ui',
      url: 'https://github.com/johan-sellstrom/eudi-app-ios-wallet-ui.git',
      dest: path.join(plan.targetRoot, 'eudi-app-ios-wallet-ui'),
      exists: false
    }
  ])
})

test('runClonePlan keeps existing repos and clones only missing repos', () => {
  const targetRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-run-root-'))
  const existingDest = path.join(targetRoot, 'eudi-app-ios-wallet-ui')
  const missingDest = path.join(targetRoot, 'eudi-app-android-wallet-ui')
  fs.mkdirSync(existingDest, { recursive: true })

  const calls = []
  api.runClonePlan(
    {
      targetRoot,
      dryRun: false,
      repos: [
        {
          name: 'eudi-app-ios-wallet-ui',
          url: 'https://github.com/johan-sellstrom/eudi-app-ios-wallet-ui.git',
          dest: existingDest,
          exists: true
        },
        {
          name: 'eudi-app-android-wallet-ui',
          url: 'https://github.com/johan-sellstrom/eudi-app-android-wallet-ui.git',
          dest: missingDest,
          exists: false
        }
      ]
    },
    (command, args, options) => {
      calls.push({ command, args, options })
      return { status: 0 }
    }
  )

  assert.deepEqual(calls, [
    {
      command: 'git',
      args: [
        'clone',
        'https://github.com/johan-sellstrom/eudi-app-android-wallet-ui.git',
        missingDest
      ],
      options: { stdio: 'inherit' }
    }
  ])
})

test('formatNextSteps reminds students to use the local runbook and a reachable issuer URL', () => {
  const text = api.formatNextSteps({
    dryRun: true,
    repos: []
  })

  assert.match(text, /workshop forks/i)
  assert.match(text, /iProov gate already wired/i)
  assert.match(text, /STUDENT_WALLET_RUNBOOK\.md/)
  assert.match(text, /local LearningLab checkout/)
  assert.match(text, /do not use localhost unless the issuer is running on this same laptop/i)
})
