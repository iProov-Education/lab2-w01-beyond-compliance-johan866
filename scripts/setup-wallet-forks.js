#!/usr/bin/env node
/*
 * Clone the public workshop EUDI wallet forks beside the LearningLab repo.
 *
 * Why:
 * - The mobile wallet sources live in separate repos and should stay that way.
 * - Students should clone only the platform they need without dealing with
 *   submodules or nested git repositories inside LearningLab.
 * - The cloned repos are already patched for the workshop iProov gate; students
 *   should configure and run them, not add the gate from scratch.
 *
 * Usage:
 *   node scripts/setup-wallet-forks.js
 *   node scripts/setup-wallet-forks.js --platform ios
 *   node scripts/setup-wallet-forks.js --dir ../wallets --dry-run
 *   node scripts/setup-wallet-forks.js --platform ios --allow-codespaces
 */

const fs = require('node:fs')
const path = require('node:path')
const { spawnSync } = require('node:child_process')

const ROOT = path.resolve(__dirname, '..')

const WALLET_REPOS = {
  ios: {
    name: 'eudi-app-ios-wallet-ui',
    httpsUrl: 'https://github.com/johan-sellstrom/eudi-app-ios-wallet-ui.git',
    sshUrl: 'git@github.com:johan-sellstrom/eudi-app-ios-wallet-ui.git'
  },
  android: {
    name: 'eudi-app-android-wallet-ui',
    httpsUrl: 'https://github.com/johan-sellstrom/eudi-app-android-wallet-ui.git',
    sshUrl: 'git@github.com:johan-sellstrom/eudi-app-android-wallet-ui.git'
  }
}

function printUsage() {
  console.log(`setup-wallet-forks.js

Clone the public workshop EUDI wallet forks beside LearningLab.

These repos already contain the iProov presentation-gate wiring used in Lab 06.
They are not the untouched upstream vanilla wallets.

Options:
  --platform <ios|android|all>   Select which wallet repo(s) to clone
  --dir <path>                   Target root for the sibling clones
  --protocol <https|ssh>         Clone protocol (default: https)
  --dry-run                      Print the clone plan without running git
  --allow-codespaces             Override the local-terminal guard
  -h, --help                     Show this message`)
}

function normalizePlatform(value) {
  const normalized = String(value || 'all').trim().toLowerCase()
  if (!normalized || normalized === 'all') return 'all'
  if (normalized === 'ios' || normalized === 'android') return normalized
  throw new Error(`Invalid platform: ${value}. Use ios, android, or all.`)
}

function normalizeProtocol(value) {
  const normalized = String(value || 'https').trim().toLowerCase()
  if (normalized === 'https' || normalized === 'ssh') return normalized
  throw new Error(`Invalid protocol: ${value}. Use https or ssh.`)
}

function parseArgs(argv) {
  const out = {
    platform: 'all',
    dir: null,
    protocol: 'https',
    dryRun: false,
    allowCodespaces: false,
    help: false
  }

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') out.help = true
    else if (arg === '--dry-run') out.dryRun = true
    else if (arg === '--allow-codespaces') out.allowCodespaces = true
    else if (arg === '--platform') out.platform = normalizePlatform(argv[++i])
    else if (arg.startsWith('--platform=')) out.platform = normalizePlatform(arg.split('=')[1])
    else if (arg === '--dir') out.dir = argv[++i]
    else if (arg.startsWith('--dir=')) out.dir = arg.split('=')[1]
    else if (arg === '--protocol') out.protocol = normalizeProtocol(argv[++i])
    else if (arg.startsWith('--protocol=')) out.protocol = normalizeProtocol(arg.split('=')[1])
    else throw new Error(`Unknown argument: ${arg}`)
  }

  return out
}

function isCodespacesEnvironment(env = process.env) {
  return String(env.CODESPACES || '').trim().toLowerCase() === 'true' || Boolean(env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN)
}

function assertLocalTerminalEnvironment(options = {}, env = process.env) {
  if (options.allowCodespaces || !isCodespacesEnvironment(env)) return
  throw new Error(
    'Run this script from a local terminal on your laptop, not inside GitHub Codespaces. ' +
      'Clone your LearningLab student repo locally, then rerun this command there. ' +
      'The mobile wallet repos need local Xcode or Android Studio.'
  )
}

function resolveTargetRoot(dir, repoRoot = ROOT) {
  return path.resolve(repoRoot, dir || '..')
}

function selectWalletRepos(platform) {
  if (platform === 'all') {
    return [WALLET_REPOS.ios, WALLET_REPOS.android]
  }
  return [WALLET_REPOS[platform]]
}

function createClonePlan(options, repoRoot = ROOT) {
  const targetRoot = resolveTargetRoot(options.dir, repoRoot)
  const repos = selectWalletRepos(options.platform).map((repo) => {
    const dest = path.join(targetRoot, repo.name)
    return {
      name: repo.name,
      url: options.protocol === 'ssh' ? repo.sshUrl : repo.httpsUrl,
      dest,
      exists: fs.existsSync(dest)
    }
  })

  return {
    targetRoot,
    dryRun: Boolean(options.dryRun),
    repos
  }
}

function formatClonePlan(plan) {
  return [
    `[wallet-setup] target root: ${plan.targetRoot}`,
    ...plan.repos.map((repo) => {
      const status = repo.exists ? 'keep existing' : 'clone'
      return `[wallet-setup] ${status} ${repo.name} <- ${repo.url}`
    })
  ].join('\n')
}

function runClonePlan(plan, spawnImpl = spawnSync) {
  fs.mkdirSync(plan.targetRoot, { recursive: true })

  for (const repo of plan.repos) {
    if (repo.exists) {
      console.log(`[wallet-setup] keeping existing ${repo.dest}`)
      continue
    }

    if (plan.dryRun) {
      console.log(`[wallet-setup] would clone ${repo.url} -> ${repo.dest}`)
      continue
    }

    console.log(`[wallet-setup] cloning ${repo.name} into ${repo.dest}`)
    const result = spawnImpl('git', ['clone', repo.url, repo.dest], {
      stdio: 'inherit'
    })

    if (result.status !== 0) {
      throw new Error(`git clone failed for ${repo.name}`)
    }
  }
}

function formatNextSteps(plan) {
  const lines = []

  if (plan.dryRun) {
    lines.push('[wallet-setup] preview complete; rerun the same command on your laptop without --dry-run to clone the wallet repo.')
  }

  lines.push('[wallet-setup] next: these are workshop forks with the iProov gate already wired, not the untouched upstream wallets')
  lines.push('[wallet-setup] next: open STUDENT_WALLET_RUNBOOK.md in your local LearningLab checkout')
  lines.push('[wallet-setup] next: open the cloned wallet repo in Xcode or Android Studio on your laptop')
  lines.push('[wallet-setup] next: do not add the iProov SDK from scratch; only set the issuer/verifier values and run the fork')
  lines.push('[wallet-setup] next: use the issuer URL your instructor gave you, or your own local backend URL')
  lines.push('[wallet-setup] next: do not use localhost unless the issuer is running on this same laptop')

  return lines.join('\n')
}

function main(argv = process.argv.slice(2), env = process.env) {
  const args = parseArgs(argv)
  if (args.help) {
    printUsage()
    return
  }

  assertLocalTerminalEnvironment(args, env)

  const plan = createClonePlan(args)
  console.log(formatClonePlan(plan))
  runClonePlan(plan)
  console.log(formatNextSteps(plan))
}

if (require.main === module) {
  try {
    main()
  } catch (err) {
    console.error('[wallet-setup] FAILED:', err?.message || err)
    process.exitCode = 1
  }
}

module.exports = {
  WALLET_REPOS,
  createClonePlan,
  formatClonePlan,
  main,
  assertLocalTerminalEnvironment,
  normalizePlatform,
  normalizeProtocol,
  parseArgs,
  resolveTargetRoot,
  runClonePlan,
  selectWalletRepos,
  formatNextSteps,
  isCodespacesEnvironment
}
