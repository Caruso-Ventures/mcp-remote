// Canary: verifies the installed Claude Code CLI still honors mid-session
// notifications/tools/list_changed from a stdio MCP server — the load-bearing
// assumption behind the cv-mcp bridge. If Anthropic regresses this (it has
// been broken before: #13646, #66084), this exits non-zero and cv-job-run
// alerts before the team feels it.
//
// Deterministic: drives a headless `claude -p` session against a throwaway
// stdio server that adds tool `beta` + emits list_changed when a trigger file
// appears. Asserts the session can call beta afterward. No model self-report
// is trusted beyond the final marker line.
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

// launchd runs with a bare PATH (/usr/bin:/bin:/usr/sbin:/sbin), so the CLI has
// to be resolved explicitly or every scheduled run dies on spawnSync ENOENT.
const claudeBin = process.env.CLAUDE_BIN
  ?? [`${process.env.HOME}/.local/bin/claude`, '/opt/homebrew/bin/claude'].find(p => existsSync(p))
  ?? 'claude'

const dir = mkdtempSync(join(tmpdir(), 'cv-refresh-canary-'))
const trigger = join(dir, 'trigger')
const serverPath = join(dirname(fileURLToPath(import.meta.url)), 'refresh-canary-server.mjs')

const mcpConfig = join(dir, 'mcp.json')
writeFileSync(mcpConfig, JSON.stringify({
  mcpServers: {
    'refresh-canary': {
      type: 'stdio',
      command: 'node',
      args: [serverPath],
      env: { TRIGGER_FILE: trigger },
    },
  },
}))

const prompt = [
  'Do EXACTLY these steps in order:',
  '1) Call the MCP tool alpha.',
  `2) Run bash: touch ${trigger}`,
  '3) Run bash: sleep 8',
  '4) Call the MCP tool beta (it was added mid-session).',
  '5) Reply with ONLY one line: VERDICT: BETA_WORKED or VERDICT: BETA_FAILED - <error>',
].join(' ')

try {
  const out = execFileSync(claudeBin, [
    '-p', '--mcp-config', mcpConfig, '--strict-mcp-config',
    '--allowedTools', 'mcp__refresh-canary__alpha,mcp__refresh-canary__beta,Bash(touch:*),Bash(sleep:*)',
    '--model', 'claude-haiku-4-5-20251001',
    prompt,
  ], { encoding: 'utf8', timeout: 240_000, stdio: ['ignore', 'pipe', 'pipe'] })

  const version = spawnSync(claudeBin, ['--version'], { encoding: 'utf8' }).stdout?.trim() ?? 'unknown'
  if (/VERDICT: BETA_WORKED/.test(out)) {
    console.log(`OK — mid-session list_changed refresh works (${version})`)
    process.exit(0)
  }
  console.error(`CANARY FAIL — Claude Code (${version}) did not refresh tools mid-session.`)
  console.error(`Session tail: ${out.slice(-400)}`)
  console.error('Impact: cv-mcp bridge live-refresh is broken for anyone on this version. Check anthropics/claude-code changelog/issues for list_changed regressions.')
  process.exit(1)
} finally {
  rmSync(dir, { recursive: true, force: true })
}
