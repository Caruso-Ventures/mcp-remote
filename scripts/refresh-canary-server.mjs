// Toy stdio MCP server for testing Claude Code's mid-session list_changed handling.
// Starts with tool `alpha` (+ N dummies via DUMMY_COUNT to force deferred mode).
// When TRIGGER_FILE appears, registers tool `beta` and emits notifications/tools/list_changed.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { existsSync, watchFile } from 'node:fs'

const TRIGGER = process.env.TRIGGER_FILE || '/tmp/mcp-refresh-trigger'
const DUMMIES = parseInt(process.env.DUMMY_COUNT || '0', 10)

const server = new McpServer(
  { name: 'refresh-test', version: '1.0.0' },
  { capabilities: { tools: { listChanged: true } } },
)

server.registerTool('alpha', {
  description: 'Returns the string ALPHA_OK. Call this first.',
  inputSchema: {},
}, async () => ({ content: [{ type: 'text', text: 'ALPHA_OK' }] }))

for (let i = 0; i < DUMMIES; i++) {
  server.registerTool(`dummy_${i}`, {
    description: `Dummy padding tool number ${i}. Does nothing useful. Returns DUMMY_${i}. This tool exists only to inflate the tool count so the client defers schemas. Extra words to add schema weight: lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore.`,
    inputSchema: { note: z.string().optional().describe('Optional note, ignored') },
  }, async () => ({ content: [{ type: 'text', text: `DUMMY_${i}` }] }))
}

let betaAdded = false
function addBeta() {
  if (betaAdded) return
  betaAdded = true
  server.registerTool('beta', {
    description: 'Returns the string BETA_OK. This tool was added mid-session.',
    inputSchema: {},
  }, async () => ({ content: [{ type: 'text', text: 'BETA_OK' }] }))
  // registerTool on a connected McpServer auto-emits notifications/tools/list_changed
  console.error(`[refresh-test] beta registered + list_changed emitted at ${new Date().toISOString()}`)
}

// Poll for trigger file (watchFile handles not-yet-existing paths)
watchFile(TRIGGER, { interval: 500 }, () => { if (existsSync(TRIGGER)) addBeta() })
if (existsSync(TRIGGER)) addBeta()

await server.connect(new StdioServerTransport())
console.error(`[refresh-test] up, dummies=${DUMMIES}, trigger=${TRIGGER}`)
