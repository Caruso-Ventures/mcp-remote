#!/usr/bin/env node

/**
 * MCP Proxy with OAuth support
 * A bidirectional proxy between a local STDIO MCP server and a remote SSE server with OAuth authentication.
 *
 * Run with: npx tsx proxy.ts https://example.remote/server [callback-port]
 *
 * If callback-port is not specified, an available port will be automatically selected.
 *
 * This is the node CLI entry point only; the actual proxy logic lives in
 * ./run-proxy.ts (side-effect-free) so the compiled-binary entry
 * (./bin-compiled.ts, via ./bin.ts) can import it without also re-triggering
 * this file's top-level invocation.
 */

import { runFromArgv } from './bin'

runFromArgv(process.argv.slice(2))
