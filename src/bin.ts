import { parseCommandLineArgs, log } from './lib/utils'
import { runProxy } from './run-proxy'

export function runFromArgv(args: string[]): Promise<void> {
  return parseCommandLineArgs(args, 'Usage: cv-bridge <https://server-url> [callback-port] [--watch-tools <ms>] [--debug]')
    .then((p) =>
      runProxy(
        p.serverUrl,
        p.callbackPort,
        p.headers,
        p.transportStrategy,
        p.host,
        p.staticOAuthClientMetadata,
        p.staticOAuthClientInfo,
        p.authorizeResource,
        p.ignoredTools,
        p.authTimeoutMs,
        p.serverUrlHash,
        p.watchToolsMs,
      ),
    )
    .catch((error) => {
      log('Fatal error:', error)
      process.exit(1)
    })
}
