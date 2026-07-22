import open from 'open'
import { OAuthClientProvider, refreshAuthorization, selectResourceURL } from '@modelcontextprotocol/sdk/client/auth.js'
import { InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type {
  AuthorizationServerMetadata as SdkAuthorizationServerMetadata,
  OAuthProtectedResourceMetadata,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { StaticOAuthClientInformationFull } from './types'
import { log, debugLog, DEBUG, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { randomUUID } from 'node:crypto'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import type { ProtectedResourceMetadata } from './protected-resource-metadata'
import { mkdir, rm } from 'node:fs/promises'
import { statSync } from 'node:fs'
import { getConfigFilePath } from './mcp-auth-config'

// --- cross-process refresh coordination ---------------------------------
// tokens.json stores a RELATIVE expires_in, so a sidecar records WHEN the
// tokens were saved; together they give absolute expiry. When the access
// token is stale, concurrent proxies would otherwise all burn the same
// (rotating) refresh_token — first wins, the rest get invalid_grant and drop
// the user into a browser re-auth. A mkdir-based cross-process lock (below)
// serializes refresh across sibling processes: acquired in tokens() when
// stale, released in saveTokens()/doCoordinatedRefresh's finally. Within a
// single process, coordinatedRefresh()/inFlightRefresh makes concurrent
// tokens() callers share ONE in-flight refresh instead of each racing the
// lock. Waiters (lock or in-flight) re-read disk after acquiring/joining —
// if a sibling or a concurrent caller already refreshed, they return the
// fresh tokens and the SDK never refreshes at all. saveTokens() is a pure
// write (tokens.json + the savedAt sidecar); it does not touch the lock or
// inFlightRefresh. The browser is opened only on a genuine InvalidGrantError
// surfaced by the SDK's own auth() retry (see redirectToAuthorization) —
// never from this coordination logic.
const REFRESH_SKEW_MS = 30_000 // treat tokens expiring within 30s as stale
const REFRESH_LOCK_TIMEOUT_MS = 15_000 // max wait to acquire the lock
const REFRESH_LOCK_STALE_MS = 60_000 // break locks older than this (crashed holder)
const REFRESH_HTTP_TIMEOUT_MS = 25_000 // treat a hung refresh POST as transient, not invalid_grant

type TokensMeta = { savedAt: number }

function refreshLockPath(serverUrlHash: string): string {
  return getConfigFilePath(serverUrlHash, 'refresh.lock')
}

async function acquireRefreshLock(serverUrlHash: string): Promise<boolean> {
  const lockDir = refreshLockPath(serverUrlHash)
  const deadline = Date.now() + REFRESH_LOCK_TIMEOUT_MS
  while (Date.now() < deadline) {
    try {
      await mkdir(lockDir)
      return true
    } catch {
      // Lock held — break it if stale (holder crashed before saveTokens).
      try {
        const age = Date.now() - statSync(lockDir).mtimeMs
        if (age > REFRESH_LOCK_STALE_MS) {
          await rm(lockDir, { recursive: true, force: true })
          continue
        }
      } catch {
        continue // lock vanished between mkdir and stat — retry immediately
      }
      await new Promise((r) => setTimeout(r, 250))
    }
  }
  return false
}

async function releaseRefreshLock(serverUrlHash: string): Promise<void> {
  await rm(refreshLockPath(serverUrlHash), { recursive: true, force: true }).catch(() => {})
}

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private serverUrlHash: string
  private inFlightRefresh: Promise<OAuthTokens | undefined> | null = null
  private callbackPath: string
  private clientName: string
  private clientUri: string
  private softwareId: string
  private softwareVersion: string
  private staticOAuthClientMetadata: StaticOAuthClientMetadata
  private staticOAuthClientInfo: StaticOAuthClientInformationFull
  private authorizeResource: string | undefined
  private _state: string
  private _clientInfo: OAuthClientInformationFull | undefined
  private authorizationServerMetadata: AuthorizationServerMetadata | undefined
  private protectedResourceMetadata: ProtectedResourceMetadata | undefined
  private wwwAuthenticateScope: string | undefined
  private backgroundMode = false

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = options.serverUrlHash
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    this.authorizeResource = options.authorizeResource
    this._state = randomUUID()
    this._clientInfo = undefined
    this.authorizationServerMetadata = options.authorizationServerMetadata
    this.protectedResourceMetadata = options.protectedResourceMetadata
    this.wwwAuthenticateScope = options.wwwAuthenticateScope
  }

  /**
   * Belt-and-suspenders guard for background reconnects: once enabled,
   * redirectToAuthorization() refuses to open a browser and throws instead.
   */
  setBackgroundMode(v: boolean): void {
    this.backgroundMode = v
  }

  get redirectUrl(): string {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`
  }

  get clientMetadata() {
    const effectiveScope = this.getEffectiveScope()
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
      scope: effectiveScope,
    }
  }

  state(): string {
    return this._state
  }

  /**
   * Gets the authorization server metadata, fetching it if not already available
   * @returns The authorization server metadata, or undefined if unavailable
   */
  async getAuthorizationServerMetadata(): Promise<AuthorizationServerMetadata | undefined> {
    // Already have metadata? Return it
    debugLog(`authorizationServerMetadata: ${JSON.stringify(this.authorizationServerMetadata)}`)
    if (this.authorizationServerMetadata) {
      return this.authorizationServerMetadata
    }

    // Fetch metadata and cache in memory for this session
    try {
      this.authorizationServerMetadata = await fetchAuthorizationServerMetadata(this.options.serverUrl)
      if (this.authorizationServerMetadata?.scopes_supported) {
        debugLog('Authorization server supports scopes', {
          scopes_supported: this.authorizationServerMetadata.scopes_supported,
        })
      }
      return this.authorizationServerMetadata
    } catch (error) {
      debugLog('Failed to fetch authorization server metadata', error)
      return undefined
    }
  }

  private getEffectiveScope(): string {
    // Priority 1: User-provided scope from staticOAuthClientMetadata (highest priority)
    if (this.staticOAuthClientMetadata?.scope && this.staticOAuthClientMetadata.scope.trim().length > 0) {
      debugLog('Using scope from staticOAuthClientMetadata', { scope: this.staticOAuthClientMetadata.scope })
      return this.staticOAuthClientMetadata.scope
    }

    // Priority 2: Scope from WWW-Authenticate header (per MCP spec)
    if (this.wwwAuthenticateScope && this.wwwAuthenticateScope.trim().length > 0) {
      debugLog('Using scope from WWW-Authenticate header', { scope: this.wwwAuthenticateScope })
      return this.wwwAuthenticateScope
    }

    // Priority 3: Scopes from Protected Resource Metadata (RFC 9728)
    if (this.protectedResourceMetadata?.scopes_supported?.length) {
      const scope = this.protectedResourceMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Protected Resource Metadata', {
        scopes_supported: this.protectedResourceMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 4: Scope from client registration response
    if (this._clientInfo?.scope && this._clientInfo.scope.trim().length > 0) {
      debugLog('Using scope from client registration response', { scope: this._clientInfo.scope })
      return this._clientInfo.scope
    }

    // Priority 5: Use authorization server's supported scopes if available
    if (this.authorizationServerMetadata?.scopes_supported?.length) {
      const scope = this.authorizationServerMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Authorization Server Metadata', {
        scopes_supported: this.authorizationServerMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 6: Fallback to hardcoded default
    debugLog('Using fallback default scope')
    return 'openid email profile'
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    debugLog('Reading client info')
    if (this.staticOAuthClientInfo) {
      debugLog('Returning static client info')
      this._clientInfo = this.staticOAuthClientInfo
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )

    if (clientInfo) {
      this._clientInfo = clientInfo
    }

    debugLog('Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    debugLog('Saving client info', { client_id: clientInformation.client_id })
    this._clientInfo = clientInformation
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    debugLog('Reading OAuth tokens')
    if (DEBUG) debugLog('Token request stack trace:', new Error().stack)

    let tokens = await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)

    if (tokens?.refresh_token && !(await this.tokensAreFresh(tokens))) {
      debugLog('Access token stale — coordinated refresh')
      tokens = await this.coordinatedRefresh(tokens)
    }

    if (tokens) {
      const timeLeft = tokens.expires_in || 0

      // Alert if expires_in is invalid
      if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
        debugLog('⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', {
          expiresIn: tokens.expires_in,
          tokenObject: JSON.stringify(tokens),
          stack: new Error('Invalid expires_in value').stack,
        })
      }

      debugLog('Token result:', {
        found: true,
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        isExpired: timeLeft <= 0,
        expiresInValue: tokens.expires_in,
      })
    } else {
      debugLog('Token result: Not found')
    }

    return tokens
  }

  // In-process single-flight: concurrent tokens() callers share ONE refresh
  // instead of each racing the rotating refresh_token (fixes re-entrancy leak).
  private async coordinatedRefresh(stale: OAuthTokens): Promise<OAuthTokens | undefined> {
    if (this.inFlightRefresh) {
      debugLog('Joining in-flight refresh')
      return this.inFlightRefresh
    }
    const p = this.doCoordinatedRefresh(stale).finally(() => {
      this.inFlightRefresh = null
    })
    this.inFlightRefresh = p
    return p
  }

  private async doCoordinatedRefresh(stale: OAuthTokens): Promise<OAuthTokens | undefined> {
    if (!(await acquireRefreshLock(this.serverUrlHash))) {
      // Lock timeout: NEVER hand onward a known-stale rotated RT. Re-read disk —
      // a sibling almost certainly refreshed — and use the freshest tokens.
      debugLog('Refresh lock timeout — re-reading disk for freshest tokens')
      const reread = await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)
      return reread ?? stale
    }
    try {
      // A sibling may have refreshed while we waited on the lock.
      const reread = await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)
      if (reread && (await this.tokensAreFresh(reread))) {
        debugLog('Sibling refreshed while we waited — using fresh disk tokens')
        return reread
      }
      const current = reread ?? stale
      const asMeta = await this.getAuthorizationServerMetadata()
      const clientInfo = await this.clientInformation()
      if (!asMeta?.token_endpoint || !clientInfo || !current.refresh_token) {
        debugLog('Cannot refresh in-provider (missing metadata/client/RT) — returning current tokens')
        return current
      }
      const resource = await selectResourceURL(
        this.options.serverUrl,
        this,
        this.protectedResourceMetadata as unknown as OAuthProtectedResourceMetadata | undefined,
      )
      let timeoutId: ReturnType<typeof setTimeout> | undefined
      try {
        // Bound the refresh POST: a hung request would otherwise hold the
        // cross-process lock (and inFlightRefresh) indefinitely. A timeout
        // is a TRANSIENT failure — same path as a network error below — not
        // an invalid_grant, so it must never invalidate tokens or open a
        // browser.
        const timeout = new Promise<never>((_, reject) => {
          timeoutId = setTimeout(
            () => reject(new Error(`Refresh request timed out after ${REFRESH_HTTP_TIMEOUT_MS}ms`)),
            REFRESH_HTTP_TIMEOUT_MS,
          )
        })
        const fresh = await Promise.race([
          refreshAuthorization(asMeta.issuer, {
            metadata: asMeta as unknown as SdkAuthorizationServerMetadata,
            clientInformation: clientInfo,
            refreshToken: current.refresh_token,
            resource,
          }),
          timeout,
        ])
        await this.saveTokens(fresh) // writes tokens.json + tokens-meta.json sidecar
        debugLog('Provider-side refresh succeeded')
        return fresh
      } catch (err) {
        if (err instanceof InvalidGrantError) {
          // RT genuinely dead — let the SDK's 401 → auth() path drive the (rare,
          // correct) browser re-authorization.
          debugLog('Refresh token dead (invalid_grant) — browser re-auth required')
          return current
        }
        // Transient (network / ServerError): surface it, do NOT browser-bounce.
        throw err
      } finally {
        // Whichever side of the race wins, the other must not dangle and
        // keep the event loop alive (delaying clean process exit).
        clearTimeout(timeoutId)
      }
    } finally {
      await releaseRefreshLock(this.serverUrlHash)
    }
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const timeLeft = tokens.expires_in || 0

    // Alert if expires_in is invalid
    if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
      debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
        expiresIn: tokens.expires_in,
        tokenObject: JSON.stringify(tokens),
        stack: new Error('Invalid expires_in value').stack,
      })
    }

    debugLog('Saving tokens', {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: `${timeLeft} seconds`,
      expiresInValue: tokens.expires_in,
    })

    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokens)
    // Absolute-expiry sidecar (tokens.json only has a relative expires_in).
    await writeJsonFile(this.serverUrlHash, 'tokens-meta.json', { savedAt: Date.now() } satisfies TokensMeta)
  }

  // True when the stored access token is still valid (with skew), judged by
  // the sidecar's absolute savedAt + expires_in. Missing sidecar (pre-upgrade
  // cache) counts as stale, which just costs one coordinated refresh.
  private async tokensAreFresh(tokens: OAuthTokens): Promise<boolean> {
    if (typeof tokens.expires_in !== 'number') return false
    const meta = await readJsonFile<TokensMeta>(this.serverUrlHash, 'tokens-meta.json', {
      parseAsync: async (v: unknown) => v as TokensMeta,
    })
    if (!meta?.savedAt) return false
    return meta.savedAt + tokens.expires_in * 1000 - REFRESH_SKEW_MS > Date.now()
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    if (this.backgroundMode) {
      log(
        '[auth] background token refresh needs re-authorization, but interactive browser auth is suppressed. ' +
          'Serving last-known tools. To re-authenticate, restart the bridge or run the cv-mcp login command.',
      )
      throw new Error('interactive-auth-suppressed') // reject the auth flow instead of opening a browser
    }

    // Optionally fetch metadata for debugging/informational purposes (non-blocking)
    this.getAuthorizationServerMetadata().catch(() => {
      // Ignore errors, metadata is optional
    })

    if (this.authorizeResource) {
      authorizationUrl.searchParams.set('resource', this.authorizeResource)
    }

    const effectiveScope = this.getEffectiveScope()
    authorizationUrl.searchParams.set('scope', effectiveScope)
    debugLog('Added scope parameter to authorization URL', { scopes: effectiveScope })

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    try {
      await open(sanitizeUrl(authorizationUrl.toString()))
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      debugLog('Failed to open browser', error)
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    debugLog('Saving code verifier')
    await writeTextFile(this.serverUrlHash, 'code_verifier.txt', codeVerifier)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    debugLog('Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
    debugLog('Code verifier found:', !!verifier)
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    debugLog(`Invalidating credentials: ${scope}`)

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        this._clientInfo = undefined
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        this._clientInfo = undefined
        debugLog('Client information invalidated')
        break

      case 'tokens':
        await deleteConfigFile(this.serverUrlHash, 'tokens.json')
        debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, 'code_verifier.txt')
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }
}
