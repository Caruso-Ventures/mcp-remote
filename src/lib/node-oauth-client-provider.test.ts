import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import * as mcpAuthConfig from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'
import { InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { refreshAuthorization, selectResourceURL } from '@modelcontextprotocol/sdk/client/auth.js'

vi.mock('./mcp-auth-config')
vi.mock('./authorization-server-metadata', () => ({
  fetchAuthorizationServerMetadata: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('./utils', () => ({
  getServerUrlHash: () => 'test-hash',
  log: vi.fn(),
  debugLog: vi.fn(),
  DEBUG: false,
  MCP_REMOTE_VERSION: '1.0.0',
}))
vi.mock('open', () => ({ default: vi.fn() }))
vi.mock('@modelcontextprotocol/sdk/client/auth.js', async (importOriginal) => {
  const actual = await importOriginal<any>()
  return {
    ...actual,
    refreshAuthorization: vi.fn(),
    selectResourceURL: vi.fn().mockResolvedValue(undefined),
  }
})
vi.mock('node:fs/promises', () => ({
  mkdir: vi.fn().mockResolvedValue(undefined),
  rm: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('node:fs', () => ({
  statSync: vi.fn().mockReturnValue({ mtimeMs: Date.now() }),
}))

describe('NodeOAuthClientProvider - OAuth Scope Handling', () => {
  let provider: NodeOAuthClientProvider
  let mockReadJsonFile: any
  let mockWriteJsonFile: any
  let mockDeleteConfigFile: any

  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://example.com',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }

  beforeEach(() => {
    mockReadJsonFile = vi.mocked(mcpAuthConfig.readJsonFile)
    mockWriteJsonFile = vi.mocked(mcpAuthConfig.writeJsonFile)
    mockDeleteConfigFile = vi.mocked(mcpAuthConfig.deleteConfigFile)

    mockReadJsonFile.mockResolvedValue(undefined)
    mockWriteJsonFile.mockResolvedValue(undefined)
    mockDeleteConfigFile.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('scope priority', () => {
    it('should prioritize custom scope from staticOAuthClientMetadata', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom read write',
        } as any,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom read write')
    })

    it('should use scope from registration response', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile read:user',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile read:user')
    })

    it('should fallback to default scopes when none provided', () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })
  })

  describe('authorization URL', () => {
    it('should include scope parameter in authorization URL', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'github read:user',
        } as any,
      })

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('github read:user')
    })

    it('should include default scope in authorization URL when none specified', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email profile')
    })
  })

  describe('backward compatibility', () => {
    it('should preserve existing custom scope behavior', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'user:email repo',
          client_name: 'My Custom Client',
        } as any,
      })

      const metadata = provider.clientMetadata

      expect(metadata).toMatchObject({
        scope: 'user:email repo',
        client_name: 'My Custom Client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        software_id: '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d',
        software_version: '1.0.0',
      })
    })
  })

  describe('credential invalidation', () => {
    it('should reset to default scopes after client invalidation', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'extracted custom scopes',
      }

      mockReadJsonFile.mockResolvedValueOnce(clientInfo)
      await provider.clientInformation()
      expect(provider.clientMetadata.scope).toBe('extracted custom scopes')

      await provider.invalidateCredentials('client')

      expect(provider.clientMetadata.scope).toBe('openid email profile')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'client_info.json')
    })

    it('should not delete client info when invalidating only tokens', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).not.toHaveBeenCalledWith('test-hash', 'client_info.json')
    })
  })

  describe('scopes_supported parsing', () => {
    it('should use custom scopes without filtering', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email', 'profile'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'openid email profile custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use all requested scopes without filtering
      expect(clientMetadata.scope).toBe('openid email profile custom:read custom:write')
    })

    it('should use requested scopes regardless of scopes_supported', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['some', 'other', 'scopes'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use requested scopes even if not in scopes_supported
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when scopes_supported is missing', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        // No scopes_supported
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write special:scope',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write special:scope')
    })

    it('should use scopes when scopes_supported is empty', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when no metadata is provided', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes from client registration response', async () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile custom:read',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const clientMetadata = provider.clientMetadata
      // Should use all scopes from registration response
      expect(clientMetadata.scope).toBe('openid email profile custom:read')
    })

    it('should use scopes_supported when no user or client scopes provided', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use scopes_supported when nothing else is provided
      expect(clientMetadata.scope).toBe('openid email')
    })

    it('should treat empty scope string as no scope and use default', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: '',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      // Empty scope should fallback to default
      expect(clientMetadata.scope).toBe('openid email profile')
    })
  })

  describe('provider-side single-flight refresh', () => {
    const staleTokens = {
      access_token: 'old',
      refresh_token: 'rt1',
      expires_in: 300,
      token_type: 'Bearer',
    }
    const freshFromRefresh = {
      access_token: 'new',
      refresh_token: 'rt2',
      expires_in: 300,
      token_type: 'Bearer',
    }

    beforeEach(async () => {
      vi.mocked(refreshAuthorization).mockReset()
      vi.mocked(selectResourceURL)
        .mockReset()
        .mockResolvedValue(undefined as any)
      const { mkdir, rm } = await import('node:fs/promises')
      vi.mocked(mkdir)
        .mockReset()
        .mockResolvedValue(undefined as any)
      vi.mocked(rm)
        .mockReset()
        .mockResolvedValue(undefined as any)
    })

    it('single-flight: N concurrent tokens() calls trigger exactly ONE refresh POST', async () => {
      mockReadJsonFile.mockImplementation(async (_hash: string, filename: string) => {
        if (filename === 'tokens.json') return staleTokens
        if (filename === 'tokens-meta.json') return { savedAt: 0 }
        if (filename === 'client_info.json') return { client_id: 'test-client', redirect_uris: [] }
        return undefined
      })
      vi.mocked(refreshAuthorization).mockResolvedValue(freshFromRefresh as any)

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: { issuer: 'https://auth.example.com', token_endpoint: 'https://auth.example.com/token' },
      })

      const [t1, t2, t3] = await Promise.all([provider.tokens(), provider.tokens(), provider.tokens()])

      expect(refreshAuthorization).toHaveBeenCalledTimes(1)
      expect(t1).toMatchObject(freshFromRefresh)
      expect(t2).toMatchObject(freshFromRefresh)
      expect(t3).toMatchObject(freshFromRefresh)
      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'tokens.json', expect.objectContaining(freshFromRefresh))
    })

    it('lock-timeout path returns the freshest disk tokens without calling refreshAuthorization', async () => {
      vi.useFakeTimers()
      try {
        const { mkdir } = await import('node:fs/promises')
        vi.mocked(mkdir).mockRejectedValue(new Error('locked'))

        const freshSibling = { access_token: 'sibling', refresh_token: 'rt2', expires_in: 300, token_type: 'Bearer' }
        // First 'tokens.json' read (the initial staleness check) is stale;
        // the re-read after the lock-acquire timeout finds a fresh sibling.
        let tokensCall = 0
        mockReadJsonFile.mockImplementation(async (_hash: string, filename: string) => {
          if (filename === 'tokens.json') {
            tokensCall += 1
            return tokensCall === 1 ? staleTokens : freshSibling
          }
          // Always stale for the initial tokensAreFresh() check — the
          // timeout branch never re-checks freshness, it just re-reads.
          if (filename === 'tokens-meta.json') return { savedAt: 0 }
          return undefined
        })

        provider = new NodeOAuthClientProvider({
          ...defaultOptions,
          authorizationServerMetadata: { issuer: 'https://auth.example.com', token_endpoint: 'https://auth.example.com/token' },
        })

        const resultPromise = provider.tokens()
        // Drive the acquireRefreshLock retry loop (250ms sleeps) past its
        // 15s deadline without waiting on real wall-clock time.
        await vi.advanceTimersByTimeAsync(16_000)
        const result = await resultPromise

        expect(result).toMatchObject(freshSibling)
        expect(refreshAuthorization).not.toHaveBeenCalled()
      } finally {
        vi.useRealTimers()
      }
    })

    it("invalid_grant returns current (stale) tokens without saving — browser re-auth is the SDK's job", async () => {
      mockReadJsonFile.mockImplementation(async (_hash: string, filename: string) => {
        if (filename === 'tokens.json') return staleTokens
        if (filename === 'tokens-meta.json') return { savedAt: 0 }
        if (filename === 'client_info.json') return { client_id: 'test-client', redirect_uris: [] }
        return undefined
      })
      vi.mocked(refreshAuthorization).mockRejectedValue(new InvalidGrantError('bad'))

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: { issuer: 'https://auth.example.com', token_endpoint: 'https://auth.example.com/token' },
      })

      const result = await provider.tokens()

      expect(result).toMatchObject(staleTokens)
      expect(mockWriteJsonFile).not.toHaveBeenCalledWith('test-hash', 'tokens.json', expect.anything())
    })

    it('transient refresh error is re-thrown, not swallowed into a browser bounce', async () => {
      mockReadJsonFile.mockImplementation(async (_hash: string, filename: string) => {
        if (filename === 'tokens.json') return staleTokens
        if (filename === 'tokens-meta.json') return { savedAt: 0 }
        if (filename === 'client_info.json') return { client_id: 'test-client', redirect_uris: [] }
        return undefined
      })
      vi.mocked(refreshAuthorization).mockRejectedValue(new Error('network'))

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: { issuer: 'https://auth.example.com', token_endpoint: 'https://auth.example.com/token' },
      })

      await expect(provider.tokens()).rejects.toThrow('network')
    })

    it('fresh token short-circuits: no refresh, no lock', async () => {
      const { mkdir } = await import('node:fs/promises')
      mockReadJsonFile.mockImplementation(async (_hash: string, filename: string) => {
        if (filename === 'tokens.json') return staleTokens
        if (filename === 'tokens-meta.json') return { savedAt: Date.now() }
        return undefined
      })

      provider = new NodeOAuthClientProvider(defaultOptions)

      const result = await provider.tokens()

      expect(result).toMatchObject(staleTokens)
      expect(refreshAuthorization).not.toHaveBeenCalled()
      expect(mkdir).not.toHaveBeenCalled()
    })
  })
})
