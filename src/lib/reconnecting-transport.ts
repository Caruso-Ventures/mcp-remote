import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { log, debugLog } from './utils'

export interface ReconnectOptions {
  connect: () => Promise<Transport> // factory: connectToRemoteServer(..., allowInteractiveAuth=false)
  minDelayMs?: number // default 500
  maxDelayMs?: number // default 30_000
  onReconnected?: (t: Transport) => void
  onStateChange?: (connected: boolean) => void
}

// Wraps the real upstream transport so `mcpProxy` can keep a single, stable
// reference across upstream blips. StreamableHTTP has no standing socket, so
// a dead upstream surfaces as a send() rejection (or onerror), not always an
// onclose — reconnect is driven by all three. Retries are infinite with full
// jitter backoff: the local stdio server must stay alive across an
// arbitrarily long outage, served from cache in the meantime.
export class ReconnectingServerTransport implements Transport {
  onmessage?: (message: any) => void
  onclose?: () => void
  onerror?: (error: Error) => void

  private current: Transport
  private readonly opts: Required<Pick<ReconnectOptions, 'minDelayMs' | 'maxDelayMs'>> & ReconnectOptions
  private reconnecting = false
  private closed = false
  private connected = true

  constructor(initial: Transport, opts: ReconnectOptions) {
    this.opts = { minDelayMs: 500, maxDelayMs: 30_000, ...opts }
    this.current = initial
    this.wireInner(this.current)
  }

  isConnected(): boolean {
    return this.connected && !this.closed
  }

  async start(): Promise<void> {
    /* inner already started by connectToRemoteServer; no-op */
  }

  async send(message: any): Promise<void> {
    if (this.closed) throw new Error('transport closed')
    try {
      await this.current.send(message)
    } catch (err) {
      // StreamableHTTP has no standing socket: a dead upstream surfaces here.
      debugLog('[reconnect] send failed, scheduling reconnect', { message: (err as Error).message })
      this.scheduleReconnect()
      throw err // let mcpProxy synthesize a client response for this id
    }
  }

  async close(): Promise<void> {
    this.closed = true // permanent: stop the reconnect loop
    try {
      await this.current.close()
    } catch {
      /* ignore */
    }
    this.onclose?.() // ONLY here does the local server learn the upstream is gone
  }

  private wireInner(t: Transport) {
    t.onmessage = (m: any) => this.onmessage?.(m)
    t.onerror = (e: Error) => {
      this.onerror?.(e)
      this.scheduleReconnect()
    }
    t.onclose = () => {
      if (!this.closed) this.scheduleReconnect() // transient: DO NOT propagate
    }
  }

  private setConnected(v: boolean) {
    if (this.connected !== v) {
      this.connected = v
      this.opts.onStateChange?.(v)
    }
  }

  private scheduleReconnect() {
    if (this.reconnecting || this.closed) return
    this.reconnecting = true
    this.setConnected(false)
    void this.reconnectLoop()
  }

  private async reconnectLoop() {
    let attempt = 0
    while (!this.closed) {
      const cap = Math.min(this.opts.maxDelayMs, this.opts.minDelayMs * 2 ** attempt)
      const delay = Math.floor(Math.random() * cap) // full jitter
      await new Promise((r) => setTimeout(r, delay))
      if (this.closed) return
      attempt++
      try {
        const next = await this.opts.connect()

        // close() may have been called while connect() was in flight — don't
        // resurrect a transport after the local server already saw onclose.
        if (this.closed) {
          try {
            await next.close()
          } catch {
            /* ignore */
          }
          return
        }

        const old = this.current
        // Unwire the outgoing transport first: an async late onclose/onerror
        // from it must not fire scheduleReconnect against the healthy new one.
        old.onmessage = undefined
        old.onerror = undefined
        old.onclose = undefined
        try {
          await old.close()
        } catch {
          /* ignore */
        }
        this.current = next
        this.wireInner(next)
        this.reconnecting = false
        this.setConnected(true)
        log('[reconnect] upstream reconnected')
        this.opts.onReconnected?.(next)
        return
      } catch (e) {
        debugLog('[reconnect] attempt failed', { attempt, message: (e as Error).message })
        // keep looping forever — never tear down the local server
      }
    }
  }
}
