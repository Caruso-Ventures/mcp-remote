import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ReconnectingServerTransport } from './reconnecting-transport'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'

vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
}))

function makeTransport(): Transport {
  return {
    send: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
    start: vi.fn().mockResolvedValue(undefined),
    onmessage: undefined,
    onclose: undefined,
    onerror: undefined,
  } as unknown as Transport
}

describe('ReconnectingServerTransport', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('forwards send() to the inner transport and relays inner onmessage', async () => {
    const inner = makeTransport()
    const wrapper = new ReconnectingServerTransport(inner, { connect: vi.fn() })

    const onmessage = vi.fn()
    wrapper.onmessage = onmessage

    await wrapper.send({ jsonrpc: '2.0', id: 1, method: 'ping' })
    expect(inner.send).toHaveBeenCalledWith({ jsonrpc: '2.0', id: 1, method: 'ping' })

    inner.onmessage?.({ jsonrpc: '2.0', id: 1, result: {} })
    expect(onmessage).toHaveBeenCalledWith({ jsonrpc: '2.0', id: 1, result: {} })
  })

  it('transient inner onclose does not propagate; reconnects and wires the new inner', async () => {
    const inner = makeTransport()
    const next = makeTransport()
    const connect = vi.fn().mockResolvedValue(next)
    const wrapper = new ReconnectingServerTransport(inner, { connect })

    const onclose = vi.fn()
    wrapper.onclose = onclose

    inner.onclose?.()
    await vi.runAllTimersAsync()

    expect(onclose).not.toHaveBeenCalled()
    expect(connect).toHaveBeenCalledTimes(1)

    const onmessage = vi.fn()
    wrapper.onmessage = onmessage
    next.onmessage?.({ jsonrpc: '2.0', id: 2, result: {} })
    expect(onmessage).toHaveBeenCalledWith({ jsonrpc: '2.0', id: 2, result: {} })
  })

  it('backoff: connect() rejects 3x then resolves; ends connected, onReconnected fires once', async () => {
    const inner = makeTransport()
    const next = makeTransport()
    const connect = vi
      .fn()
      .mockRejectedValueOnce(new Error('fail1'))
      .mockRejectedValueOnce(new Error('fail2'))
      .mockRejectedValueOnce(new Error('fail3'))
      .mockResolvedValueOnce(next)
    const onReconnected = vi.fn()
    const wrapper = new ReconnectingServerTransport(inner, { connect, onReconnected, maxDelayMs: 1000 })

    inner.onclose?.()
    await vi.runAllTimersAsync()

    expect(connect).toHaveBeenCalledTimes(4)
    expect(wrapper.isConnected()).toBe(true)
    expect(onReconnected).toHaveBeenCalledTimes(1)
    expect(onReconnected).toHaveBeenCalledWith(next)
  })

  it('send() rejection triggers a reconnect and re-throws to the caller', async () => {
    const inner = makeTransport()
    vi.mocked(inner.send).mockRejectedValueOnce(new Error('boom'))
    const next = makeTransport()
    const connect = vi.fn().mockResolvedValue(next)
    const wrapper = new ReconnectingServerTransport(inner, { connect })

    await expect(wrapper.send({ jsonrpc: '2.0', id: 1, method: 'x' })).rejects.toThrow('boom')

    await vi.runAllTimersAsync()
    expect(connect).toHaveBeenCalledTimes(1)
  })

  it('close() closes the inner transport, stops reconnecting, and calls onclose permanently', async () => {
    const inner = makeTransport()
    const connect = vi.fn().mockResolvedValue(makeTransport())
    const wrapper = new ReconnectingServerTransport(inner, { connect })
    const onclose = vi.fn()
    wrapper.onclose = onclose

    await wrapper.close()

    expect(inner.close).toHaveBeenCalled()
    expect(onclose).toHaveBeenCalledTimes(1)

    // A transient inner onclose firing after close() must not restart reconnecting.
    inner.onclose?.()
    await vi.runAllTimersAsync()
    expect(connect).not.toHaveBeenCalled()
  })

  it('isConnected() transitions false during reconnect and true after', async () => {
    const inner = makeTransport()
    const next = makeTransport()
    let resolveConnect: (t: Transport) => void
    const connect = vi.fn().mockImplementation(
      () =>
        new Promise<Transport>((resolve) => {
          resolveConnect = resolve
        }),
    )
    const wrapper = new ReconnectingServerTransport(inner, { connect })

    expect(wrapper.isConnected()).toBe(true)
    inner.onclose?.()
    await vi.advanceTimersByTimeAsync(1000) // clear the jittered backoff delay so connect() is invoked
    expect(wrapper.isConnected()).toBe(false)
    expect(connect).toHaveBeenCalledTimes(1)

    resolveConnect!(next)
    await vi.runAllTimersAsync()
    expect(wrapper.isConnected()).toBe(true)
  })

  it('close() during an in-flight connect(): the late-resolving transport is closed, not adopted', async () => {
    const inner = makeTransport()
    const next = makeTransport()
    let resolveConnect: (t: Transport) => void
    const connect = vi.fn().mockImplementation(
      () =>
        new Promise<Transport>((resolve) => {
          resolveConnect = resolve
        }),
    )
    const onReconnected = vi.fn()
    const onclose = vi.fn()
    const wrapper = new ReconnectingServerTransport(inner, { connect, onReconnected })
    wrapper.onclose = onclose

    inner.onclose?.()
    await vi.advanceTimersByTimeAsync(1000) // clear the jittered backoff delay so connect() is invoked
    expect(connect).toHaveBeenCalledTimes(1)
    expect(wrapper.isConnected()).toBe(false)

    // Permanent close happens while connect() is still pending.
    await wrapper.close()
    expect(onclose).toHaveBeenCalledTimes(1)

    // The in-flight connect() now resolves — must not resurrect the wrapper.
    resolveConnect!(next)
    await vi.runAllTimersAsync()

    expect(next.close).toHaveBeenCalled()
    expect(onReconnected).not.toHaveBeenCalled()
    expect(wrapper.isConnected()).toBe(false)
  })
})
