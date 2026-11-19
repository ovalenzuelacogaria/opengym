import { describe, it, expect } from 'vitest'
import { lockedFrom, canEnter, mustWait } from './gate.js'

describe('lockedFrom', () => {
  it('follows the live config', () => {
    expect(lockedFrom({ guest_mode: false }, '0')).toBe(true)
    expect(lockedFrom({ guest_mode: true }, '1')).toBe(false)
    expect(lockedFrom({}, '1')).toBe(false)   // an original server says nothing: open, as before
  })
  it('falls back to the last answer when the config has not arrived', () => {
    expect(lockedFrom(null, '1')).toBe(true)
    expect(lockedFrom(null, '0')).toBe(false)
    expect(lockedFrom(null, null)).toBe(false)
  })
})

describe('canEnter on a locked instance', () => {
  const locked = true
  it('bad: a cached profile without a confirmed session stays out', () => {
    expect(canEnter({ locked, user: { id: 'u' }, sessionOk: false, guest: false })).toBe(false)
  })
  it('bad: the guest flag left over from before does not open it', () => {
    expect(canEnter({ locked, user: null, sessionOk: false, guest: true })).toBe(false)
  })
  it('twin: a profile with a session the server confirmed goes in', () => {
    expect(canEnter({ locked, user: { id: 'u' }, sessionOk: true, guest: false })).toBe(true)
  })
})

describe('canEnter on an open instance (the original behaviour)', () => {
  const locked = false
  it('a guest goes in', () => expect(canEnter({ locked, user: null, guest: true })).toBe(true))
  it('a cached profile goes in before the server answers', () => expect(canEnter({ locked, user: { id: 'u' }, sessionOk: false })).toBe(true))
  it('nobody stays on the sign-in screen', () => expect(canEnter({ locked, user: null, guest: false })).toBe(false))
})

describe('mustWait', () => {
  it('holds the splash until boot when the instance is locked or has never been asked', () => {
    expect(mustWait({ ready: false, cached: '1' })).toBe(true)
    expect(mustWait({ ready: false, cached: null })).toBe(true)
  })
  it('does not hold an instance known to be open, nor the demo or phone builds, nor after boot', () => {
    expect(mustWait({ ready: false, cached: '0' })).toBe(false)
    expect(mustWait({ ready: false, cached: null, demo: true })).toBe(false)
    expect(mustWait({ ready: false, cached: null, mobile: true })).toBe(false)
    expect(mustWait({ ready: true, cached: '1' })).toBe(false)
  })
})
