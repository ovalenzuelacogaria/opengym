import { describe, it, expect } from 'vitest'
import { passkeyLabel, fmtWhen } from './passkeys.js'

const t = (s, ...a) => a.reduce((v, x, i) => v.replaceAll('{' + i + '}', x), s)

describe('passkeyLabel', () => {
  it('names a platform passkey by OS and browser', () => {
    expect(passkeyLabel({ device: { os: 'Windows', browser: 'Edge', attachment: 'platform' } }, t)).toBe('Windows · Edge')
  })
  it('names one made through the QR dialog as a phone or key, and where it was added from', () => {
    expect(passkeyLabel({ device: { os: 'Windows', browser: 'Chrome', attachment: 'cross-platform' } }, t)).toBe('Phone or security key · added from Windows')
  })
  it('falls back for passkeys made before devices were recorded', () => {
    expect(passkeyLabel({ device: null }, t)).toBe('Passkey')
    expect(passkeyLabel({}, t)).toBe('Passkey')
    expect(passkeyLabel({ device: { os: '', browser: '' } }, t)).toBe('Passkey')
  })
})

describe('fmtWhen', () => {
  it('is empty for nothing or garbage', () => {
    expect(fmtWhen(null)).toBe('')
    expect(fmtWhen('not a date')).toBe('')
  })
  it('formats a date', () => expect(fmtWhen('2026-11-19T10:00:00Z')).toMatch(/2026/))
})
