// How a passkey is named in Settings and in security notices.
// The server records where it was created: OS and browser of the request, and whether the
// browser reported a platform authenticator or a cross-platform one (a phone over QR, a key).
import { dateLocale } from './i18n.js'

/** @param p {{ device?: { os?: string, browser?: string, attachment?: string } | null }} */
export function passkeyLabel(p, t) {
  const d = p?.device
  if (!d) return t('Passkey')
  if (d.attachment === 'cross-platform') return t('Phone or security key') + (d.os ? ' · ' + t('added from {0}', d.os) : '')
  return [d.os, d.browser].filter(Boolean).join(' · ') || t('Passkey')
}

export function fmtWhen(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return isNaN(d) ? '' : d.toLocaleDateString(dateLocale(), { day: 'numeric', month: 'short', year: 'numeric' })
}
