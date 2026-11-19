// Security notices. openGym has no e-mail, so the
// server keeps "a passkey was added / removed", "access was recovered" for the user's other
// sessions and /api/me hands them over; this shows them once and acknowledges them.
// "Got it" acknowledges; closing the sheet any other way shows them again at the next load.
import { useUI } from '../store/useUI.js'
import { t } from './i18n.js'
import { ackNotices } from './api.js'
import { passkeyLabel, fmtWhen } from './passkeys.js'
import { Button } from '../components/ui.jsx'

const TEXT = {
  'passkey.added': n => t('A passkey was added to your profile ({0}) on {1}.', passkeyLabel(n, t), fmtWhen(n.at)),
  'passkey.removed': n => t('A passkey was removed from your profile ({0}) on {1}.', passkeyLabel(n, t), fmtWhen(n.at)),
  'recovery.used': n => t('Access to your profile was recovered with a code on {0}. Earlier passkeys were removed.', fmtWhen(n.at)),
}

export function showNotices(notices) {
  const list = (notices || []).filter(n => TEXT[n.type])
  if (!list.length) return
  useUI.getState().openSheet(close => <>
    <h3>{t('Security notice')}</h3>
    <ul className="small" style={{ margin: '6px 0 12px', paddingLeft: 18, lineHeight: 1.5 }}>
      {list.map(n => <li key={n.id}>{TEXT[n.type](n)}</li>)}
    </ul>
    <div className="muted small" style={{ marginBottom: 14 }}>{t('If this wasn’t you, open Settings → Passkeys, remove what you don’t recognise and use “Sign out everywhere”.')}</div>
    <Button variant="primary" onClick={() => { ackNotices().catch(() => {}); close() }}>{t('Got it')}</Button>
  </>)
}
