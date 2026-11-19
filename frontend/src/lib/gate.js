// Who may see the app. An instance started with GUEST_MODE=0 says
// `guest_mode: false` in /api/config: then the only way past the sign-in screen is a session the
// server has confirmed in this load (GET /api/me) — not a profile cached in localStorage, not the
// guest flag. With guests allowed (the default) the app behaves exactly as it always did.
// The server enforces the same rule on every route; this only decides what to draw.

export const LOCK_KEY = 'gym_locked'   // last answer seen: '1' locked, '0' open, absent = never asked

/** Is this instance closed to guests? The live config wins; until it arrives, the last answer. */
export function lockedFrom(config, cached) {
  if (config) return config.guest_mode === false
  return cached === '1'
}

/** May the app's views be drawn? */
export function canEnter({ locked, user, sessionOk, guest }) {
  return locked ? !!user && !!sessionOk : !!user || !!guest
}

/** Hold the splash screen until boot has asked the server? Only the demo and the phone build,
 *  which have no server, and instances known to be open skip the wait — so a device that has
 *  never asked can't flash a cached view before learning that the instance is locked. */
export function mustWait({ ready, cached, demo, mobile }) {
  if (ready || demo || mobile) return false
  return cached !== '0'
}
