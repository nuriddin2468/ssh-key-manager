// The order of the logins in the menu.

import type { LoginOffer } from '../shared/client';

/**
 * The logins for the username in the form first: one saved with just that
 * username, then those it begins; the rest after them, as they came.
 */
export function forUsername(logins: LoginOffer[], typed: string): LoginOffer[] {
  const name = typed.trim().toLowerCase();
  if (!name) return logins;
  const rank = (login: LoginOffer) => {
    const username = login.username.toLowerCase();
    return username === name ? 0 : username.startsWith(name) ? 1 : 2;
  };
  return logins
    .map((login, at) => ({ login, at, rank: rank(login) }))
    .sort((a, b) => a.rank - b.rank || a.at - b.at)
    .map(({ login }) => login);
}
