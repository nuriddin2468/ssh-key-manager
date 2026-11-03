/** The WebExtension API: `browser` in Firefox, `chrome` in Chromium browsers. */
const scope = globalThis as unknown as { browser?: WebExt.Api; chrome?: WebExt.Api };
export const ext = (scope.browser ?? scope.chrome) as WebExt.Api;

/** The browser's name, recorded with the pairing in the app. */
export function browserName(): string {
  const agent = navigator.userAgent;
  if (agent.includes('Firefox/')) return 'Firefox';
  const brands =
    (navigator as { userAgentData?: { brands: { brand: string }[] } }).userAgentData?.brands.map(
      (b) => b.brand,
    ) ?? [];
  for (const brand of ['Microsoft Edge', 'Opera', 'Brave', 'Vivaldi', 'Google Chrome']) {
    if (brands.includes(brand)) return brand;
  }
  if (agent.includes('Edg/')) return 'Microsoft Edge';
  if (agent.includes('OPR/')) return 'Opera';
  if (agent.includes('Vivaldi/')) return 'Vivaldi';
  if ((navigator as { brave?: unknown }).brave) return 'Brave';
  return brands.includes('Chromium') ? 'Chromium' : 'Google Chrome';
}
