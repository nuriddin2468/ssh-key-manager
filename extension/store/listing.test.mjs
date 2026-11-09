import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';

// The Chrome Web Store asks why the extension needs each permission, optional
// ones too, and refuses to publish a package with a permission it has no
// answer for (INVALID_ITEM_METADATA). en.md holds the answers to paste into
// the dashboard's Privacy tab.
it('has an answer for every permission the store asks about', () => {
  const manifest = JSON.parse(readFileSync('extension/manifest.json', 'utf8'));
  const listing = readFileSync('extension/store/en.md', 'utf8').replaceAll('\r\n', '\n');
  const permissions = [...manifest.permissions, ...(manifest.optional_permissions ?? [])];
  for (const permission of permissions) {
    expect(listing, permission).toContain(`### Permission justification: ${permission}\n`);
  }
  const hosts = manifest.content_scripts?.some((script) => script.matches?.length);
  if (hosts || manifest.host_permissions?.length) {
    expect(listing).toContain('### Host permission justification\n');
  }
});
