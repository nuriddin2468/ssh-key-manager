// Builds the extension into extension/dist/chromium (Chrome, Edge, Brave…)
// and extension/dist/firefox, ready to load unpacked or as a temporary
// add-on. Each script is bundled on its own as a plain script: content
// scripts and Firefox's background page can't be modules.

import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, 'dist');
const bundles = join(dist, '.bundles');
const SCRIPTS = ['background', 'content', 'popup', 'connect'];
const PAGES = ['popup.html', 'connect.html', 'pages.css'];

/** The manifest for one browser family. */
function manifestFor(base, target) {
  const manifest = structuredClone(base);
  if (target === 'chromium') {
    delete manifest.browser_specific_settings;
  } else {
    // Firefox has no extension service workers, and finds itself by its id.
    delete manifest.key;
    delete manifest.minimum_chrome_version;
    manifest.background = { scripts: ['background.js'] };
  }
  return manifest;
}

await rm(dist, { recursive: true, force: true });
for (const name of SCRIPTS) {
  await build({
    configFile: false,
    root,
    logLevel: 'warn',
    publicDir: false,
    build: {
      outDir: bundles,
      emptyOutDir: false,
      target: ['chrome121', 'firefox128'],
      minify: false,
      lib: {
        entry: join(root, 'src', `${name}.ts`),
        formats: ['iife'],
        name: `sshkm_${name}`,
        fileName: () => `${name}.js`,
      },
    },
  });
}

const manifest = JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8'));
for (const target of ['chromium', 'firefox']) {
  const out = join(dist, target);
  await mkdir(out, { recursive: true });
  await cp(bundles, out, { recursive: true });
  for (const page of PAGES) await cp(join(root, 'src', page), join(out, page));
  await cp(join(root, 'icons'), join(out, 'icons'), { recursive: true });
  await cp(join(root, '_locales'), join(out, '_locales'), { recursive: true });
  await writeFile(
    join(out, 'manifest.json'),
    `${JSON.stringify(manifestFor(manifest, target), null, 2)}\n`,
  );
  console.log(`extension/dist/${target}`);
}
await rm(bundles, { recursive: true, force: true });
