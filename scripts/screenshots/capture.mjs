// Captures the README screenshots into docs/screenshots/.
//
// Needs `pnpm dev` running (the in-memory mock backend supplies the data, so
// nothing from your own ~/.ssh is shown) and Google Chrome. Run with
// `pnpm screenshots`. CHROME and APP_URL override the defaults.

import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import puppeteer from 'puppeteer-core';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const out = join(root, 'docs/screenshots');
const frame = pathToFileURL(join(root, 'scripts/screenshots/frame.html'));
const chrome = process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const app = process.env.APP_URL ?? 'http://localhost:1420';

const shots = [
  ['overview', 'page=overview'],
  [
    'keys',
    `page=keys&key=${encodeURIComponent('SHA256:u9Fh2KdL7pQ3zX8mV1bN6rT4wY0sGcJ5aE2iOkHjUyB#id_rsa')}`,
  ],
  ['generate', 'page=keys&open=generate'],
  ['hosts', 'page=hosts&host=3'],
  ['agent', 'page=agent'],
  ['audit', 'page=audit'],
  ['known', 'page=known'],
];

mkdirSync(out, { recursive: true });
const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: true,
  args: ['--lang=en-US', '--hide-scrollbars'],
  defaultViewport: { width: 1440, height: 960, deviceScaleFactor: 2 },
});

try {
  for (const [name, query] of shots) {
    const page = await browser.newPage();
    const url = new URL(frame);
    url.searchParams.set('src', `${app}/?${query}`);
    await page.goto(url.href, { waitUntil: 'networkidle0' });
    // Let queries settle and entry animations finish.
    await new Promise((resolve) => setTimeout(resolve, 2500));
    const file = join(out, `${name}.png`);
    await page.screenshot({ path: file });
    await page.close();
    // 2880 px is more than a README needs; 1800 px stays sharp on Retina screens.
    execFileSync('sips', ['--resampleWidth', '1800', file], { stdio: 'ignore' });
    console.log(file);
  }
} finally {
  await browser.close();
}
