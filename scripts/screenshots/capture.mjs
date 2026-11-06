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

// Name, the app's dev query, and the section heading to scroll to, if any.
const shots = [
  ['overview', 'page=overview'],
  [
    'keys',
    `page=keys&key=${encodeURIComponent('SHA256:u9Fh2KdL7pQ3zX8mV1bN6rT4wY0sGcJ5aE2iOkHjUyB#id_rsa')}`,
  ],
  ['generate', 'page=keys&open=generate'],
  ['hosts', 'page=hosts'],
  ['agent', 'page=agent'],
  ['audit', 'page=audit'],
  ['known', 'page=known'],
  ['hosts-file', 'page=hostsFile'],
  ['passwords', 'page=passwords'],
  ['terminal', 'page=terminal&connect=prod-api'],
  ['nearby', 'page=nearby'],
  ['background', 'page=settings', 'Background'],
];

mkdirSync(out, { recursive: true });
const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: true,
  args: ['--lang=en-US', '--hide-scrollbars'],
  defaultViewport: { width: 1440, height: 960, deviceScaleFactor: 2 },
});

try {
  for (const [name, query, section] of shots) {
    const page = await browser.newPage();
    const url = new URL(frame);
    // The mock vault starts locked; Passwords, Nearby and Settings show more unlocked.
    url.searchParams.set('src', `${app}/?${query}&vault=unlocked`);
    await page.goto(url.href, { waitUntil: 'networkidle0' });
    // Let queries settle and entry animations finish.
    await new Promise((resolve) => setTimeout(resolve, 2500));
    if (section) {
      const view = page.frames().find((candidate) => candidate.url().startsWith(app));
      await view?.evaluate((title) => {
        const heading = [...document.querySelectorAll('h2')].find(
          (element) => element.textContent === title,
        );
        heading?.scrollIntoView({ block: 'start' });
        // Leave the page's top padding above the heading.
        let scroller = heading?.parentElement;
        while (scroller && scroller.scrollHeight <= scroller.clientHeight) {
          scroller = scroller.parentElement;
        }
        if (scroller) scroller.scrollTop -= 16;
      }, section);
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
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
