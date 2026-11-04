// End-to-end check of browser autofill in Chrome, through the real native
// messaging host, against the test bridge (src-tauri/examples/autofill_bridge.rs)
// over a throwaway vault. Nothing touches your browser profile or your vault:
// Chrome runs with a temporary profile, whose NativeMessagingHosts folder
// gets the host manifest.
//
//   cargo build -p sshkm-app --example autofill_bridge && pnpm extension:build
//   node extension/e2e.mjs [path to Chrome] [folder for screenshots]
//
// Quit SSH Key Manager first: the bridge takes over its endpoint file while
// the test runs.
//
// On macOS the host is copied to the temporary profile first: macOS keeps
// browsers out of ~/Documents, ~/Desktop and ~/Downloads, and a host started
// from there hangs before its first instruction.

import { spawn } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const chrome = process.argv[2] ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const shots = process.argv[3] ?? null;
const EXTENSION_ID = 'lkmgdcanagjeajepncgokapkbihahddb';
const HOST = 'dev.sshkeymanager.autofill';
const exe = process.platform === 'win32' ? '.exe' : '';

let failures = 0;
function check(what, ok, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${detail ? ` (${detail})` : ''}`);
  if (!ok) failures += 1;
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** The extension's menu or banner: a plain element, shown as a popover. */
const SURFACE = 'html > div:popover-open';
/** A choice in the menu or banner counts only once it has been in place this long. */
const SETTLE = 600;

// A site with a login form; a sent form lands on /welcome.
const LOGIN = `<!doctype html><title>Sign in</title>
<form action="/welcome" method="post" style="display:grid;gap:8px;width:280px;margin:40px">
  <input id="username" name="username" autocomplete="username" placeholder="Username">
  <input id="password" name="password" type="password" autocomplete="current-password" placeholder="Password">
  <button id="submit">Sign in</button>
</form>`;
const server = createServer((request, response) => {
  response.setHeader('content-type', 'text/html; charset=utf-8');
  response.end(request.url?.startsWith('/welcome') ? '<!doctype html><h1>Welcome</h1>' : LOGIN);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
const site = `http://127.0.0.1:${port}`;

// The bridge, with one saved login for the site.
const bridge = spawn(
  join(root, `target/debug/examples/autofill_bridge${exe}`),
  ['--login', site, 'alice', 's3cret'],
  { stdio: ['pipe', 'pipe', 'inherit'] },
);
const events = [];
const waiters = [];
createInterface({ input: bridge.stdout }).on('line', (line) => {
  const event = JSON.parse(line);
  events.push(event);
  for (const waiter of [...waiters]) waiter(event);
});
function next(name, timeout = 15_000, what = undefined) {
  const fits = (e) => e.event === name && !e.seen && (what === undefined || e.what === what);
  return new Promise((resolve, reject) => {
    const found = events.find(fits);
    if (found) {
      found.seen = true;
      return resolve(found);
    }
    const timer = setTimeout(() => reject(new Error(`no ${name} from the bridge`)), timeout);
    waiters.push(function waiter(event) {
      if (!fits(event)) return;
      event.seen = true;
      clearTimeout(timer);
      waiters.splice(waiters.indexOf(waiter), 1);
      resolve(event);
    });
  });
}
async function bridgeSays(command, answer) {
  bridge.stdin.write(`${command}\n`);
  return next(answer);
}
await next('ready');

const profile = await mkdtemp(join(tmpdir(), 'sshkm-e2e-'));
await mkdir(join(profile, 'NativeMessagingHosts'));
const host = join(profile, `sshkm-app${exe}`);
await copyFile(join(root, `target/debug/sshkm-app${exe}`), host);
await writeFile(
  join(profile, 'NativeMessagingHosts', `${HOST}.json`),
  JSON.stringify({
    name: HOST,
    description: 'SSH Key Manager (test)',
    path: host,
    type: 'stdio',
    allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
  }),
);

const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: true,
  pipe: true,
  userDataDir: profile,
  enableExtensions: [join(root, 'extension/dist/chromium')],
  defaultViewport: { width: 900, height: 640 },
});

async function shot(page, name) {
  if (shots) await page.screenshot({ path: join(shots, `${name}.png`) });
}

async function extensionPage(path) {
  const page = await browser.newPage();
  await page.goto(`chrome-extension://${EXTENSION_ID}/${path}`);
  return page;
}

async function popupText() {
  const page = await extensionPage('popup.html');
  await page.waitForFunction(() => !document.querySelector('.spinner'), { timeout: 15_000 });
  const text = await page.$eval('#app', (app) => app.textContent ?? '');
  await shot(page, `popup-${text.slice(15, 30).replace(/\W+/g, '-')}`);
  await page.close();
  return text;
}

/**
 * When the pairing's keys last changed, from the extension's IndexedDB;
 * with `set`, first makes it that time.
 */
async function pairingKeysAt(set = undefined) {
  // The connect page sends no sealed request, so it changes no keys itself.
  const page = await extensionPage('connect.html');
  const at = await page.evaluate(
    (set) =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open('sshkm-autofill', 1);
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const store = open.result.transaction('pairing', 'readwrite').objectStore('pairing');
          const get = store.get('current');
          get.onsuccess = () => {
            const pairing = get.result;
            if (set === null) return resolve(pairing.keysAt ?? pairing.pairedAt);
            const put = store.put({ ...pairing, keysAt: set }, 'current');
            put.onsuccess = () => resolve(set);
            put.onerror = () => reject(put.error);
          };
        };
      }),
    set ?? null,
  );
  await page.close();
  return at;
}

/** Waits until a menu or banner of the extension is on the page. */
async function surface(page, timeout = 10_000) {
  try {
    await page.waitForSelector(SURFACE, { timeout });
    return true;
  } catch {
    return false;
  }
}

async function signIn(page, username, password) {
  await page.goto(`${site}/login`);
  await page.click('#username', { clickCount: 3 });
  await page.keyboard.type(username);
  await page.click('#password', { clickCount: 3 });
  await page.keyboard.type(password);
  await Promise.all([page.waitForNavigation(), page.click('#submit')]);
}

/** Clicks the banner's main button: the last button, at its bottom right. */
async function clickBannerSave(page) {
  await sleep(SETTLE);
  const box = await page.$eval(SURFACE, (host) => {
    const r = host.getBoundingClientRect();
    return { right: r.right, bottom: r.bottom };
  });
  await page.mouse.click(box.right - 14 - 22, box.bottom - 12 - 15);
}

try {
  check('the popup asks to connect', (await popupText()).includes('Connect this browser'));

  // Pairing: the code on the page is the one the app is asked about.
  const connect = await extensionPage('connect.html');
  await connect.waitForSelector('button.primary');
  await shot(connect, 'connect-intro');
  await connect.click('button.primary');
  const pairing = await next('pairing');
  await connect.waitForSelector('.code');
  const shown = await connect.$eval('.code', (code) => code.textContent?.replace(/\s/g, ''));
  await shot(connect, 'connect-code');
  check('the page and the app show the same code', shown === pairing.code, shown);
  await connect.waitForSelector('h1.success', { timeout: 15_000 });
  await shot(connect, 'connect-done');
  check('pairing completes', true);
  await connect.close();
  check('the popup says connected', (await popupText()).includes('Connected'));

  // Filling: the menu under the field, chosen with the keyboard.
  const page = await browser.newPage();
  await page.goto(`${site}/login`);
  await page.focus('#password');
  check('the menu opens on a login field', await surface(page));
  await shot(page, 'menu');
  await page.keyboard.press('ArrowDown');
  await sleep(SETTLE);
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => document.querySelector('#password').value !== '', {
    timeout: 10_000,
  });
  const filled = await page.evaluate(() => [
    document.querySelector('#username').value,
    document.querySelector('#password').value,
  ]);
  check(
    'the picked login fills both fields',
    filled.join('/') === 'alice/s3cret',
    filled.join('/'),
  );
  const asked = await next('fill');
  check(
    'the app asked before filling, naming the login and the page',
    asked.site === site && asked.username === 'alice',
    JSON.stringify(asked),
  );

  // Nothing for another host, not even one that is the same machine.
  const other = await browser.newPage();
  await other.goto(`http://localhost:${port}/login`);
  await other.focus('#password');
  check('another host gets no menu', !(await surface(other, 2500)));
  await other.close();

  // Keys a day old change at the next request; filling goes on with the new ones.
  const keysAt = await pairingKeysAt(Date.now() - 2 * 86_400_000);
  await page.goto(`${site}/login`);
  await sleep(11_000); // past the background's 10-second cache of logins
  await page.focus('#password');
  await next('keys'); // the app keeps the browser's next keys
  await next('keys'); // and makes them its current ones on their first use
  check('day-old keys change', (await pairingKeysAt()) > keysAt);
  await page.goto(`${site}/login`);
  await page.focus('#password');
  check('the menu opens with the new keys', await surface(page));
  await page.keyboard.press('ArrowDown');
  await sleep(SETTLE);
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => document.querySelector('#password').value !== '', {
    timeout: 10_000,
  });
  check(
    'an allowed login fills again without asking',
    !events.some((e) => e.event === 'fill' && !e.seen),
  );

  // Saving a new login after the form is sent.
  await signIn(page, 'bob', 'newpass1');
  check('the save banner shows after signing in', await surface(page));
  await shot(page, 'banner-save');
  await clickBannerSave(page);
  await next('changed', 15_000, 'entries');
  let { entries } = await bridgeSays('entries', 'entries');
  const bob = entries.find((e) => e.username === 'bob');
  check(
    'the new login is saved',
    bob?.password === 'newpass1' && bob.url === site,
    JSON.stringify(bob),
  );

  // A changed password updates the login.
  await signIn(page, 'alice', 'changed2');
  check('the update banner shows', await surface(page));
  await shot(page, 'banner-update');
  await clickBannerSave(page);
  await next('changed', 15_000, 'entries');
  ({ entries } = await bridgeSays('entries', 'entries'));
  check(
    'the password is updated',
    entries.find((e) => e.username === 'alice')?.password === 'changed2',
  );
  check('nothing else was added', entries.length === 2, String(entries.length));

  // The same login again: no banner.
  await signIn(page, 'alice', 'changed2');
  check('a saved login is not offered again', !(await surface(page, 2500)));

  // Locked: the menu offers to unlock, the popup says so.
  await bridgeSays('lock', 'locked');
  await page.goto(`${site}/login`);
  await sleep(11_000); // past the background's 10-second cache of logins
  await page.focus('#password');
  check('a locked vault shows the unlock item', await surface(page));
  await shot(page, 'menu-locked');
  check('the popup says locked', (await popupText()).includes('locked'));
  await bridgeSays('unlock', 'unlocked');

  // Disconnecting from the popup removes the pairing in the app too.
  const popup = await extensionPage('popup.html');
  await popup.waitForSelector('button.danger', { timeout: 15_000 });
  await popup.click('button.danger');
  await popup.waitForFunction(
    () => document.querySelector('#app')?.textContent?.includes('Connect this browser'),
    { timeout: 15_000 },
  );
  await popup.close();
  const after = await bridgeSays('entries', 'entries');
  check('disconnecting removes the pairing in the app', after.browsers === 0);
} catch (error) {
  failures += 1;
  console.error(error);
} finally {
  await browser.close();
  bridge.stdin.end('quit\n');
  server.close();
  await rm(profile, { recursive: true, force: true });
}

console.log(failures === 0 ? 'all checks passed' : `${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
