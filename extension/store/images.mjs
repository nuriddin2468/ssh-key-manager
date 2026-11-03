// Makes the Chrome Web Store images in extension/store/images:
//
// - four 1280×800 screenshots for each listing language (en, ru);
// - the 440×280 small promo tile;
// - the 128×128 store icon: the app's icon at 96×96 with 16 pixels of
//   transparent padding, as the store asks. It is also the package's
//   extension/icons/icon-128.png.
//
// The screenshots show the real extension in Chrome, talking to the test
// bridge over a throwaway vault (src-tauri/examples/autofill_bridge.rs), on a
// made-up site at console.example.com that this script serves itself. The
// pairing shot also shows the app's dialog, from the UI's mock backend. No
// real vault, browser profile or site is involved.
//
//   cargo build -p sshkm-app --bin sshkm-app --example autofill_bridge
//   pnpm extension:build
//   pnpm dev                      # in another terminal, for the app's dialog
//   node extension/store/images.mjs
//
// Quit SSH Key Manager first: the bridge takes over its endpoint file while
// it runs. The site listens on port 443 of all interfaces, which macOS allows
// without root; PORT picks another. CHROME and APP_URL (default
// http://localhost:1420) override the defaults.

import { execFileSync, spawn } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '../..');
const out = join(here, 'images');
const chrome = process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const app = process.env.APP_URL ?? 'http://localhost:1420';
const port = Number(process.env.PORT ?? 443);
const EXTENSION_ID = 'lkmgdcanagjeajepncgokapkbihahddb';
const HOST = 'dev.sshkeymanager.autofill';
const DOMAIN = 'console.example.com';
const site = port === 443 ? `https://${DOMAIN}` : `https://${DOMAIN}:${port}`;
const exe = process.platform === 'win32' ? '.exe' : '';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** The autofill menu or save banner: a popover `div` on the page's root. */
const SURFACE = 'html > div:popover-open';
/** The menu and banner ignore clicks for 500 ms after they appear. */
const SETTLE = 600;

// The browser window in the screenshots, in CSS pixels. Pages inside it are
// shown at 125% (and captured at twice that), so the extension's surfaces
// stay legible at the store's thumbnail size.
const WINDOW = { x: 120, y: 190, width: 1040, height: 610 };
const CHROME_BAR = 78;
const ZOOM = 1.25;
const viewportFor = (box) => ({
  width: Math.round(box.width / ZOOM),
  height: Math.round((box.height - CHROME_BAR) / ZOOM),
  deviceScaleFactor: 2 * ZOOM,
});

const TEXT = {
  en: {
    site: {
      lang: 'en',
      title: 'Sign in · Example Console',
      heading: 'Sign in',
      lead: 'to continue to Example Console',
      email: 'Email',
      password: 'Password',
      submit: 'Sign in',
      forgot: 'Forgot password?',
      home: 'Example Console',
      welcome: 'Welcome back',
      projects: 'Projects',
      healthy: 'Healthy',
      deploying: 'Deploying',
    },
    shots: {
      fill: [
        'Your logins, right where you sign in',
        'Click a login field and pick a login. Nothing is filled until you do.',
      ],
      save: [
        'Save new logins as you sign in',
        'They go to your SSH Key Manager vault, encrypted on your computer.',
      ],
      connect: [
        'Connect once, with a code you check',
        'The browser and the app show the same code. Every message after that is encrypted.',
      ],
      popup: [
        'Know when autofill is ready',
        'The button shows whether this browser is connected and the vault is unlocked.',
      ],
    },
  },
  ru: {
    site: {
      lang: 'ru',
      title: 'Вход · Example Console',
      heading: 'Вход',
      lead: 'чтобы продолжить в Example Console',
      email: 'Эл. почта',
      password: 'Пароль',
      submit: 'Войти',
      forgot: 'Забыли пароль?',
      home: 'Example Console',
      welcome: 'С возвращением',
      projects: 'Проекты',
      healthy: 'Работает',
      deploying: 'Развёртывается',
    },
    shots: {
      fill: [
        'Логины — прямо в форме входа',
        'Нажмите на поле входа и выберите логин. Без вашего выбора ничего не заполняется.',
      ],
      save: [
        'Сохраняйте новые логины при входе',
        'Они попадают в хранилище SSH Key Manager, зашифрованное на вашем компьютере.',
      ],
      connect: [
        'Одно подключение — по коду',
        'Браузер и приложение показывают один и тот же код. Дальше все сообщения зашифрованы.',
      ],
      popup: [
        'Видно, готово ли автозаполнение',
        'Кнопка показывает, подключён ли браузер и разблокировано ли хранилище.',
      ],
    },
  },
};

// The made-up site: a sign-in page and the page behind it.

const SITE_STYLE = `
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; color: #1f2933; background: #f4f6f9; }
.mark { display: inline-grid; place-items: center; width: 28px; height: 28px; border-radius: 8px; background: #334155; }
.mark::after { content: ""; width: 12px; height: 12px; border-radius: 3px; border: 2.5px solid #e2e8f0; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 15px; }
.signin { display: grid; justify-items: center; padding-top: 12px; }
.card { width: 380px; padding: 24px 28px 28px; background: #fff; border: 1px solid #e3e7ee; border-radius: 14px; box-shadow: 0 12px 32px -18px rgb(15 23 42 / 0.25); }
h1 { margin: 16px 0 2px; font-size: 22px; letter-spacing: -0.01em; }
.lead { margin: 0 0 12px; color: #5b6676; }
label { display: block; margin: 14px 0 6px; font-weight: 500; font-size: 13px; }
input { width: 100%; height: 40px; padding: 0 12px; font: inherit; color: inherit; border: 1px solid #cfd6e0; border-radius: 8px; background: #fff; outline: none; }
input:focus { border-color: #64748b; box-shadow: 0 0 0 3px rgb(100 116 139 / 0.2); }
button { width: 100%; height: 40px; margin-top: 22px; font: inherit; font-weight: 600; color: #fff; background: #1f2937; border: 0; border-radius: 8px; }
.forgot { display: block; margin-top: 16px; text-align: center; color: #5b6676; text-decoration: none; font-size: 13px; }
.top { display: flex; align-items: center; justify-content: space-between; height: 60px; padding: 0 32px; background: #fff; border-bottom: 1px solid #e3e7ee; }
.avatar { width: 30px; height: 30px; border-radius: 50%; background: #cbd5e1; }
main { padding: 36px 32px; }
main h1 { margin: 0 0 22px; }
h2 { margin: 0 0 12px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.06em; color: #5b6676; }
.grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.project { padding: 18px; background: #fff; border: 1px solid #e3e7ee; border-radius: 12px; }
.project b { display: block; margin-bottom: 8px; font-family: ui-monospace, Menlo, monospace; font-size: 13.5px; }
.state { display: flex; align-items: center; gap: 6px; color: #5b6676; font-size: 13px; }
.state::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: #16a34a; }
.state.busy::before { background: #d97706; }
.bar { height: 6px; margin-top: 14px; border-radius: 3px; background: #eef1f5; }
`;

function signInPage(t) {
  return `<!doctype html><html lang="${t.lang}"><meta charset="utf-8"><title>${t.title}</title>
<style>${SITE_STYLE}</style>
<div class="signin"><form class="card" action="/session" method="post">
  <div class="brand"><span class="mark"></span>Example Console</div>
  <h1>${t.heading}</h1><p class="lead">${t.lead}</p>
  <label for="email">${t.email}</label>
  <input id="email" name="email" type="email" autocomplete="username">
  <label for="password">${t.password}</label>
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button id="submit">${t.submit}</button>
  <a class="forgot" href="#">${t.forgot}</a>
</form></div>`;
}

function homePage(t) {
  const project = (name, busy) =>
    `<div class="project"><b>${name}</b><span class="state${busy ? ' busy' : ''}">${busy ? t.deploying : t.healthy}</span><div class="bar"></div></div>`;
  return `<!doctype html><html lang="${t.lang}"><meta charset="utf-8"><title>${t.home}</title>
<style>${SITE_STYLE}</style>
<div class="top"><div class="brand"><span class="mark"></span>Example Console</div><span class="avatar"></span></div>
<main><h1>${t.welcome}</h1><h2>${t.projects}</h2>
<div class="grid">${project('web-frontend')}${project('billing-api', true)}${project('data-pipeline')}${project('auth-service')}${project('docs-site')}${project('metrics')}</div></main>`;
}

// The frame around each screenshot: the app's dark canvas with the
// Passwords section's pink glow, a caption, and a plain browser window.

const png = (bytes) => `data:image/png;base64,${Buffer.from(bytes).toString('base64')}`;

const FRAME_STYLE = `
* { box-sizing: border-box; }
html, body { margin: 0; width: 1280px; height: 800px; overflow: hidden; }
body {
  position: relative;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
  color: #f2f4f8;
  -webkit-font-smoothing: antialiased;
  background:
    radial-gradient(760px 420px at 88% -4%, rgb(219 39 119 / 0.34), transparent 64%),
    radial-gradient(640px 420px at -4% 104%, rgb(124 58 237 / 0.2), transparent 62%),
    #0a0d14;
}
.caption { position: absolute; left: ${WINDOW.x}px; top: 54px; width: 820px; }
.caption h1 { margin: 0; font-size: 36px; line-height: 44px; font-weight: 650; letter-spacing: -0.02em; }
.caption p { margin: 10px 0 0; font-size: 18px; line-height: 26px; color: #a7b0c0; }
.badge { position: absolute; right: ${1280 - WINDOW.x - WINDOW.width}px; top: 60px; display: flex; align-items: center; gap: 10px; font-size: 15px; font-weight: 600; color: #c9cfda; }
.badge img { width: 30px; height: 30px; }
.window {
  position: absolute; overflow: hidden;
  border-radius: 12px 12px 0 0;
  background: #fff;
  box-shadow: 0 0 0 1px rgb(255 255 255 / 0.12), 0 40px 100px -20px rgb(0 0 0 / 0.85);
}
.tabs { display: flex; align-items: flex-end; height: 38px; padding: 0 12px; background: #1b1e26; }
.lights { display: flex; gap: 8px; align-self: center; margin-right: 16px; }
.lights i { width: 12px; height: 12px; border-radius: 50%; background: #3a3f4b; }
.tab { display: flex; align-items: center; gap: 8px; height: 30px; padding: 0 14px; min-width: 210px; border-radius: 9px 9px 0 0; background: #2a2e38; font-size: 12.5px; color: #e4e7ee; }
.tab img, .tab .fav { width: 16px; height: 16px; flex: none; }
.fav { border-radius: 4px; background: #64748b; }
.toolbar { display: flex; align-items: center; gap: 10px; height: 40px; padding: 0 12px; background: #2a2e38; border-bottom: 1px solid #14161c; }
.nav { display: flex; gap: 14px; color: #8d94a3; font-size: 15px; }
.address { flex: 1; display: flex; align-items: center; gap: 8px; height: 28px; padding: 0 14px; border-radius: 14px; background: #1b1e26; color: #d6dae2; font-size: 13px; }
.address img { width: 14px; height: 14px; }
.address svg { width: 12px; height: 12px; color: #8d94a3; }
.address .path { color: #8d94a3; }
.ext { display: grid; place-items: center; width: 30px; height: 30px; border-radius: 8px; }
.ext img { width: 18px; height: 18px; }
.ext.open { background: rgb(244 114 182 / 0.22); }
.page { display: block; }
.popup {
  position: absolute; width: ${320 * ZOOM}px; overflow: hidden; border-radius: 12px;
  box-shadow: 0 0 0 1px rgb(255 255 255 / 0.14), 0 28px 60px -12px rgb(0 0 0 / 0.75);
}
.popup img { display: block; width: ${320 * ZOOM}px; }
.appwin {
  position: absolute; overflow: hidden; border-radius: 12px; background: #0a0d14;
  box-shadow: 0 0 0 1px rgb(255 255 255 / 0.14), 0 40px 90px -16px rgb(0 0 0 / 0.9);
}
.appwin .bar { display: flex; align-items: center; gap: 8px; height: 34px; padding: 0 12px; background: #141822; border-bottom: 1px solid rgb(255 255 255 / 0.06); font-size: 12.5px; color: #a7b0c0; }
.appwin .bar .lights { margin-right: 6px; }
.appwin img.shot { display: block; }
`;

const LOCK =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>';

function browserWindow({ box, tab, address, page, icon, extOpen = false }) {
  const favicon = tab.icon ? `<img src="${tab.icon}" alt="">` : '<span class="fav"></span>';
  const where = address.icon
    ? `<img src="${address.icon}" alt="">${address.text}`
    : `${LOCK}${address.host}<span class="path">${address.path ?? ''}</span>`;
  return `<div class="window" style="left:${box.x}px;top:${box.y}px;width:${box.width}px;height:${box.height}px">
  <div class="tabs"><div class="lights"><i></i><i></i><i></i></div><div class="tab">${favicon}${tab.title}</div></div>
  <div class="toolbar"><div class="nav"><span>←</span><span>→</span><span>↻</span></div>
    <div class="address">${where}</div>
    <div class="ext${extOpen ? ' open' : ''}"><img src="${icon}" alt=""></div></div>
  <img class="page" src="${page}" style="width:${box.width}px" alt="">
</div>`;
}

function frame({ caption, icon, body }) {
  const [title, text] = caption;
  return `<!doctype html><meta charset="utf-8"><style>${FRAME_STYLE}</style>
<div class="caption"><h1>${title}</h1><p>${text}</p></div>
<div class="badge"><img src="${icon}" alt="">SSH Key Manager</div>
${body}`;
}

async function render(browser, html, size, file, options = {}) {
  const page = await browser.newPage();
  await page.setViewport({ ...size, deviceScaleFactor: 1 });
  await page.setContent(html, { waitUntil: 'load' });
  await page.screenshot({ path: file, omitBackground: options.transparent ?? false });
  await page.close();
  console.log(file.slice(root.length + 1));
}

// One listing language: pair, fill, save, and the popup, each framed.

async function captureLanguage(lang, assets) {
  const t = TEXT[lang];
  const dir = join(out, lang);
  await mkdir(dir, { recursive: true });

  const work = await mkdtemp(join(tmpdir(), 'sshkm-store-'));
  const key = join(work, 'key.pem');
  const cert = join(work, 'cert.pem');
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-subj',
      `/CN=${DOMAIN}`,
      '-keyout',
      key,
      '-out',
      cert,
    ],
    { stdio: 'ignore' },
  );
  const server = createServer(
    { key: await readFile(key), cert: await readFile(cert) },
    (request, response) => {
      if (request.method === 'POST') {
        request.resume();
        response.writeHead(303, { location: '/home' }).end();
        return;
      }
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end(request.url?.startsWith('/home') ? homePage(t.site) : signInPage(t.site));
    },
  );
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '0.0.0.0', resolve);
  });

  const bridge = spawn(
    join(root, `target/debug/examples/autofill_bridge${exe}`),
    [
      '--entry',
      'Example Console',
      site,
      'alex@example.com',
      'correct-horse-7',
      '--entry',
      'Example Console (admin)',
      site,
      'admin@example.com',
      'battery-staple-9',
      '--approve-after',
      '4000',
    ],
    { stdio: ['pipe', 'pipe', 'inherit'] },
  );
  const events = [];
  createInterface({ input: bridge.stdout }).on('line', (line) => events.push(JSON.parse(line)));
  const waitFor = async (name, what = undefined) => {
    for (let i = 0; i < 300; i++) {
      if (events.some((e) => e.event === name && (what === undefined || e.what === what))) return;
      await sleep(50);
    }
    throw new Error(`no ${name} from the bridge`);
  };
  await waitFor('ready');

  await mkdir(join(work, 'NativeMessagingHosts'));
  const host = join(work, `sshkm-app${exe}`);
  await copyFile(join(root, `target/debug/sshkm-app${exe}`), host);
  await writeFile(
    join(work, 'NativeMessagingHosts', `${HOST}.json`),
    JSON.stringify({
      name: HOST,
      description: 'SSH Key Manager (store images)',
      path: host,
      type: 'stdio',
      allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
    }),
  );

  const browser = await puppeteer.launch({
    executablePath: chrome,
    headless: true,
    pipe: true,
    userDataDir: work,
    enableExtensions: [join(root, 'extension/dist/chromium')],
    args: [
      `--lang=${lang}`,
      `--accept-lang=${lang}`,
      `--host-resolver-rules=MAP ${DOMAIN} 127.0.0.1`,
      '--ignore-certificate-errors',
      '--hide-scrollbars',
    ],
    defaultViewport: viewportFor(WINDOW),
  });

  const caption = (name) => t.shots[name];
  const shot = (page) => page.screenshot({ type: 'png' });
  const browserIcon = assets.icon32;

  try {
    // Pairing: the code on the connect page, and the same code in the app.
    const connectBox = { x: 96, y: WINDOW.y, width: 700, height: WINDOW.height };
    const connect = await browser.newPage();
    await connect.setViewport(viewportFor(connectBox));
    await connect.goto(`chrome-extension://${EXTENSION_ID}/connect.html`);
    await connect.waitForSelector('button.primary');
    await connect.click('button.primary');
    await connect.waitForSelector('.code');
    await sleep(300);
    const connectShot = await shot(connect);
    const { code } = events.find((e) => e.event === 'pairing');
    await connect.waitForSelector('h1.success', { timeout: 15_000 });
    await connect.close();

    const dialog = await browser.newPage();
    await dialog.setViewport({ width: 1100, height: 760, deviceScaleFactor: 2 });
    await dialog.goto(`${app}/?open=pairing&code=${code}`, { waitUntil: 'networkidle0' });
    await dialog.waitForSelector('[role=dialog]');
    // Only the dialog, over the app's dimmed canvas: hide the page behind it.
    await dialog.evaluate(() => {
      document.getElementById('root').style.visibility = 'hidden';
    });
    await sleep(900);
    const rect = await dialog.$eval('[role=dialog]', (el) => {
      const r = el.getBoundingClientRect();
      return { x: r.x, y: r.y, width: r.width, height: r.height };
    });
    const margin = 26;
    const clip = {
      x: rect.x - margin,
      y: rect.y - margin,
      width: rect.width + 2 * margin,
      height: rect.height + 2 * margin,
    };
    const dialogShot = await dialog.screenshot({ type: 'png', clip });
    await dialog.close();
    const appWidth = 470;
    const appHeight = Math.round((clip.height * appWidth) / clip.width) + 34;
    await render(
      browser,
      frame({
        caption: caption('connect'),
        icon: assets.icon128,
        body: `${browserWindow({
          box: connectBox,
          tab: { title: 'SSH Key Manager', icon: assets.icon16 },
          address: { icon: assets.icon16, text: 'SSH Key Manager' },
          page: png(connectShot),
          icon: browserIcon,
        })}
<div class="appwin" style="left:${1280 - 96 - appWidth}px;top:${WINDOW.y + 70}px;width:${appWidth}px;height:${appHeight}px">
  <div class="bar"><div class="lights"><i></i><i></i><i></i></div>SSH Key Manager</div>
  <img class="shot" src="${png(dialogShot)}" style="width:${appWidth}px" alt="">
</div>`,
      }),
      { width: 1280, height: 800 },
      join(dir, '3-connect.png'),
    );

    // The menu under the field, with the first login highlighted.
    const page = await browser.newPage();
    await page.goto(`${site}/`);
    await page.click('#email');
    await page.waitForSelector(SURFACE, { timeout: 10_000 });
    await page.keyboard.press('ArrowDown');
    await sleep(400);
    const below = await page.evaluate(() => {
      const menu = document.querySelector('html > div:popover-open').getBoundingClientRect();
      return menu.top >= document.querySelector('#email').getBoundingClientRect().bottom;
    });
    if (!below) throw new Error('the menu opened above the field: make the sign-in page shorter');
    const fillShot = await shot(page);
    const menuRect = await page.$eval(SURFACE, (el) => {
      const r = el.getBoundingClientRect();
      return { x: r.x, y: r.y, width: r.width, height: r.height };
    });
    assets.menu ??= await page.screenshot({ type: 'png', clip: menuRect });
    await render(
      browser,
      frame({
        caption: caption('fill'),
        icon: assets.icon128,
        body: browserWindow({
          box: WINDOW,
          tab: { title: t.site.title },
          address: { host: DOMAIN },
          page: png(fillShot),
          icon: browserIcon,
        }),
      }),
      { width: 1280, height: 800 },
      join(dir, '1-fill.png'),
    );

    // A new login: the banner on the next page.
    await page.keyboard.press('Escape');
    await page.click('#email');
    await page.keyboard.type('sam@example.com');
    await page.click('#password');
    await page.keyboard.type('new-login-42');
    await Promise.all([page.waitForNavigation(), page.click('#submit')]);
    await page.waitForSelector(SURFACE, { timeout: 10_000 });
    await page.mouse.move(10, 10);
    await sleep(SETTLE);
    const saveShot = await shot(page);
    await render(
      browser,
      frame({
        caption: caption('save'),
        icon: assets.icon128,
        body: browserWindow({
          box: WINDOW,
          tab: { title: t.site.home },
          address: { host: DOMAIN, path: '/home' },
          page: png(saveShot),
          icon: browserIcon,
        }),
      }),
      { width: 1280, height: 800 },
      join(dir, '2-save.png'),
    );

    // Saved, as a user would; then the popup over the signed-in page.
    const banner = await page.$eval(SURFACE, (el) => {
      const r = el.getBoundingClientRect();
      return { right: r.right, bottom: r.bottom };
    });
    await page.mouse.click(banner.right - 14 - 22, banner.bottom - 12 - 15);
    await waitFor('changed', 'entries');
    await page.goto(`${site}/home`);
    await sleep(300);
    const homeShot = await shot(page);
    const popup = await browser.newPage();
    await popup.setViewport({ width: 320, height: 600, deviceScaleFactor: 2 * ZOOM });
    await popup.goto(`chrome-extension://${EXTENSION_ID}/popup.html`);
    await popup.waitForFunction(
      () => !document.querySelector('.spinner') && document.querySelector('.dot.ok'),
      { timeout: 15_000 },
    );
    const height = await popup.evaluate(() => document.querySelector('.popup').offsetHeight);
    const popupShot = await popup.screenshot({
      type: 'png',
      clip: { x: 0, y: 0, width: 320, height },
    });
    await popup.close();
    await render(
      browser,
      frame({
        caption: caption('popup'),
        icon: assets.icon128,
        body: `${browserWindow({
          box: WINDOW,
          tab: { title: t.site.home },
          address: { host: DOMAIN, path: '/home' },
          page: png(homeShot),
          icon: browserIcon,
          extOpen: true,
        })}
<div class="popup" style="left:${WINDOW.x + WINDOW.width - 320 * ZOOM - 8}px;top:${WINDOW.y + CHROME_BAR - 2}px"><img src="${png(popupShot)}" alt=""></div>`,
      }),
      { width: 1280, height: 800 },
      join(dir, '4-popup.png'),
    );
  } finally {
    await browser.close();
    bridge.stdin.end('quit\n');
    await new Promise((resolve) => bridge.once('exit', resolve));
    server.close();
    await rm(work, { recursive: true, force: true });
  }
}

// The store icon and the promo tile.

async function makeIcon(browser) {
  const source = await readFile(join(root, 'src-tauri/icons/icon.png'));
  const page = await browser.newPage();
  const data = await page.evaluate(async (src) => {
    const image = new Image();
    image.src = src;
    await image.decode();
    // The art without the transparent margin around it.
    const probe = new OffscreenCanvas(image.width, image.height).getContext('2d');
    probe.drawImage(image, 0, 0);
    const alpha = probe.getImageData(0, 0, image.width, image.height).data;
    let [x0, y0, x1, y1] = [image.width, image.height, 0, 0];
    for (let y = 0; y < image.height; y++) {
      for (let x = 0; x < image.width; x++) {
        if (alpha[(y * image.width + x) * 4 + 3] > 8) {
          x0 = Math.min(x0, x);
          y0 = Math.min(y0, y);
          x1 = Math.max(x1, x + 1);
          y1 = Math.max(y1, y + 1);
        }
      }
    }
    const side = Math.max(x1 - x0, y1 - y0);
    const canvas = new OffscreenCanvas(128, 128);
    const context = canvas.getContext('2d');
    context.imageSmoothingQuality = 'high';
    context.drawImage(image, x0, y0, side, side, 16, 16, 96, 96);
    const blob = await canvas.convertToBlob({ type: 'image/png' });
    return Array.from(new Uint8Array(await blob.arrayBuffer()));
  }, png(source));
  await page.close();
  return Buffer.from(data);
}

async function makePromo(browser, assets) {
  const html = `<!doctype html><meta charset="utf-8"><style>
* { box-sizing: border-box; }
html, body { margin: 0; width: 440px; height: 280px; overflow: hidden; }
body {
  display: flex; align-items: center; gap: 22px; padding: 0 26px;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
  color: #f2f4f8; -webkit-font-smoothing: antialiased;
  background:
    radial-gradient(360px 240px at 100% 0%, rgb(219 39 119 / 0.42), transparent 70%),
    radial-gradient(300px 220px at 0% 100%, rgb(124 58 237 / 0.26), transparent 70%),
    #0a0d14;
}
.brand { display: flex; flex-direction: column; gap: 14px; width: 164px; flex: none; }
.brand img { width: 84px; height: 84px; margin-left: -6px; }
.brand b { font-size: 18px; line-height: 22px; font-weight: 650; letter-spacing: -0.02em; white-space: nowrap; }
.menu { width: 214px; border-radius: 12px; box-shadow: 0 0 0 1px rgb(255 255 255 / 0.12), 0 24px 48px -12px rgb(0 0 0 / 0.8); }
</style>
<div class="brand"><img src="${assets.icon128}" alt=""><b>SSH Key Manager</b></div>
<img class="menu" src="${png(assets.menu)}" alt="">`;
  await render(browser, html, { width: 440, height: 280 }, join(out, 'promo-small-440x280.png'));
}

await mkdir(out, { recursive: true });
const tools = await puppeteer.launch({ executablePath: chrome, headless: true, pipe: true });
try {
  const icon = await makeIcon(tools);
  await writeFile(join(out, 'icon-128.png'), icon);
  await writeFile(join(root, 'extension/icons/icon-128.png'), icon);
  console.log('extension/store/images/icon-128.png, extension/icons/icon-128.png');

  const assets = {
    icon128: png(icon),
    icon32: png(await readFile(join(root, 'extension/icons/icon-32.png'))),
    icon16: png(await readFile(join(root, 'extension/icons/icon-16.png'))),
    menu: null,
  };
  for (const lang of Object.keys(TEXT)) await captureLanguage(lang, assets);
  await makePromo(tools, assets);
} finally {
  await tools.close();
}
