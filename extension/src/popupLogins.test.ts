import { beforeEach, describe, expect, it, vi } from 'vitest';

const client = vi.hoisted(() => ({ request: vi.fn(), changeLogin: vi.fn() }));
vi.mock('./shared/client', () => client);
const ext = vi.hoisted(() => ({
  runtime: { sendMessage: vi.fn(async () => null) },
  tabs: { query: vi.fn() },
}));
vi.mock('./shared/ext', () => ({ ext }));

import { siteLogins, tabOrigin } from './popupLogins';

const LOGINS = [
  { id: 'e1', title: 'Bank', username: 'alice', exact: true },
  { id: 'e2', title: 'Bank (old)', username: '', exact: false },
];

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

async function shown(): Promise<HTMLElement> {
  const section = siteLogins('https://bank.example');
  document.body.replaceChildren(section);
  await settle();
  return section;
}

function inputs(root: ParentNode): [HTMLInputElement, HTMLInputElement] {
  const [first, second] = root.querySelectorAll('input');
  if (!first || !second) throw new Error('no form');
  return [first, second];
}

function buttonNamed(root: ParentNode, name: string): HTMLButtonElement {
  const found = [...root.querySelectorAll('button')].find(
    (b) => b.textContent === name || b.getAttribute('aria-label') === name,
  );
  if (!found) throw new Error(`no button ${name}`);
  return found;
}

beforeEach(() => {
  client.request.mockReset();
  client.request.mockResolvedValue({ ok: true, value: { logins: LOGINS } });
  client.changeLogin.mockReset();
  client.changeLogin.mockResolvedValue({ ok: true, value: undefined });
  ext.runtime.sendMessage.mockClear();
});

describe('the tab', () => {
  it('names the site by the tab the browser reports, for web pages only', async () => {
    ext.tabs.query.mockResolvedValue([{ id: 1, url: 'https://www.bank.example/login?next=/' }]);
    expect(await tabOrigin()).toBe('https://www.bank.example');
    ext.tabs.query.mockResolvedValue([{ id: 1, url: 'chrome://settings' }]);
    expect(await tabOrigin()).toBeNull();
    ext.tabs.query.mockResolvedValue([{ id: 1 }]);
    expect(await tabOrigin()).toBeNull();
  });
});

describe("the site's logins", () => {
  it('are listed with a way to edit each', async () => {
    const section = await shown();
    expect(client.request).toHaveBeenCalledWith({ logins: { origin: 'https://bank.example' } });
    expect(section.querySelector('h2')?.textContent).toBe('Logins for bank.example');
    expect(section.querySelectorAll('li.login')).toHaveLength(2);
    buttonNamed(section, 'Edit “Bank” (alice)');
  });

  it('send only what the user changed', async () => {
    const section = await shown();
    buttonNamed(section, 'Edit “Bank” (alice)').click();
    const [username, password] = inputs(section);
    expect(username.value).toBe('alice');
    expect(password.value).toBe('');
    password.value = 'n3w';
    section.querySelector('form')?.requestSubmit();
    await settle();
    expect(client.changeLogin).toHaveBeenCalledWith('https://bank.example', {
      edit: { entryId: 'e1', password: 'n3w' },
    });
    expect(ext.runtime.sendMessage).toHaveBeenCalledWith({
      kind: 'loginsChanged',
      origin: 'https://bank.example',
    });
    expect(section.querySelector('[role=status]')?.textContent).toContain('Saved');

    buttonNamed(section, 'Edit “Bank” (alice)').click();
    const [renamed] = inputs(section);
    renamed.value = ' alice2 ';
    section.querySelector('form')?.requestSubmit();
    await settle();
    expect(client.changeLogin).toHaveBeenLastCalledWith('https://bank.example', {
      edit: { entryId: 'e1', username: 'alice2' },
    });
  });

  it('say when the app is too old to change them', async () => {
    client.changeLogin.mockResolvedValue({ ok: false, problem: 'outdatedApp' });
    const section = await shown();
    buttonNamed(section, 'Edit “Bank” (alice)').click();
    const [, password] = inputs(section);
    password.value = 'n3w';
    section.querySelector('form')?.requestSubmit();
    await settle();
    expect(section.querySelector('[role=alert]')?.textContent).toBe(
      'Update SSH Key Manager to edit or remove logins from the browser.',
    );
    // The typed password doesn't stay in the field.
    expect(password.value).toBe('');
  });

  it('go to the recycle bin only once the user confirms', async () => {
    const section = await shown();
    buttonNamed(section, 'Edit “Bank (old)”').click();
    buttonNamed(section, 'Move to recycle bin').click();
    expect(client.changeLogin).not.toHaveBeenCalled();
    expect(section.querySelector('.confirm-text')?.textContent).toContain('restore');
    // The safe choice has focus.
    expect(document.activeElement?.textContent).toBe('Cancel');
    buttonNamed(section, 'Cancel').click();
    expect(client.changeLogin).not.toHaveBeenCalled();

    buttonNamed(section, 'Edit “Bank (old)”').click();
    buttonNamed(section, 'Move to recycle bin').click();
    const confirm = [...section.querySelectorAll('button')].find((b) =>
      b.classList.contains('solid'),
    );
    confirm?.click();
    await settle();
    expect(client.changeLogin).toHaveBeenCalledWith('https://bank.example', {
      remove: { entryId: 'e2' },
    });
    expect(section.querySelector('[role=status]')?.textContent).toContain('recycle bin');
  });
});
