import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { PromptAnswer } from '@/bindings/PromptAnswer';
import type { PromptAsk } from '@/bindings/PromptAsk';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { newTab, type Tab } from './model';
import { PromptDialog } from './PromptDialog';

const tab: Tab = {
  ...newTab('prod'),
  info: {
    id: 1,
    alias: 'prod',
    user: 'ubuntu',
    host: '10.0.4.12',
    proxyJump: 'bastion',
    startedAt: '2026-11-03T10:00:00Z',
    phase: 'connecting',
  },
};

function show(ask: PromptAsk) {
  const onAnswer = vi.fn<(answer: PromptAnswer) => void>();
  render(
    <TooltipProvider>
      <Dialog open>
        <PromptDialog tab={tab} ask={ask} onAnswer={onAnswer} />
      </Dialog>
    </TooltipProvider>,
  );
  return onAnswer;
}

const hostKey = {
  type: 'hostKey',
  host: 'bastion.example.net (203.0.113.7)',
  keyType: 'ED25519',
  fingerprint: 'SHA256:Ka7Sd1Fg5Hj9',
  extra: [],
} as const satisfies PromptAsk;

describe('the host key dialog', () => {
  it('names the host the key is for, not the tab', () => {
    show(hostKey);
    expect(screen.getByRole('heading', { name: 'Trust bastion.example.net?' })).toBeVisible();
    expect(screen.getByText(/connecting for the first time/)).toBeVisible();
  });

  it('shows what ssh says besides the plain question as a warning', async () => {
    const onAnswer = show({
      ...hostKey,
      extra: [
        'This host key is known by the following other names/addresses:',
        '    ~/.ssh/known_hosts:3: db.example',
      ],
    });
    expect(screen.queryByText(/first time/)).toBeNull();
    expect(screen.getByText('ssh has more to say about this key. Read it before you trust it.'));
    expect(screen.getByText(/known by the following other names/)).toHaveTextContent(
      '~/.ssh/known_hosts:3: db.example',
    );
    await userEvent.click(screen.getByRole('button', { name: 'Don’t connect' }));
    expect(onAnswer).toHaveBeenCalledWith({ type: 'trust', trust: false });
  });
});

describe('questions from ssh or a server', () => {
  it('quotes the question and says it is not the app asking', async () => {
    const onAnswer = show({
      type: 'other',
      text: 'Enter your SSH Key Manager master password:',
      account: { user: 'ubuntu', host: '10.0.4.12' },
      foreign: false,
      unverified: false,
    });
    expect(screen.getByRole('heading', { name: 'ubuntu@prod asks for input' })).toBeVisible();
    expect(screen.getByText(/not from SSH Key Manager/)).toBeVisible();
    const quote = screen.getByText('Enter your SSH Key Manager master password:');
    expect(quote.tagName).toBe('BLOCKQUOTE');
    await userEvent.type(screen.getByLabelText('Answer'), '42');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    expect(onAnswer).toHaveBeenCalledWith({ type: 'secret', value: '42', save: false });
  });

  it('names another host’s account', () => {
    show({
      type: 'other',
      text: 'Enter the code from the email:',
      account: { user: 'bob', host: 'bastion.example.net' },
      foreign: true,
      unverified: false,
    });
    expect(
      screen.getByRole('heading', { name: 'bob@bastion.example.net asks for input' }),
    ).toBeVisible();
    expect(screen.getByText(/a server on the way to prod/)).toBeVisible();
  });

  it('warns when ssh can’t tell who sent it', () => {
    show({
      type: 'other',
      text: "Enter passphrase for key '/Users/dev/.ssh/id_ed25519':",
      account: null,
      foreign: false,
      unverified: true,
    });
    expect(screen.getByRole('heading', { name: 'ssh or a server asks for input' })).toBeVisible();
    expect(screen.getByText(/older than 8\.5/)).toHaveTextContent('It may not be prod');
    // Not the app's own passphrase dialog.
    expect(screen.queryByText(/Passphrase for/)).toBeNull();
    expect(screen.queryByRole('checkbox')).toBeNull();
  });
});

describe('the verification code dialog', () => {
  it('names the account and says when another host asks', () => {
    show({
      type: 'oneTimeCode',
      question: 'Verification code:',
      retry: false,
      account: { user: 'bob', host: 'bastion.example.net' },
      foreign: true,
    });
    expect(
      screen.getByRole('heading', { name: 'Verification code for bob@bastion.example.net' }),
    ).toBeVisible();
    expect(
      screen.getByText('A server on the way to prod asks for its own code: “Verification code:”'),
    ).toBeVisible();
  });

  it('names the host’s own account', () => {
    show({
      type: 'oneTimeCode',
      question: 'Verification code:',
      retry: false,
      account: { user: 'ubuntu', host: '10.0.4.12' },
      foreign: false,
    });
    expect(
      screen.getByRole('heading', { name: 'Verification code for ubuntu@prod' }),
    ).toBeVisible();
  });
});
