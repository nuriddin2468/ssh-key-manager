import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RouterProvider } from '@/app/router';
import type { ChatEntry } from '@/bindings/ChatEntry';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { Bubble } from './Bubble';
import { Composer } from './Composer';
import { byDay } from './model';

const api = vi.hoisted(() => ({
  chatSendText: vi.fn(),
  chatReveal: vi.fn(),
  chatCopy: vi.fn(),
  chatRevoke: vi.fn(),
  chatRetry: vi.fn(),
  chatAnswer: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <RouterProvider>
        <TooltipProvider>{children}</TooltipProvider>
      </RouterProvider>
    </QueryClientProvider>,
  );
}

const bob = { key: 'Ym9i', name: 'ThinkPad Bob', online: true };

const secret: ChatEntry = {
  id: 'a'.repeat(32),
  mine: false,
  at: '2026-11-13T09:00:00Z',
  delivery: { state: 'received' },
  body: {
    kind: 'secret',
    label: 'staging DB',
    expires: new Date(Date.now() + 3_000_000).toISOString(),
    gone: null,
  },
};

beforeEach(() => {
  for (const fn of Object.values(api)) fn.mockReset();
});

describe('Composer', () => {
  it('sends on Enter, breaks the line on Shift+Enter', async () => {
    api.chatSendText.mockResolvedValue(undefined);
    wrap(<Composer peer={bob} onOpen={() => undefined} />);
    const field = screen.getByRole('textbox', { name: 'Message ThinkPad Bob' });
    await userEvent.type(field, 'line one{Shift>}{Enter}{/Shift}line two');
    expect(api.chatSendText).not.toHaveBeenCalled();
    await userEvent.keyboard('{Enter}');
    await waitFor(() =>
      expect(api.chatSendText).toHaveBeenCalledWith('Ym9i', 'line one\nline two'),
    );
    await waitFor(() => expect(field).toHaveValue(''));
  });

  it('is off while the other computer is offline, and says why', () => {
    wrap(<Composer peer={{ ...bob, online: false }} onOpen={() => undefined} />);
    expect(screen.getByRole('textbox')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Send something else' })).toBeDisabled();
    expect(
      screen.getByText(
        'ThinkPad Bob is offline. Messages go only while Nearby is open on both computers.',
      ),
    ).toBeInTheDocument();
  });
});

describe('a secret', () => {
  it('stays hidden until asked, then hides itself again', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    api.chatReveal.mockResolvedValue('hunter2');
    wrap(<Bubble peer={bob} entry={secret} onAddVariables={() => undefined} />);
    expect(screen.queryByText('hunter2')).toBeNull();
    expect(screen.getByText('hidden')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));
    expect(await screen.findByText('hunter2')).toBeInTheDocument();
    expect(api.chatReveal).toHaveBeenCalledWith('Ym9i', secret.id, null);
    await act(async () => {
      vi.advanceTimersByTime(31_000);
    });
    expect(screen.queryByText('hunter2')).toBeNull();
    vi.useRealTimers();
  });

  it('is copied by the backend, never through the page', async () => {
    api.chatCopy.mockResolvedValue({ clearsInSecs: 30 });
    wrap(<Bubble peer={bob} entry={secret} onAddVariables={() => undefined} />);
    await userEvent.click(screen.getByRole('button', { name: 'Copy' }));
    await waitFor(() => expect(api.chatCopy).toHaveBeenCalledWith('Ym9i', secret.id, null));
    expect(api.chatReveal).not.toHaveBeenCalled();
  });

  it('says once its value is gone, with no way to show it', () => {
    const gone: ChatEntry = {
      ...secret,
      body: { kind: 'secret', label: 'staging DB', expires: null, gone: 'expired' },
    };
    wrap(<Bubble peer={bob} entry={gone} onAddVariables={() => undefined} />);
    expect(screen.getByText('Secret · expired')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Show' })).toBeNull();
  });
});

describe('a card offered', () => {
  it('is accepted or declined only while the other computer is online', async () => {
    api.chatAnswer.mockResolvedValue(undefined);
    const card: ChatEntry = {
      ...secret,
      body: {
        kind: 'card',
        item: {
          type: 'host',
          alias: 'prod',
          address: 'deploy@10.0.4.12',
          proxyJump: null,
          hostKeys: 1,
        },
        outcome: 'waiting',
        name: null,
        keysDiffer: false,
        group: null,
      },
    };
    const { unmount } = wrap(<Bubble peer={bob} entry={card} onAddVariables={() => undefined} />);
    await userEvent.click(screen.getByRole('button', { name: 'Accept' }));
    await waitFor(() => expect(api.chatAnswer).toHaveBeenCalledWith('Ym9i', secret.id, true));
    unmount();
    wrap(<Bubble peer={{ ...bob, online: false }} entry={card} onAddVariables={() => undefined} />);
    expect(screen.queryByRole('button', { name: 'Accept' })).toBeNull();
  });
});

describe('a message that did not arrive', () => {
  it('can be sent again while the other computer is online', async () => {
    api.chatRetry.mockResolvedValue(undefined);
    const lost: ChatEntry = {
      ...secret,
      mine: true,
      delivery: { state: 'notDelivered' },
      body: { kind: 'text', text: 'hello' },
    };
    wrap(<Bubble peer={bob} entry={lost} onAddVariables={() => undefined} />);
    expect(screen.getByText('Not delivered')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Send again' }));
    await waitFor(() => expect(api.chatRetry).toHaveBeenCalledWith('Ym9i', secret.id));
  });
});

describe('byDay', () => {
  it('groups entries by the local day they came, in order', () => {
    const at = (day: number, hour: number): ChatEntry => {
      const iso = new Date(2026, 10, day, hour, 30).toISOString();
      return { ...secret, id: iso, at: iso };
    };
    // Late on the 12th here may already be the 13th in UTC, or the other way round.
    const days = byDay([at(12, 23), at(13, 0), at(13, 2)]);
    expect(days.map((day) => [day.day, day.entries.length])).toEqual([
      ['2026-11-12', 1],
      ['2026-11-13', 2],
    ]);
  });
});

describe('adding received variables', () => {
  it('ticks only new names that start nothing, and saves nothing until Add', async () => {
    const review = vi.fn().mockResolvedValue([
      { name: 'API_KEY', secret: true, change: 'new', risky: false },
      { name: 'LOG_LEVEL', secret: false, change: 'replaces', risky: false },
      { name: 'NODE_OPTIONS', secret: false, change: 'new', risky: true },
      { name: 'PORT', secret: false, change: 'same', risky: false },
    ]);
    const addVariables = vi.fn().mockResolvedValue('env-1');
    Object.assign(api, {
      chatReviewVariables: review,
      chatAddVariables: addVariables,
      envsList: vi.fn().mockResolvedValue([]),
    });
    const { stubPointer } = await import('@/features/envs/testing');
    stubPointer();
    const { AddVariablesDialog } = await import('./AddVariablesDialog');
    const { Dialog } = await import('@/components/ui/Dialog');
    wrap(
      <Dialog open>
        <AddVariablesDialog peer={bob} id={secret.id} onDone={() => undefined} />
      </Dialog>,
    );
    const box = async (name: string) =>
      screen.findByRole('checkbox', { name: new RegExp(`^${name}`) });
    expect(await box('API_KEY')).toBeChecked();
    expect(await box('LOG_LEVEL')).not.toBeChecked();
    expect(await box('NODE_OPTIONS')).not.toBeChecked();
    expect(await box('PORT')).not.toBeChecked();
    expect(addVariables).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Add 1 variable' }));
    await waitFor(() =>
      expect(addVariables).toHaveBeenCalledWith(
        'Ym9i',
        secret.id,
        { type: 'new', name: 'ThinkPad Bob' },
        ['API_KEY'],
      ),
    );
  });
});

describe('wiping a secret this user sent', () => {
  it('reaches both computers only while the other is online, and says so', async () => {
    api.chatRevoke.mockResolvedValue(undefined);
    const mine: ChatEntry = { ...secret, mine: true, delivery: { state: 'delivered' } };
    const { unmount } = wrap(<Bubble peer={bob} entry={mine} onAddVariables={() => undefined} />);
    await userEvent.click(screen.getByRole('button', { name: 'Wipe now' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Wipe now' }));
    await waitFor(() => expect(api.chatRevoke).toHaveBeenCalledWith('Ym9i', secret.id, true));
    unmount();
    wrap(<Bubble peer={{ ...bob, online: false }} entry={mine} onAddVariables={() => undefined} />);
    await userEvent.click(screen.getByRole('button', { name: 'Wipe here only' }));
    expect(await screen.findByText('Wipe it on this computer?')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Wipe here' }));
    await waitFor(() => expect(api.chatRevoke).toHaveBeenLastCalledWith('Ym9i', secret.id, false));
  });
});

describe('a chat kept of a removed computer', () => {
  const variables: ChatEntry = {
    ...secret,
    body: {
      kind: 'variables',
      label: 'shop · staging',
      expires: new Date(Date.now() + 3_000_000).toISOString(),
      gone: null,
      variables: [{ name: 'API_KEY', secret: true, value: null, risky: false }],
    },
  };
  const gone = { ...bob, online: false, removed: true };

  it('offers no adding of its variables, which could not be', () => {
    wrap(<Bubble peer={gone} entry={variables} onAddVariables={() => undefined} />);
    expect(screen.queryByRole('button', { name: /environment/ })).not.toBeInTheDocument();
  });

  it('still wipes what this user sent, here', async () => {
    api.chatRevoke.mockResolvedValue(undefined);
    const mine: ChatEntry = { ...variables, mine: true, delivery: { state: 'delivered' } };
    wrap(<Bubble peer={gone} entry={mine} onAddVariables={() => undefined} />);
    await userEvent.click(screen.getByRole('button', { name: 'Wipe here only' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Wipe here' }));
    await waitFor(() => expect(api.chatRevoke).toHaveBeenCalledWith('Ym9i', secret.id, false));
  });
});
