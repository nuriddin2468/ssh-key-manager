import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { type FormEvent, useState } from 'react';
import { Toaster, toast } from 'sonner';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { useAppMutation, useShowError } from '@/api/useAppMutation';
import { stubPointer } from '@/features/envs/testing';
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogHeader, fromToast } from './Dialog';
import { TextField } from './TextField';
import { TooltipProvider } from './Tooltip';

/** A dialog's form: Notes first, then Name, which must be filled in. */
function SaveForm({ run }: { run: () => Promise<unknown> }) {
  const save = useAppMutation(run);
  const [notes, setNotes] = useState('');
  const [name, setName] = useState('');
  const [touched, setTouched] = useState(false);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (name) save.mutate(undefined);
  };
  return (
    <DialogContent section="envs">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader title="Save it" />
        <DialogBody>
          <TextField label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
          <TextField
            label="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            error={touched && !name ? 'Name it' : undefined}
          />
        </DialogBody>
        <DialogFooter>
          <button type="submit">Save</button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

function show(run: () => Promise<unknown>) {
  const onOpenChange = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient()}>
      <TooltipProvider>
        <Toaster />
        <Dialog open onOpenChange={onOpenChange}>
          <SaveForm run={run} />
        </Dialog>
      </TooltipProvider>
    </QueryClientProvider>,
  );
  return onOpenChange;
}

beforeAll(() => {
  stubPointer();
  // Sonner holds the pointer on a toast, to swipe it away.
  const proto = window.HTMLElement.prototype as unknown as Record<string, unknown>;
  proto.setPointerCapture ??= () => undefined;
});
afterEach(() => {
  vi.restoreAllMocks();
  toast.dismiss();
});

/** Says a failure, outside any dialog's footer. */
function Probe() {
  const showError = useShowError();
  return (
    <button type="button" onClick={() => showError({ code: 'io', message: 'gone' })}>
      Fail
    </button>
  );
}

describe('a dialog and toasts', () => {
  // Radix doesn't see clicks outside in jsdom: the browser preview checks
  // the click itself; this, that a toast's events count as the toast's.
  it('takes an event from a toast as not outside the dialog', async () => {
    render(<Toaster />);
    act(() => void toast('Copied'));
    const inToast = new Event('pointerdown', { bubbles: true });
    (await screen.findByText('Copied')).dispatchEvent(inToast);
    expect(fromToast(inToast)).toBe(true);

    const elsewhere = new Event('pointerdown', { bubbles: true });
    document.body.dispatchEvent(elsewhere);
    expect(fromToast(elsewhere)).toBe(false);
  });
});

describe('a failed save in a dialog', () => {
  it('is said above the buttons, keeps the dialog open, and goes on the next try', async () => {
    const error = vi.spyOn(toast, 'error');
    const run = vi.fn().mockRejectedValueOnce({ code: 'io', message: 'disk full' });
    const onOpenChange = show(run);
    fireEvent.change(screen.getByRole('textbox', { name: 'Name' }), { target: { value: 'dev' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    const dialog = screen.getByRole('dialog');
    expect(await within(dialog).findByText('The file could not be read or written.')).toBeVisible();
    expect(within(dialog).getByText('disk full')).toBeInTheDocument();
    expect(error).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalled();

    run.mockResolvedValueOnce(undefined);
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await vi.waitFor(() => expect(run).toHaveBeenCalledTimes(2));
    expect(within(dialog).queryByText('disk full')).toBeNull();
  });

  it('brings a field the form refused into focus', async () => {
    const run = vi.fn();
    show(run);
    await vi.waitFor(() => expect(screen.getByRole('textbox', { name: 'Notes' })).toHaveFocus());
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    const name = screen.getByRole('textbox', { name: 'Name' });
    await vi.waitFor(() => expect(name).toHaveFocus());
    expect(name).toHaveAttribute('aria-invalid', 'true');
    expect(run).not.toHaveBeenCalled();
  });

  it('is a toast when no dialog is on screen to say it', async () => {
    const error = vi.spyOn(toast, 'error');
    render(
      <Dialog open={false}>
        <Probe />
      </Dialog>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Fail' }));
    expect(error).toHaveBeenCalledWith('The file could not be read or written.', {
      description: 'gone',
    });
  });
});
