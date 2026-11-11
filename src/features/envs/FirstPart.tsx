import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { PartRename } from '@/bindings/PartRename';
import { TextField } from '@/components/ui/TextField';
import { type FirstPart, labelProblem } from './model';

type Problem = 'empty' | 'slash' | 'long' | 'same';

/**
 * Naming the part a project's environments share when it gets a second
 * one: filled in with the name it has, which the user may keep or change.
 * A dialog asks with [`ask`] when [`secondPart`] says so, shows
 * [`FirstPartField`] instead of its form until [`back`], and sends
 * [`rename`] with its save, so both happen in one change.
 */
export function useFirstPart(initial: FirstPart | null = null) {
  const [naming, setNaming] = useState<FirstPart | null>(initial);
  const [name, setName] = useState(initial?.part ?? '');
  const [touched, setTouched] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  // Where the focus was when the step came, to go back to.
  const from = useRef<HTMLElement | null>(null);
  const same = naming?.coming.find((part) => part.toLowerCase() === name.trim().toLowerCase());
  const problem: Problem | null = !naming
    ? null
    : (labelProblem(name) ?? (same !== undefined ? 'same' : null));
  const rename: PartRename | null =
    naming && name.trim() !== naming.part ? { ids: naming.ids, part: name.trim() } : null;
  return {
    naming,
    name,
    setName: (value: string) => {
      setName(value);
      setRefusal(null);
    },
    touched,
    problem,
    /** The new part it equals, for the error. */
    same: same ?? '',
    refusal,
    /** Asks for the name of `first`'s part. */
    ask: (first: FirstPart) => {
      from.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      setNaming(first);
      setName(first.part);
      setTouched(false);
      setRefusal(null);
    },
    back: () => {
      setNaming(null);
      setRefusal(null);
      // The form's fields come back as new elements: the focus goes where
      // it was if that is still there (the submit button), else to the
      // dialog's first field.
      const element = from.current;
      const dialog = element?.closest('[role=dialog]') ?? document.querySelector('[role=dialog]');
      setTimeout(() => {
        if (element?.isConnected) element.focus();
        else dialog?.querySelector<HTMLElement>('input:not([type=hidden]), textarea')?.focus();
      }, 0);
    },
    /** Whether the step can go on; shows why not otherwise. */
    confirm: () => {
      setTouched(true);
      return problem === null;
    },
    /** What to send with the save; nothing when the name is kept. */
    rename,
    /** Says why the save failed, in the step, while it shows. */
    refuse: (message: string) => setRefusal(message),
  };
}

export type FirstPartState = ReturnType<typeof useFirstPart>;

/** The step's field: the name of the part the project's environments share. */
export function FirstPartField({ state }: { state: FirstPartState }) {
  const { t } = useTranslation();
  const { naming, problem, touched, refusal } = state;
  const error = !touched
    ? (refusal ?? undefined)
    : problem === 'same'
      ? t('envs.firstPart.same', { part: state.same })
      : problem
        ? t(`envs.form.${problem}`)
        : (refusal ?? undefined);
  return (
    <>
      <TextField
        label={t('envs.firstPart.label')}
        value={state.name}
        onChange={(event) => state.setName(event.target.value)}
        hint={naming?.fromFolder ? t('envs.firstPart.hint') : undefined}
        error={error}
        autoFocus
      />
      {/* Said when it appears: the focus is on the button pressed. */}
      <p role="alert" className="sr-only">
        {error}
      </p>
    </>
  );
}
