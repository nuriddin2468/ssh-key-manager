import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { TextField } from '@/components/ui/TextField';
import { type FirstPart, labelProblem } from './model';

/**
 * Naming the part a project's environments share when it gets a second
 * one: filled in with the name it has (from before projects, the old
 * group's), which the user may keep or change.
 */
export function useFirstPart() {
  const [naming, setNaming] = useState<FirstPart | null>(null);
  const [name, setName] = useState('');
  return {
    naming,
    name,
    setName,
    /** Asks for the name of `first`'s part. */
    ask: (first: FirstPart) => {
      setNaming(first);
      setName(first.part);
    },
    back: () => setNaming(null),
    /** Why the name can't be taken, next to the new part `part`; none when it can. */
    problem: (part: string): 'empty' | 'slash' | 'long' | 'same' | null =>
      labelProblem(name) ??
      (name.trim().toLowerCase() === part.trim().toLowerCase() ? 'same' : null),
  };
}

export function FirstPartField({
  value,
  onChange,
  part,
  problem,
  touched,
}: {
  value: string;
  onChange: (value: string) => void;
  /** The new part, which this one can't be called. */
  part: string;
  problem: 'empty' | 'slash' | 'long' | 'same' | null;
  touched: boolean;
}) {
  const { t } = useTranslation();
  const error = !touched
    ? undefined
    : problem === 'same'
      ? t('envs.firstPart.same', { part: part.trim() })
      : problem
        ? t(`envs.form.${problem}`)
        : undefined;
  return (
    <>
      <TextField
        label={t('envs.firstPart.label')}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        hint={t('envs.firstPart.hint')}
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
