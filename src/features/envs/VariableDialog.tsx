import { Eye, Pencil, Plus } from 'lucide-react';
import { type FormEvent, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvVarInfo } from '@/bindings/EnvVarInfo';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { toastVaultError, useSecretCall, useVaultMutation } from '@/features/passwords/vault';
import { envLabel, isVariableName, looksSecretName } from './model';

interface VariableDialogProps {
  env: EnvDetail;
  /** The variable to change; `null` adds one. */
  variable: EnvVarInfo | null;
  onDone: () => void;
}

/**
 * A new variable, or a change to one. An existing value stays unless the
 * user types a new one or loads the current one to edit it; it is never
 * fetched just to open the dialog.
 */
export function VariableDialog({ env, variable, onDone }: VariableDialogProps) {
  const { t } = useTranslation();
  const valueId = useId();
  const [name, setName] = useState(variable?.name ?? '');
  // `null`: keep the current value.
  const [value, setValue] = useState<string | null>(variable ? null : '');
  const [secret, setSecret] = useState(variable?.secret ?? false);
  const [secretTouched, setSecretTouched] = useState(variable !== null);
  const [note, setNote] = useState(variable?.note ?? '');
  const [touched, setTouched] = useState(false);
  const reveal = useSecretCall(api.envsReveal);
  const valueField = useRef<HTMLTextAreaElement>(null);

  const save = useVaultMutation(
    () =>
      api.envsSetVar(env.id, variable?.name ?? null, {
        name: name.trim(),
        value,
        secret,
        note: note.trim(),
      }),
    {
      success: () =>
        variable
          ? t('envs.varSaved', { name: name.trim() })
          : t('envs.varAdded', { name: name.trim() }),
      onSuccess: onDone,
      onError: (error) => {
        if (error.code !== 'already_exists') return false;
        setTouched(true);
        return true;
      },
    },
  );

  const trimmed = name.trim();
  const taken = env.variables.some((other) => other.name === trimmed && other !== variable);
  const nameError = !trimmed
    ? t('envs.varForm.nameEmpty')
    : !isVariableName(trimmed)
      ? t('envs.varForm.nameInvalid')
      : taken
        ? t('envs.varForm.nameTaken')
        : undefined;

  const loadCurrent = () => {
    if (!variable || reveal.pending) return;
    reveal
      .call(env.id, variable.name)
      .then((current) => {
        setValue(current);
        // The button is gone with the loaded value: go on in the field.
        requestAnimationFrame(() => valueField.current?.focus());
      })
      .catch((error: unknown) => toastVaultError(t, error));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (!nameError && !save.isPending) save.mutate(undefined);
  };

  return (
    <DialogContent section="envs" className="max-w-[560px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              {variable ? (
                <Pencil className="size-5" strokeWidth={2} />
              ) : (
                <Plus className="size-[22px]" strokeWidth={2.25} />
              )}
            </Tile>
          }
          title={variable ? t('envs.varForm.editTitle') : t('envs.varForm.newTitle')}
          description={envLabel(env)}
        />
        <DialogBody>
          <TextField
            label={t('envs.varForm.name')}
            value={name}
            mono
            placeholder="DATABASE_URL"
            onChange={(event) => {
              const next = event.target.value;
              setName(next);
              if (!secretTouched) setSecret(looksSecretName(next.trim()));
            }}
            error={touched ? nameError : undefined}
            hint={t('envs.varForm.nameHint')}
          />
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              <label htmlFor={valueId} className="text-[12px] font-semibold text-fg-2">
                {t('envs.varForm.value')}
              </label>
              {variable && value === null && !variable.empty ? (
                <Button
                  variant="ghost"
                  size="sm"
                  className="ml-auto h-6 px-2"
                  icon={<Eye className="size-3.5" strokeWidth={1.9} />}
                  loading={reveal.pending}
                  onClick={loadCurrent}
                >
                  {t('envs.varForm.loadCurrent')}
                </Button>
              ) : null}
            </div>
            <textarea
              ref={valueField}
              id={valueId}
              value={value ?? ''}
              onChange={(event) => setValue(event.target.value)}
              rows={value?.includes('\n') ? 5 : 2}
              spellCheck={false}
              autoComplete="off"
              aria-describedby={`${valueId}-hint`}
              placeholder={
                variable && value === null ? t('envs.varForm.keepPlaceholder') : undefined
              }
              className="field min-h-[60px] resize-y rounded-[10px] px-[11px] py-2 font-mono text-[12.5px] text-fg outline-none focus:border-[rgb(var(--accent-rgb)/0.55)] focus:shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.15)]"
            />
            <p id={`${valueId}-hint`} className="text-[12px] text-subtle">
              {variable && value === null
                ? t('envs.varForm.keepHint')
                : t('envs.varForm.valueHint')}
            </p>
          </div>
          <SwitchGroup>
            <SwitchRow
              label={t('envs.varForm.secret')}
              hint={t('envs.varForm.secretHint')}
              checked={secret}
              onCheckedChange={(checked) => {
                setSecret(checked);
                setSecretTouched(true);
              }}
            />
          </SwitchGroup>
          <TextField
            label={t('envs.varForm.note')}
            value={note}
            placeholder={t('envs.varForm.notePlaceholder')}
            onChange={(event) => setNote(event.target.value.replace(/[\r\n]+/g, ' '))}
          />
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" size="lg" loading={save.isPending}>
            {variable ? t('common.save') : t('envs.varForm.add')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
