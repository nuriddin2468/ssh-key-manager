import { Clock, Network } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { HostsEntryEdit } from '@/bindings/HostsEntryEdit';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { SwitchRow } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { expiryIn, isIpAddress, isSystemName, isValidName, splitNames } from './model';

interface EntryDialogProps {
  /** The entry to edit; `null` adds one. */
  initial: HostsEntryEdit | null;
  /** Groups to choose from. */
  groups: string[];
  /** The group a new entry starts in. */
  defaultGroup?: string | null;
  onSave: (entry: HostsEntryEdit) => void;
  onDone: () => void;
}

const NONE = '\u0000none';
const NEW = '\u0000new';
const KEEP = 'keep';
const EXPIRY_SECONDS = { '3600': 3600, '28800': 28_800, '86400': 86_400 } as const;

export const MAX_GROUP_NAME = 64;

/** A group name problem, or nothing when `name` can be used. */
export function groupNameError(name: string, taken: readonly string[]) {
  const trimmed = name.trim();
  if (!trimmed || [...trimmed].length > MAX_GROUP_NAME)
    return 'hostsFile.groupNameInvalid' as const;
  if (taken.includes(trimmed)) return 'hostsFile.groupNameTaken' as const;
  return undefined;
}

/** Adds or edits one entry of the draft; nothing is written until review. */
export function EntryDialog({ initial, groups, defaultGroup, onSave, onDone }: EntryDialogProps) {
  const { t, i18n } = useTranslation();
  const [address, setAddress] = useState(initial?.address ?? '');
  const [names, setNames] = useState(initial?.names.join(' ') ?? '');
  const [comment, setComment] = useState(initial?.comment ?? '');
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const startGroup = initial ? initial.group : (defaultGroup ?? null);
  const [group, setGroup] = useState(startGroup ?? NONE);
  const [newGroup, setNewGroup] = useState('');
  const [expiry, setExpiry] = useState<string>(initial?.expires ? KEEP : 'never');
  const [touched, setTouched] = useState(false);

  const list = splitNames(names);
  const addressError = !isIpAddress(address.trim()) ? t('hostsFile.addressInvalid') : undefined;
  const badName = list.find((name) => !isValidName(name));
  const systemName = list.find((name) => isSystemName(name));
  const namesError =
    list.length === 0
      ? t('hostsFile.namesRequired')
      : badName
        ? t('hostsFile.namesInvalid', { name: badName })
        : systemName
          ? t('hostsFile.namesSystem', { name: systemName })
          : undefined;
  const newGroupError = group === NEW ? groupNameError(newGroup, groups) : undefined;
  const invalid = Boolean(addressError || namesError || newGroupError);

  const time = (iso: string) =>
    new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }).format(
      new Date(iso),
    );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (invalid) return;
    const expires =
      expiry === KEEP
        ? (initial?.expires ?? null)
        : expiry in EXPIRY_SECONDS
          ? expiryIn(EXPIRY_SECONDS[expiry as keyof typeof EXPIRY_SECONDS])
          : null;
    onSave({
      address: address.trim(),
      names: list,
      comment: comment.trim() || null,
      enabled,
      expires,
      group: group === NEW ? newGroup.trim() : group === NONE ? null : group,
    });
    onDone();
  };

  const clock = <Clock aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />;
  return (
    <DialogContent section="hostsFile" className="max-w-[560px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="indigo" size={44} glow>
              <Network className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={initial ? t('hostsFile.entryEditTitle') : t('hostsFile.entryAddTitle')}
          description={t('hostsFile.entryDescription')}
        />
        <DialogBody>
          <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)] gap-3">
            <TextField
              label={t('hostsFile.address')}
              mono
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              placeholder="10.0.0.5"
              hint={t('hostsFile.addressHint')}
              error={touched ? addressError : undefined}
              autoFocus
            />
            <TextField
              label={t('hostsFile.names')}
              mono
              value={names}
              onChange={(event) => setNames(event.target.value)}
              placeholder="api.local api"
              hint={t('hostsFile.namesHint')}
              error={touched ? namesError : undefined}
            />
          </div>
          <TextField
            label={t('hostsFile.comment')}
            value={comment}
            onChange={(event) => setComment(event.target.value)}
          />
          <div className="grid grid-cols-2 gap-3">
            <Select
              label={t('hostsFile.group')}
              value={group}
              onValueChange={setGroup}
              options={[
                { value: NONE, label: t('hostsFile.groupNone') },
                ...groups.map((name) => ({ value: name, label: name })),
                { value: NEW, label: t('hostsFile.groupCreate') },
              ]}
            />
            <Select
              label={t('hostsFile.expiry')}
              hint={t('hostsFile.expiryHint')}
              value={expiry}
              onValueChange={setExpiry}
              options={[
                ...(initial?.expires
                  ? [
                      {
                        value: KEEP,
                        label: t('hostsFile.expiryKeep', { time: time(initial.expires) }),
                        icon: clock,
                      },
                    ]
                  : []),
                { value: 'never', label: t('hostsFile.expiryNever') },
                { value: '3600', label: t('hostsFile.expiry1h'), icon: clock },
                { value: '28800', label: t('hostsFile.expiry8h'), icon: clock },
                { value: '86400', label: t('hostsFile.expiry1d'), icon: clock },
              ]}
            />
          </div>
          {group === NEW ? (
            <TextField
              label={t('hostsFile.groupName')}
              value={newGroup}
              onChange={(event) => setNewGroup(event.target.value)}
              error={touched && newGroupError ? t(newGroupError) : undefined}
              autoFocus
            />
          ) : null}
          <SwitchRow
            label={t('hostsFile.enabled')}
            hint={t('hostsFile.enabledHint')}
            checked={enabled}
            onCheckedChange={setEnabled}
          />
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" size="lg">
            {initial ? t('hostsFile.saveEntry') : t('hostsFile.addEntry')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

interface GroupDialogProps {
  name: string;
  taken: string[];
  onSave: (name: string) => void;
  onDone: () => void;
}

/** Renames a group. */
export function GroupDialog({ name, taken, onSave, onDone }: GroupDialogProps) {
  const { t } = useTranslation();
  const [value, setValue] = useState(name);
  const error = value.trim() === name ? undefined : groupNameError(value, taken);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (error) return;
    if (value.trim() !== name) onSave(value.trim());
    onDone();
  };
  return (
    <DialogContent section="hostsFile" className="max-w-[440px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader title={t('hostsFile.renameTitle')} />
        <DialogBody>
          <TextField
            label={t('hostsFile.groupName')}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            error={error ? t(error) : undefined}
            autoFocus
          />
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" size="lg" disabled={Boolean(error)}>
            {t('common.save')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
