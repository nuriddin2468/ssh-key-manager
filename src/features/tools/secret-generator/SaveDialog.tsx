import { Archive } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import { Button } from '@/components/ui/Button';
import {
  DialogBody,
  DialogClose,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';

interface SaveDialogProps {
  secret: string;
  initialTitle: string;
  initialUser: string;
  /** A note to keep with it, such as the connection URL without the password. */
  notes: string;
  onDone: () => void;
}

/** Saves a generated secret as the password of a new vault entry. */
export function SaveDialog({ secret, initialTitle, initialUser, notes, onDone }: SaveDialogProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const [title, setTitle] = useState(initialTitle);
  const [user, setUser] = useState(initialUser);
  const save = useAppMutation(api.vaultAdd, {
    onSuccess: (entry) => {
      toast.success(t('toolGenerator.save.saved', { title: entry.title }), {
        action: {
          label: t('toolGenerator.save.open'),
          onClick: () => navigate({ page: 'passwords', entryId: entry.id }),
        },
      });
      onDone();
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!title.trim() || save.isPending) return;
    save.mutate({
      title: title.trim(),
      username: user.trim(),
      password: secret,
      url: '',
      notes,
      otp: null,
      kind: 'login',
      host: null,
      keyFingerprint: null,
    });
  };

  return (
    <DialogContent section="tools" className="max-w-[480px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="pink" size={44} glow>
              <Archive className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('toolGenerator.save.title')}
          description={t('toolGenerator.save.description')}
        />
        <DialogBody>
          <TextField
            label={t('toolGenerator.save.name')}
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            autoFocus
          />
          <TextField
            label={t('toolGenerator.save.user')}
            hint={t('toolGenerator.save.optional')}
            value={user}
            onChange={(event) => setUser(event.target.value)}
          />
        </DialogBody>
        <DialogFooter>
          <DialogClose asChild>
            <Button size="lg">{t('common.cancel')}</Button>
          </DialogClose>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={save.isPending}
            disabled={!title.trim()}
          >
            {t('toolGenerator.save.submit')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
