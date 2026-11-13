import { useMutation } from '@tanstack/react-query';
import { FileText } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useHostsFile } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { DnsAnswer } from '@/bindings/DnsAnswer';
import type { DnsReport } from '@/bindings/DnsReport';
import type { DnsStatus } from '@/bindings/DnsStatus';
import type { RecordType } from '@/bindings/RecordType';
import { Badge, type BadgeTone } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/Spinner';
import { isValidName, lookupName } from '@/features/hostsFile/model';
import { AppError } from '@/lib/ipc';
import { isAddress } from '../network/model';
import { HostField, LiveRegion, Note, ToolForm } from '../network/parts';

const TYPE_LABEL: Record<RecordType, string> = {
  a: 'A',
  aaaa: 'AAAA',
  cname: 'CNAME',
  mx: 'MX',
  txt: 'TXT',
};

const STATUS_TONE: Record<DnsStatus, BadgeTone> = {
  found: 'accent',
  noRecords: 'neutral',
  noSuchName: 'warning',
  serverFailure: 'critical',
  refused: 'critical',
  noAnswer: 'warning',
  failed: 'critical',
};

const isLookupName = (name: string) => isValidName(name.trim()) && !isAddress(name);

/**
 * A name's DNS records from the computer's DNS servers, the address the
 * system resolver gives (hosts file first, as `ssh` sees it) and the hosts
 * file lines that override DNS.
 */
export function DnsLookupPanel() {
  const { t } = useTranslation();
  const [name, setName] = useState('');
  const [touched, setTouched] = useState(false);
  // Both go over the network, so they run only when the user asks.
  const dns = useMutation({
    mutationFn: api.toolsDnsLookup,
    onError: (error) => {
      if (AppError.from(error).code === 'not_found') toast.error(t('toolNetwork.dns.noServers'));
      else toastError(t, error);
    },
  });
  const system = useMutation({ mutationFn: api.lookupHost });

  const run = () => {
    setTouched(true);
    const value = name.trim();
    if (!isLookupName(value) || dns.isPending) return;
    dns.mutate(value);
    system.mutate(value);
  };

  return (
    <div className="flex max-w-[860px] flex-col gap-3">
      <ToolForm
        onSubmit={run}
        action={
          <Button type="submit" variant="primary" loading={dns.isPending}>
            {t('toolNetwork.dns.run')}
          </Button>
        }
      >
        <HostField
          label={t('toolNetwork.dns.name')}
          placeholder={t('toolNetwork.dns.namePlaceholder')}
          value={name}
          onChange={setName}
          invalid={touched && name.trim() !== '' && !isLookupName(name)}
        />
      </ToolForm>
      {touched && isAddress(name) ? (
        <p className="px-1 text-[12.5px] text-critical">{t('toolNetwork.dns.nameInvalid')}</p>
      ) : null}
      <LiveRegion busy={dns.isPending}>
        {dns.variables ? (
          <>
            <Overrides name={dns.variables} />
            <SystemAnswer
              name={dns.variables}
              pending={system.isPending}
              addresses={system.data?.addresses ?? null}
            />
          </>
        ) : null}
        {dns.data ? <Records report={dns.data} /> : null}
      </LiveRegion>
    </div>
  );
}

/** The hosts file lines that send the name somewhere, which beat DNS. */
function Overrides({ name }: { name: string }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const hostsFile = useHostsFile();
  const used = lookupName(hostsFile.data?.view.entries ?? [], name).filter((m) => m.used);
  if (used.length === 0) return null;
  return (
    <div className="flex flex-col gap-2">
      {used.map(({ entry }) => (
        <Note
          key={entry.line}
          tone="warning"
          icon={<FileText aria-hidden="true" className="size-4" strokeWidth={1.9} />}
          action={
            <Button
              size="sm"
              variant="ghost"
              onClick={() => navigate({ page: 'hostsFile', line: entry.line })}
            >
              {t('toolNetwork.dns.openHostsFile')}
            </Button>
          }
        >
          {t('toolNetwork.dns.pinned', { name, address: entry.address, line: entry.line })}
        </Note>
      ))}
    </div>
  );
}

function SystemAnswer({
  name,
  pending,
  addresses,
}: {
  name: string;
  pending: boolean;
  addresses: string[] | null;
}) {
  const { t } = useTranslation();
  return (
    <section className="glass flex flex-wrap items-baseline gap-x-3 gap-y-1 rounded-2xl px-4 py-3">
      {pending ? (
        <>
          <h2 className="text-[12.5px] font-semibold text-fg-2">{t('toolNetwork.dns.system')}</h2>
          <Spinner className="size-3.5" />
        </>
      ) : addresses && addresses.length > 0 ? (
        <>
          <h2 className="text-[12.5px] font-semibold text-fg-2">{t('toolNetwork.dns.system')}</h2>
          <span className="selectable font-mono text-[12.5px] text-fg [overflow-wrap:anywhere]">
            {addresses.join(', ')}
          </span>
        </>
      ) : (
        <h2 className="text-[12.5px] font-medium text-muted">
          {t('toolNetwork.dns.systemNone', { name })}
        </h2>
      )}
    </section>
  );
}

function Records({ report }: { report: DnsReport }) {
  const { t } = useTranslation();
  const server = report.answers.find((a) => a.status === 'found')?.server ?? report.servers[0];
  return (
    <section className="glass flex flex-col gap-1 rounded-2xl p-4 animate-fade-in">
      <div className="mb-1 flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-[14.5px] font-semibold">{t('toolNetwork.dns.records')}</h2>
        {server ? (
          <span className="text-[12px] text-subtle">{t('toolNetwork.dns.asked', { server })}</span>
        ) : null}
      </div>
      <ul className="flex flex-col divide-y divide-line-soft">
        {report.answers.map((answer) => (
          <AnswerRow key={answer.kind} answer={answer} asked={report.name} />
        ))}
      </ul>
    </section>
  );
}

function AnswerRow({ answer, asked }: { answer: DnsAnswer; asked: string }) {
  const { t } = useTranslation();
  return (
    <li className="grid grid-cols-[64px_1fr] items-start gap-3 py-2.5">
      <Badge tone={answer.records.length ? 'accent' : 'neutral'} mono className="justify-center">
        {TYPE_LABEL[answer.kind]}
      </Badge>
      {answer.records.length === 0 ? (
        <span className="flex flex-wrap items-center gap-2 pt-0.5 text-[12.5px] text-muted">
          <Badge tone={STATUS_TONE[answer.status]} pill>
            {t(`toolNetwork.dns.statuses.${answer.status}`)}
          </Badge>
          {answer.message ? <span className="selectable">{answer.message}</span> : null}
        </span>
      ) : (
        <ul className="flex min-w-0 flex-col gap-1.5">
          {answer.records.map((record, index) => (
            <li
              // Records come in the server's order.
              // biome-ignore lint/suspicious/noArrayIndexKey: a fixed list
              key={index}
              className="flex min-w-0 flex-col gap-0.5"
            >
              <span className="selectable font-mono text-[12.5px] leading-[18px] text-fg [overflow-wrap:anywhere]">
                {record.kind !== answer.kind ? (
                  <span className="text-subtle">
                    {TYPE_LABEL[record.kind]} {record.name} →{' '}
                  </span>
                ) : record.name !== asked ? (
                  <span className="text-subtle">{record.name} → </span>
                ) : null}
                {record.value}
              </span>
              <span className="text-[11.5px] text-subtle">
                {record.priority !== null
                  ? `${t('toolNetwork.dns.priority', { value: record.priority })} · `
                  : ''}
                {t('toolNetwork.dns.ttl', { value: record.ttl })}
              </span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}
