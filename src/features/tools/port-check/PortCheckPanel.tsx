import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError } from '@/api/useAppMutation';
import type { PortCheck } from '@/bindings/PortCheck';
import { Button } from '@/components/ui/Button';
import { Chip } from '@/components/ui/Chip';
import { Select } from '@/components/ui/Select';
import { type ConfigTarget, formatMs, isHost, parsePort, STATE_TONE } from '../network/model';
import { HostField, LiveRegion, PortField, ResultCard, ToolForm } from '../network/parts';

const TIMEOUTS = ['2', '5', '10'] as const;
/** Ports people check most, as quick picks. */
const COMMON = [
  { port: 22, name: 'SSH' },
  { port: 80, name: 'HTTP' },
  { port: 443, name: 'HTTPS' },
  { port: 3306, name: 'MySQL' },
  { port: 5432, name: 'PostgreSQL' },
  { port: 6379, name: 'Redis' },
  { port: 3389, name: 'RDP' },
] as const;

/** Whether a TCP port on a host takes connections. */
export function PortCheckPanel() {
  const { t } = useTranslation();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('443');
  const [wait, setWait] = useState<string>('5');
  const [touched, setTouched] = useState(false);
  const check = useMutation({
    mutationFn: api.toolsPortCheck,
    onError: (error) => toastError(t, error),
  });

  const portNumber = parsePort(port);
  const run = () => {
    setTouched(true);
    if (!isHost(host) || portNumber === null || check.isPending) return;
    check.mutate({ host: host.trim(), port: portNumber, timeoutMs: Number(wait) * 1000 });
  };

  return (
    <div className="flex max-w-[860px] flex-col gap-3">
      <ToolForm
        onSubmit={run}
        action={
          <Button type="submit" variant="primary" loading={check.isPending}>
            {t('toolNetwork.portCheck.run')}
          </Button>
        }
      >
        <HostField
          value={host}
          onChange={setHost}
          invalid={touched && !isHost(host)}
          onPick={(target: ConfigTarget) => setHost(target.host)}
        />
        <PortField value={port} onChange={setPort} invalid={portNumber === null} />
        <Select
          label={t('toolNetwork.portCheck.timeout')}
          value={wait}
          onValueChange={setWait}
          options={TIMEOUTS.map((value) => ({
            value,
            label: t('toolNetwork.seconds', { value }),
          }))}
          className="w-[104px] shrink-0"
        />
      </ToolForm>
      <fieldset className="flex flex-wrap items-center gap-1.5 px-1">
        <legend className="sr-only">{t('toolNetwork.portCheck.common')}</legend>
        {COMMON.map((item) => (
          <Chip
            key={item.port}
            label={`${item.port} · ${item.name}`}
            pressed={portNumber === item.port}
            onClick={() => setPort(String(item.port))}
          />
        ))}
      </fieldset>
      <LiveRegion busy={check.isPending}>
        {check.data && check.variables ? (
          <PortResult
            check={check.data}
            host={check.variables.host}
            port={check.variables.port}
            seconds={check.variables.timeoutMs / 1000}
          />
        ) : null}
      </LiveRegion>
    </div>
  );
}

function PortResult({
  check,
  host,
  port,
  seconds,
}: {
  check: PortCheck;
  host: string;
  port: number;
  seconds: number;
}) {
  const { t, i18n } = useTranslation();
  const vars = { host, port };
  if (check.state === 'open') {
    return (
      <ResultCard
        tone={STATE_TONE.open}
        badge={t('toolNetwork.states.open')}
        title={t('toolNetwork.portCheck.open', vars)}
      >
        <p className="text-[12.5px] text-fg-2">
          {t('toolNetwork.portCheck.openDetail', {
            address: check.address ?? '',
            ms: formatMs(check.millis ?? 0, i18n.language),
          })}
        </p>
      </ResultCard>
    );
  }
  return (
    <ResultCard
      tone={STATE_TONE[check.state]}
      badge={t(`toolNetwork.states.${check.state}`)}
      title={t(`toolNetwork.portCheck.${check.state}`, vars)}
    >
      <p className="text-[12.5px] text-fg-2">
        {t(`toolNetwork.explain.${check.state}`, {
          ...vars,
          seconds,
          message: check.message ?? '',
        })}
      </p>
      {check.address && check.address !== host ? (
        <p className="text-[12px] text-subtle">
          {t('toolNetwork.tried', {
            address: check.address,
            count: check.addresses.length,
          })}
        </p>
      ) : null}
    </ResultCard>
  );
}
