import { useMutation } from '@tanstack/react-query';
import { TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError } from '@/api/useAppMutation';
import type { SshPing } from '@/bindings/SshPing';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { cn } from '@/lib/cn';
import { type ConfigTarget, formatMs, isHost, parsePort, STATE_TONE } from '../network/model';
import {
  Facts,
  HostField,
  LiveRegion,
  Note,
  PortField,
  ResultCard,
  ToolForm,
  ToolNote,
} from '../network/parts';

const SAMPLES = ['3', '5', '10'] as const;

/** Times TCP connections to a host's SSH port and reads its version line. */
export function SshPingPanel() {
  const { t } = useTranslation();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('22');
  const [samples, setSamples] = useState<string>('5');
  const [jump, setJump] = useState<ConfigTarget | null>(null);
  const [touched, setTouched] = useState(false);
  // Nothing goes over the network until the user asks.
  const ping = useMutation({
    mutationFn: api.toolsSshPing,
    onError: (error) => toastError(t, error),
  });

  const hostInvalid = touched && !isHost(host);
  const portNumber = parsePort(port);
  const run = () => {
    setTouched(true);
    if (!isHost(host) || portNumber === null || ping.isPending) return;
    ping.mutate({ host: host.trim(), port: portNumber, samples: Number(samples) });
  };
  const pick = (target: ConfigTarget) => {
    setHost(target.host);
    setPort(String(target.port));
    setJump(target.jump ? target : null);
  };

  return (
    <div className="flex max-w-[860px] flex-col gap-3">
      <ToolForm
        onSubmit={run}
        action={
          <Button type="submit" variant="primary" loading={ping.isPending}>
            {t('toolNetwork.sshPing.run')}
          </Button>
        }
      >
        <HostField
          value={host}
          onChange={(value) => {
            setHost(value);
            setJump(null);
          }}
          invalid={hostInvalid}
          onPick={pick}
        />
        <PortField value={port} onChange={setPort} invalid={portNumber === null} />
        <Select
          label={t('toolNetwork.sshPing.samples')}
          value={samples}
          onValueChange={setSamples}
          options={SAMPLES.map((value) => ({ value, label: value }))}
          className="w-[96px] shrink-0"
        />
      </ToolForm>
      {jump ? (
        <Note>
          {t('toolNetwork.viaJump', { alias: jump.alias, jump: jump.jump ?? '', host: jump.host })}
        </Note>
      ) : null}
      <ToolNote>{t('toolNetwork.sshPing.note')}</ToolNote>
      <LiveRegion busy={ping.isPending}>
        {ping.data && ping.variables ? (
          <PingResult ping={ping.data} host={ping.variables.host} port={ping.variables.port} />
        ) : null}
      </LiveRegion>
    </div>
  );
}

function PingResult({ ping, host, port }: { ping: SshPing; host: string; port: number }) {
  const { t, i18n } = useTranslation();
  const ms = (value: number | null) =>
    value === null ? '—' : t('toolNetwork.ms', { value: formatMs(value, i18n.language) });

  if (ping.state !== 'open') {
    return (
      <ResultCard
        tone={STATE_TONE[ping.state]}
        badge={t(`toolNetwork.states.${ping.state}`)}
        title={t('toolNetwork.sshPing.noConnection', { host })}
      >
        <p className="text-[12.5px] text-fg-2">
          {t(`toolNetwork.explain.${ping.state}`, {
            host,
            port,
            seconds: 5,
            message: ping.message ?? '',
          })}
        </p>
      </ResultCard>
    );
  }

  const banner = ping.banner;
  const attempts = ping.samples.length;
  return (
    <ResultCard
      tone="accent"
      badge={t('toolNetwork.states.open')}
      title={t('toolNetwork.sshPing.answered', {
        host,
        ms: formatMs(ping.avg ?? 0, i18n.language),
      })}
    >
      {/* What matters most about the server comes first. */}
      {banner?.outdated ? (
        <Note
          tone="warning"
          icon={<TriangleAlert aria-hidden="true" className="size-4" strokeWidth={2} />}
        >
          {banner.openssh
            ? t('toolNetwork.sshPing.outdated', { version: banner.openssh })
            : t('toolNetwork.sshPing.protocol1')}
        </Note>
      ) : null}
      {banner ? null : (
        <Note
          tone="warning"
          icon={<TriangleAlert aria-hidden="true" className="size-4" strokeWidth={2} />}
        >
          {ping.other
            ? t('toolNetwork.sshPing.notSsh', { port, line: ping.other })
            : t('toolNetwork.sshPing.silent', { port })}
        </Note>
      )}
      {ping.address !== host ? (
        <p className="text-[12.5px] text-muted">
          {t('toolNetwork.connectedToOneOf', {
            address: ping.address ?? '',
            count: ping.addresses.length,
          })}
        </p>
      ) : null}
      <div className="grid grid-cols-4 gap-2 max-[560px]:grid-cols-2">
        <Stat label={t('toolNetwork.sshPing.min')} value={ms(ping.min)} />
        <Stat label={t('toolNetwork.sshPing.avg')} value={ms(ping.avg)} />
        <Stat label={t('toolNetwork.sshPing.max')} value={ms(ping.max)} />
        <Stat
          label={t('toolNetwork.sshPing.lost')}
          value={`${ping.lost} / ${attempts}`}
          warn={ping.lost > 0}
        />
      </div>
      <ol
        aria-label={t('toolNetwork.sshPing.samples')}
        className="flex flex-wrap gap-1.5 font-mono text-[11.5px]"
      >
        {ping.samples.map((sample, index) => (
          <li
            // The samples come in a fixed order.
            // biome-ignore lint/suspicious/noArrayIndexKey: a fixed list
            key={index}
            className={cn(
              'rounded-md border px-1.5 py-0.5 tabular-nums',
              sample === null
                ? 'border-warning-solid/30 bg-warning-solid/10 text-warning'
                : 'border-white/[0.08] bg-white/[0.03] text-fg-2',
            )}
          >
            {sample === null ? t('toolNetwork.sshPing.lost') : ms(sample)}
          </li>
        ))}
      </ol>
      {ping.lost > 0 ? (
        <p className="text-[12.5px] text-warning">
          {t('toolNetwork.sshPing.lostSome', { count: ping.lost })}
        </p>
      ) : null}

      {banner ? (
        <section className="flex flex-col gap-2 border-t border-white/[0.06] pt-3">
          <h3 className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
            {t('toolNetwork.sshPing.server')}
          </h3>
          <Facts
            items={[
              { label: t('toolNetwork.sshPing.software'), value: banner.software },
              { label: t('toolNetwork.sshPing.versionLine'), value: banner.line },
            ]}
          />
        </section>
      ) : null}
    </ResultCard>
  );
}

function Stat({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-2">
      <span className="text-[11.5px] text-subtle">{label}</span>
      <span
        className={cn(
          'font-mono text-[15px] font-semibold tabular-nums',
          warn ? 'text-warning' : 'text-fg',
        )}
      >
        {value}
      </span>
    </div>
  );
}
