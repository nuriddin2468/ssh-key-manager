import { CircleCheck, CircleX, RotateCcw, Route, Unlink } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { refreshConnectionHistory, useConfig, useVaultStatus } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { HostEntry } from '@/bindings/HostEntry';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { EmptyState } from '@/components/ui/EmptyState';
import { Select } from '@/components/ui/Select';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { isPlainAlias, OutputBox, plainHosts, Section } from '../ssh/parts';
import { changesFor, firstAlias, hasProxyCommand } from './model';

type Test = { state: 'testing' } | { state: 'done'; result: ConnectionTest } | { state: 'error' };

/**
 * The ProxyJump wizard: a jump host, the hosts to reach through it, what
 * changes in ~/.ssh/config, then a connection test of each.
 */
export function JumpHostPanel() {
  const { t } = useTranslation();
  const config = useConfig();
  const vault = useVaultStatus();
  const hosts = useMemo(() => plainHosts(config.data?.view.hosts ?? []), [config.data]);
  const [bastion, setBastion] = useState('');
  const [picked, setPicked] = useState<Set<number>>(() => new Set());
  const [tests, setTests] = useState<Map<string, Test>>(() => new Map());

  const bastionAliases = useMemo(
    () => [...new Set(hosts.flatMap((host) => host.patterns.filter(isPlainAlias)))],
    [hosts],
  );
  const targets = hosts.filter((host) => !host.patterns.includes(bastion));
  const chosen = targets.filter((host) => picked.has(host.id));
  const changes = bastion ? changesFor(chosen, bastion) : [];
  const removable = chosen.some((host) => host.proxyJump);

  const test = async (alias: string) => {
    setTests((current) => new Map(current).set(alias, { state: 'testing' }));
    try {
      const result =
        vault.data?.state === 'unlocked'
          ? await api.vaultTestConnection(alias)
          : await api.testConnection(alias);
      setTests((current) => new Map(current).set(alias, { state: 'done', result }));
    } catch {
      setTests((current) => new Map(current).set(alias, { state: 'error' }));
    } finally {
      void refreshConnectionHistory();
    }
  };

  const save = useAppMutation(
    (jump: string | null) => api.setProxyJump(jump, [...picked], config.data?.view.revision ?? ''),
    {
      success: (_, jump) =>
        t(jump ? 'toolSsh.jump.saved' : 'toolSsh.jump.removed', { count: chosen.length }),
      onSuccess: (_, jump) => {
        setTests(new Map());
        if (jump) for (const host of chosen) void test(firstAlias(host));
      },
    },
  );

  if (config.isPending) {
    return (
      <div className="grid place-items-center py-10">
        <Spinner className="size-5 text-subtle" />
      </div>
    );
  }
  if (hosts.length < 2) {
    return (
      <EmptyState
        icon={
          <Tile tone="indigo" size={40} glow>
            <Route className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('toolSsh.jump.noHosts')}
      />
    );
  }

  const toggle = (host: HostEntry, on: boolean) =>
    setPicked((current) => {
      const next = new Set(current);
      if (on) next.add(host.id);
      else next.delete(host.id);
      return next;
    });

  return (
    <div className="flex flex-col gap-3.5">
      <p className="text-[12.5px] text-muted">{t('toolSsh.jump.description')}</p>
      <Section title={t('toolSsh.jump.bastion')} description={t('toolSsh.jump.bastionHint')}>
        <Select
          aria-label={t('toolSsh.jump.bastion')}
          value={bastion}
          onValueChange={(value) => {
            setBastion(value);
            setTests(new Map());
          }}
          options={bastionAliases.map((alias) => ({ value: alias, label: alias }))}
          placeholder={t('toolSsh.jump.bastionPlaceholder')}
          mono
          className="max-w-[320px]"
        />
      </Section>

      <Section
        title={t('toolSsh.jump.targets')}
        description={t('toolSsh.jump.targetsHint')}
        className={cn(!bastion && 'opacity-60')}
      >
        {targets.length === 0 ? (
          <p className="text-[12.5px] text-subtle">{t('toolSsh.jump.noTargets')}</p>
        ) : (
          <ul className="grid grid-cols-[repeat(auto-fill,minmax(240px,1fr))] gap-x-4 gap-y-2.5">
            {targets.map((host) => (
              <li key={host.id} className="min-w-0">
                <Checkbox
                  checked={picked.has(host.id)}
                  onCheckedChange={(on) => toggle(host, on)}
                  disabled={!bastion}
                  label={
                    <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
                      <span className="font-mono text-[12.5px]">{host.patterns.join(' ')}</span>
                      {host.proxyJump ? (
                        <Badge tone="violet" mono>
                          {t('toolSsh.jump.via', { jump: host.proxyJump })}
                        </Badge>
                      ) : null}
                      {host.hostName ? (
                        <span className="basis-full truncate font-mono text-[11.5px] text-subtle">
                          {host.user ? `${host.user}@` : ''}
                          {host.hostName}
                        </span>
                      ) : null}
                    </span>
                  }
                />
              </li>
            ))}
          </ul>
        )}
      </Section>

      {changes.length > 0 ? (
        <Section title={t('toolSsh.jump.preview')}>
          <pre className="selectable overflow-x-auto rounded-[11px] border border-ink/[0.07] bg-terminal px-3 py-2.5 font-mono text-[12px] leading-[1.65]">
            {changes.map((change, index) => (
              <span key={change.host.id} className="block">
                {index > 0 ? '\n' : ''}
                <span className="text-subtle">Host {change.host.patterns.join(' ')}</span>
                {'\n'}
                {change.removed.map((value) => (
                  <span key={`-${value}`} className="block text-critical">
                    - ProxyJump {value}
                  </span>
                ))}
                <span className="block text-ok">+ ProxyJump {bastion}</span>
              </span>
            ))}
          </pre>
          {chosen.filter(hasProxyCommand).map((host) => (
            <p key={host.id} className="text-[12.5px] text-warning">
              {t('toolSsh.jump.proxyCommand', { alias: firstAlias(host) })}
            </p>
          ))}
        </Section>
      ) : null}

      <div className="flex flex-wrap items-center justify-end gap-2.5">
        {removable ? (
          <Button
            variant="ghost"
            icon={<Unlink className="size-4" strokeWidth={2} />}
            onClick={() => save.mutate(null)}
            disabled={save.isPending}
          >
            {t('toolSsh.jump.remove')}
          </Button>
        ) : null}
        <Button
          variant="primary"
          icon={<Route className="size-4" strokeWidth={2} />}
          onClick={() => save.mutate(bastion)}
          disabled={!bastion || chosen.length === 0}
          loading={save.isPending && save.variables !== null}
        >
          {chosen.length > 0
            ? t('toolSsh.jump.save', { count: chosen.length })
            : t('toolSsh.jump.saveEmpty')}
        </Button>
      </div>

      {tests.size > 0 ? (
        <Section title={t('toolSsh.jump.results')}>
          <ul className="flex flex-col gap-2.5" aria-live="polite">
            {[...tests].map(([alias, state]) => (
              <TestRow key={alias} alias={alias} state={state} onRetry={() => void test(alias)} />
            ))}
          </ul>
        </Section>
      ) : null}
    </div>
  );
}

function TestRow({ alias, state, onRetry }: { alias: string; state: Test; onRetry: () => void }) {
  const { t } = useTranslation();
  const ok = state.state === 'done' && state.result.ok;
  return (
    <li className="flex flex-col gap-1.5">
      <div className="flex items-center gap-2.5">
        {state.state === 'testing' ? (
          <Spinner className="size-4 text-info" />
        ) : ok ? (
          <CircleCheck aria-hidden="true" className="size-4 text-ok" strokeWidth={2.25} />
        ) : (
          <CircleX aria-hidden="true" className="size-4 text-critical" strokeWidth={2.25} />
        )}
        <span className="font-mono text-[12.5px]">{alias}</span>
        <span
          className={cn(
            'text-[12.5px]',
            state.state === 'testing' ? 'text-info' : ok ? 'text-ok' : 'text-critical',
          )}
        >
          {state.state === 'testing'
            ? t('toolSsh.jump.testing')
            : ok
              ? t('toolSsh.jump.signedIn')
              : t('toolSsh.jump.failed')}
        </span>
        <span className="flex-1" />
        {state.state !== 'testing' ? (
          <Button
            size="sm"
            variant="ghost"
            icon={<RotateCcw className="size-3.5" strokeWidth={2} />}
            onClick={onRetry}
          >
            {t('toolSsh.jump.test')}
          </Button>
        ) : null}
      </div>
      {state.state === 'done' && !state.result.ok && state.result.output ? (
        <OutputBox text={state.result.output} />
      ) : null}
    </li>
  );
}
