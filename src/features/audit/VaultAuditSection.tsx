import { useQuery } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultEntries, useVaultStatus } from '@/api/queries';
import { useRouter } from '@/app/router';
import type { VaultFinding } from '@/bindings/VaultFinding';
import { Button } from '@/components/ui/Button';
import { Tile } from '@/components/ui/Tile';
import { VaultIcon } from '@/features/keys/VaultControls';
import { FindingRow } from './FindingRow';
import {
  IGNORE_PREFIX,
  vaultFindingTarget,
  vaultFindingText,
  vaultFindingTitle,
} from './vaultModel';

interface VaultAuditSectionProps {
  /** Ignored finding ids, SSH and vault ones alike. */
  ignored: ReadonlySet<string>;
  onIgnore: (id: string, value: boolean) => void;
}

/**
 * The "Passwords" part of the audit: weak, reused and old passwords and
 * entries that point at missing keys or hosts. Hidden when there is no vault.
 */
export function VaultAuditSection({ ignored, onIgnore }: VaultAuditSectionProps) {
  const { t, i18n } = useTranslation();
  const { navigate } = useRouter();
  const state = useVaultStatus().data?.state;
  // Keyed by the state, so locking or unlocking the vault checks again.
  const audit = useQuery({
    queryKey: ['vault', 'audit', state],
    queryFn: api.vaultAudit,
    enabled: state !== undefined,
  });
  const entries = useVaultEntries();
  const [showIgnored, setShowIgnored] = useState(false);

  const data = audit.data;
  if (!data || data.state === 'missing') return null;

  const titles = new Map((entries.data ?? []).map((entry) => [entry.id, entry.title]));
  const ignoreId = (finding: VaultFinding) => `${IGNORE_PREFIX}${finding.id}`;
  const open = data.findings.filter((f) => !ignored.has(ignoreId(f)));
  const hidden = data.findings.filter((f) => ignored.has(ignoreId(f)));

  const row = (finding: VaultFinding, muted: boolean) => {
    const target = vaultFindingTarget(finding);
    return (
      <FindingRow
        key={finding.id}
        severity={finding.severity}
        title={vaultFindingTitle(t, finding)}
        text={vaultFindingText(t, finding, titles, i18n.language)}
        subject={titles.get(finding.entryId) ?? ''}
        actionLabel={t(target.label)}
        onAction={() => navigate(target.route)}
        muted={muted}
        onIgnore={muted ? undefined : () => onIgnore(ignoreId(finding), true)}
        onRestore={muted ? () => onIgnore(ignoreId(finding), false) : undefined}
      />
    );
  };

  return (
    <section aria-labelledby="vault-audit-h" className="flex flex-col gap-2.5">
      <h2 id="vault-audit-h" className="text-[14px] leading-5 font-semibold">
        {t('audit.vault.title')}
      </h2>

      {data.state === 'locked' ? (
        <div className="glass flex flex-wrap items-center gap-x-3.5 gap-y-3 rounded-2xl px-4 py-[13px]">
          <Tile tone="slate" size={36}>
            <VaultIcon className="size-[18px]" />
          </Tile>
          <span className="flex min-w-[240px] flex-1 flex-col gap-0.5">
            <span className="font-semibold">{t('audit.vault.lockedTitle')}</span>
            <span className="text-[12.5px] text-muted">{t('audit.vault.lockedText')}</span>
          </span>
          <Button size="sm" onClick={() => navigate({ page: 'passwords' })}>
            {t('audit.vault.open')}
          </Button>
        </div>
      ) : open.length === 0 ? (
        <p className="flex items-center gap-2 rounded-xl border border-ok/25 bg-ok/[0.08] px-3 py-2.5 text-[12.5px] text-teal-200">
          <ShieldCheck aria-hidden="true" className="size-4" strokeWidth={2} />
          {t('audit.vault.clear')}
        </p>
      ) : (
        open.map((finding) => row(finding, false))
      )}

      {data.state === 'unlocked' && hidden.length > 0 ? (
        <>
          <p className="flex items-center gap-2 text-[12.5px] text-subtle">
            {t('audit.ignored', { count: hidden.length })}
            <Button variant="ghost" size="sm" onClick={() => setShowIgnored((v) => !v)}>
              {showIgnored ? t('audit.hideIgnored') : t('audit.showIgnored')}
            </Button>
          </p>
          {showIgnored ? hidden.map((finding) => row(finding, true)) : null}
        </>
      ) : null}
    </section>
  );
}
