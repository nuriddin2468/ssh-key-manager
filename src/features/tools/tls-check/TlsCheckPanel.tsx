import { useMutation } from '@tanstack/react-query';
import { Copy, TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { toastError } from '@/api/useAppMutation';
import type { CertSummary } from '@/bindings/CertSummary';
import type { TlsReport } from '@/bindings/TlsReport';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { IconButton } from '@/components/ui/IconButton';
import { copyText } from '@/lib/clipboard';
import { formatDate } from '@/lib/format';
import { isHost, parsePort, STATE_TONE } from '../network/model';
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
import { headline, NAMES_SHOWN, roleOf } from './model';

/** The certificate a TLS server presents, and whether this computer trusts it. */
export function TlsCheckPanel() {
  const { t } = useTranslation();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('443');
  const [touched, setTouched] = useState(false);
  const check = useMutation({
    mutationFn: api.toolsTlsCheck,
    onError: (error) => toastError(t, error),
  });

  const portNumber = parsePort(port);
  const run = () => {
    setTouched(true);
    if (!isHost(host) || portNumber === null || check.isPending) return;
    check.mutate({ host: host.trim(), port: portNumber });
  };

  return (
    <div className="flex max-w-[860px] flex-col gap-3">
      <ToolForm
        onSubmit={run}
        action={
          <Button type="submit" variant="primary" loading={check.isPending}>
            {t('toolNetwork.tls.run')}
          </Button>
        }
      >
        <HostField
          value={host}
          onChange={setHost}
          invalid={touched && !isHost(host)}
          placeholder="example.com"
        />
        <PortField value={port} onChange={setPort} invalid={portNumber === null} />
      </ToolForm>
      <ToolNote>{t('toolNetwork.tls.note')}</ToolNote>
      <LiveRegion busy={check.isPending}>
        {check.data && check.variables ? (
          <TlsResult report={check.data} host={check.variables.host} port={check.variables.port} />
        ) : null}
      </LiveRegion>
    </div>
  );
}

function TlsResult({ report, host, port }: { report: TlsReport; host: string; port: number }) {
  const { t, i18n } = useTranslation();

  if (report.state !== 'open') {
    return (
      <ResultCard
        tone={STATE_TONE[report.state]}
        badge={t(`toolNetwork.states.${report.state}`)}
        title={t(`toolNetwork.portCheck.${report.state}`, { host, port })}
      >
        <p className="text-[12.5px] text-fg-2">
          {t(`toolNetwork.explain.${report.state}`, {
            host,
            port,
            seconds: 5,
            message: report.message ?? '',
          })}
        </p>
      </ResultCard>
    );
  }
  if (!report.handshake) {
    return (
      <ResultCard
        tone="warning"
        badge={t('toolNetwork.tls.badges.noTls')}
        title={
          report.notTls
            ? t('toolNetwork.tls.notTls', { port })
            : t('toolNetwork.tls.failed', { message: report.message ?? '' })
        }
      />
    );
  }

  const leaf = report.chain[0];
  const view = headline(report);
  const date = leaf ? formatDate(leaf.notAfter, i18n.language) : '';
  const days = leaf ? Math.abs(leaf.daysLeft) : 0;
  return (
    <ResultCard
      tone={view.tone}
      badge={t(`toolNetwork.tls.badges.${view.badge}`)}
      title={
        view.problem
          ? t(`toolNetwork.tls.problems.${view.problem}`, { host })
          : t('toolNetwork.tls.trusted', { host })
      }
    >
      {leaf && !view.expiresSoon ? (
        <p className="text-[12.5px] text-fg-2">
          {leaf.daysLeft < 0
            ? t('toolNetwork.tls.expiredAgo', { count: days, date })
            : leaf.daysLeft === 0
              ? t('toolNetwork.tls.expiresToday')
              : t('toolNetwork.tls.expiresIn', { count: days, date })}
        </p>
      ) : null}
      {view.expiresSoon ? (
        <Note
          tone="warning"
          icon={<TriangleAlert aria-hidden="true" className="size-4" strokeWidth={2} />}
        >
          {t('toolNetwork.tls.expiresSoon', { count: leaf?.daysLeft ?? 0, date })}
        </Note>
      ) : null}
      {view.hint ? <Note>{t(`toolNetwork.tls.hints.${view.hint}`)}</Note> : null}
      <Facts
        items={[
          { label: t('toolNetwork.tls.protocol'), value: report.protocol ?? '—' },
          { label: t('toolNetwork.tls.cipher'), value: report.cipher ?? '—' },
          {
            label: t('toolNetwork.address'),
            value: report.address ?? '—',
          },
        ]}
      />
      <section className="flex flex-col gap-2 border-t border-line-soft pt-3">
        <h3 className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
          {t('toolNetwork.tls.chain')}
        </h3>
        <ol className="flex flex-col gap-2">
          {report.chain.map((cert, index) => (
            <CertCard
              // A misconfigured server can send a certificate twice.
              // biome-ignore lint/suspicious/noArrayIndexKey: the chain's order is fixed
              key={`${index}:${cert.sha256}`}
              cert={cert}
              role={roleOf(report.chain, index)}
            />
          ))}
        </ol>
      </section>
    </ResultCard>
  );
}

function CertCard({ cert, role }: { cert: CertSummary; role: 'server' | 'intermediate' | 'root' }) {
  const { t, i18n } = useTranslation();
  const shown = cert.names.slice(0, NAMES_SHOWN);
  const more = cert.names.length - shown.length;
  const issuer =
    cert.issuerOrganization && cert.issuerOrganization !== cert.issuer
      ? `${cert.issuer ?? '—'} · ${cert.issuerOrganization}`
      : (cert.issuer ?? '—');
  const copy = () => {
    copyText(cert.sha256)
      .then(() => toast.success(t('toolNetwork.copiedValue'), { id: 'tools-copy' }))
      .catch((error: unknown) => toastError(t, error));
  };
  return (
    <li className="flex flex-col gap-2 rounded-xl border border-line bg-fill-subtle p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={role === 'server' ? 'accent' : 'neutral'} pill>
          {t(`toolNetwork.tls.roles.${role}`)}
        </Badge>
        <span className="selectable min-w-0 flex-1 truncate font-semibold">
          {cert.subject ?? '—'}
        </span>
        {cert.key ? <span className="font-mono text-[11.5px] text-subtle">{cert.key}</span> : null}
      </div>
      <Facts
        items={[
          { label: t('toolNetwork.tls.issuer'), value: issuer },
          {
            label: t('toolNetwork.tls.validity'),
            value: t('toolNetwork.tls.validRange', {
              from: formatDate(cert.notBefore, i18n.language),
              to: formatDate(cert.notAfter, i18n.language),
            }),
          },
          ...(cert.names.length
            ? [
                {
                  label: t('toolNetwork.tls.names'),
                  value: (
                    <>
                      {shown.join(', ')}
                      {more > 0 ? (
                        <span className="font-sans text-subtle">
                          {' '}
                          {t('toolNetwork.tls.moreNames', { count: more })}
                        </span>
                      ) : null}
                    </>
                  ),
                },
              ]
            : []),
          {
            label: t('toolNetwork.tls.fingerprint'),
            value: (
              <span className="flex items-start gap-1">
                <span className="min-w-0 text-[11.5px] leading-[17px]">{cert.sha256}</span>
                <IconButton
                  label={t('toolNetwork.tls.copyFingerprint')}
                  icon={<Copy className="size-3.5" strokeWidth={1.9} />}
                  onClick={copy}
                  className="-mt-1.5 shrink-0"
                />
              </span>
            ),
          },
        ]}
      />
    </li>
  );
}
