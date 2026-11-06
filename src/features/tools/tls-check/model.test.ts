import { describe, expect, it } from 'vitest';
import type { CertSummary } from '@/bindings/CertSummary';
import type { TlsReport } from '@/bindings/TlsReport';
import { headline, roleOf } from './model';

function cert(partial: Partial<CertSummary> = {}): CertSummary {
  return {
    subject: 'example.com',
    issuer: 'R11',
    issuerOrganization: "Let's Encrypt",
    notBefore: '2026-09-01T00:00:00Z',
    notAfter: '2026-12-01T00:00:00Z',
    daysLeft: 90,
    names: ['example.com'],
    key: 'ECDSA P-256',
    selfSigned: false,
    sha256: 'AA',
    ...partial,
  };
}

function report(partial: Partial<TlsReport>): TlsReport {
  return {
    state: 'open',
    address: '93.184.216.34',
    addresses: ['93.184.216.34'],
    message: null,
    handshake: true,
    notTls: false,
    protocol: 'TLS 1.3',
    cipher: 'TLS13_AES_128_GCM_SHA256',
    trusted: true,
    problem: null,
    problemMessage: null,
    chain: [cert(), cert({ subject: 'R11', sha256: 'BB' })],
    ...partial,
  };
}

describe('headline', () => {
  it('reads a trusted certificate', () => {
    expect(headline(report({}))).toMatchObject({ badge: 'trusted', tone: 'accent', problem: null });
  });

  it('warns a month before expiry', () => {
    const soon = headline(report({ chain: [cert({ daysLeft: 12 })] }));
    expect(soon).toMatchObject({ badge: 'expiring', tone: 'warning', expiresSoon: true });
  });

  it('names the problem of an untrusted one', () => {
    const expired = headline(report({ trusted: false, problem: 'expired' }));
    expect(expired).toMatchObject({ badge: 'notTrusted', problem: 'expired', hint: null });
    const mismatch = headline(report({ trusted: false, problem: 'nameMismatch' }));
    expect(mismatch.hint).toBe('nameMismatch');
    expect(headline(report({ trusted: false, problem: null })).problem).toBe('other');
  });

  it('calls a lone self-signed certificate that', () => {
    const lone = report({
      trusted: false,
      problem: 'unknownIssuer',
      chain: [cert({ selfSigned: true })],
    });
    expect(headline(lone)).toMatchObject({ problem: 'selfSigned', hint: 'selfSigned' });
    const missingIntermediate = report({ trusted: false, problem: 'unknownIssuer' });
    expect(headline(missingIntermediate).problem).toBe('unknownIssuer');
  });
});

describe('roleOf', () => {
  it('tells the server, intermediates and roots apart', () => {
    const chain = [cert(), cert(), cert({ selfSigned: true })];
    expect(chain.map((_, i) => roleOf(chain, i))).toEqual(['server', 'intermediate', 'root']);
  });
});
