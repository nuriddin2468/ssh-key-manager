import { describe, expect, it } from 'vitest';
import { displayPath, formatDuration, shortFingerprint } from './format';

describe('displayPath', () => {
  it('abbreviates the home directory', () => {
    expect(displayPath('/Users/dev/.ssh/id_ed25519', '/Users/dev')).toBe('~/.ssh/id_ed25519');
    expect(displayPath('/Users/dev', '/Users/dev/')).toBe('~');
    expect(displayPath('C:\\Users\\dev\\.ssh\\id_rsa', 'C:\\Users\\dev')).toBe('~\\.ssh\\id_rsa');
  });

  it('leaves other paths and lookalike prefixes alone', () => {
    expect(displayPath('/Users/devops/.ssh/id_rsa', '/Users/dev')).toBe(
      '/Users/devops/.ssh/id_rsa',
    );
    expect(displayPath('/etc/ssh/ssh_config', undefined)).toBe('/etc/ssh/ssh_config');
  });
});

describe('shortFingerprint', () => {
  it('keeps the start and the end', () => {
    expect(shortFingerprint('SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw')).toBe(
      'SHA256:k3XbV9qL2…KjBnHw',
    );
    expect(shortFingerprint(null)).toBe('—');
  });
});

describe('formatDuration', () => {
  it('formats hours and minutes', () => {
    expect(formatDuration(3 * 3600 + 12 * 60, 'en')).toBe('3 hr 12 min');
    expect(formatDuration(30, 'en')).toBe('1 min');
  });
});
