import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ErrorBoundary } from './ErrorBoundary';

function Broken(): never {
  throw new Error('group name is not valid');
}

describe('ErrorBoundary', () => {
  it('shows what failed instead of a blank window', () => {
    // React reports the caught error on the console; keep the test output clean.
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    render(
      <ErrorBoundary>
        <Broken />
      </ErrorBoundary>,
    );
    consoleError.mockRestore();

    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    expect(screen.getByText('group name is not valid')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });

  it('renders its children while they work', () => {
    render(
      <ErrorBoundary>
        <p>Keys</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText('Keys')).toBeInTheDocument();
  });
});
