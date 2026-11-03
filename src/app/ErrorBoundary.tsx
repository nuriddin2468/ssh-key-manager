import { AlertTriangle } from 'lucide-react';
import { Component, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';
import { Tile } from '@/components/ui/Tile';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * Shows a recovery screen instead of a blank window when rendering fails.
 * React logs the error itself; trying again reloads the interface.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: unknown): ErrorBoundaryState {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  override render() {
    return this.state.error ? <Crashed error={this.state.error} /> : this.props.children;
  }
}

function Crashed({ error }: { error: Error }) {
  const { t } = useTranslation();
  return (
    // The sidebar is gone, so the whole screen moves the window.
    <div data-tauri-drag-region className="flex h-full items-center justify-center p-8">
      <EmptyState
        icon={
          <Tile tone="rose" size={52} glow>
            <AlertTriangle className="size-6" strokeWidth={2} />
          </Tile>
        }
        title={t('errors.title')}
        description={<span className="selectable">{error.message || t('errors.unknown')}</span>}
        action={
          <Button variant="primary" onClick={() => window.location.reload()}>
            {t('common.retry')}
          </Button>
        }
      />
    </div>
  );
}
