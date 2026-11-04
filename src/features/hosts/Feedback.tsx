// Text and result boxes shared by the host dialogs.

import { CheckCircle2, XCircle } from 'lucide-react';
import type { ReactNode } from 'react';

export function Text({ id, children }: { id?: string; children: ReactNode }) {
  return (
    <p id={id} className="text-[13px] leading-5 text-fg-2">
      {children}
    </p>
  );
}

/** Where results appear; mounted before them, so screen readers announce them. */
export function Live({ children }: { children: ReactNode }) {
  return (
    // Empty, it takes no room (the negative margin cancels the body's gap)
    // but stays in the accessibility tree.
    <div role="status" className="flex flex-col gap-2 empty:-mt-[18px]">
      {children}
    </div>
  );
}

export function OkBox({ children }: { children: ReactNode }) {
  return (
    <p className="flex gap-2.5 rounded-xl border border-ok/30 bg-ok/[0.08] px-3 py-2.5 font-medium">
      <CheckCircle2 aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-ok" strokeWidth={2} />
      {children}
    </p>
  );
}

export function ErrorBox({ children }: { children: ReactNode }) {
  return (
    <p className="flex gap-2.5 rounded-xl border border-critical-solid/30 bg-critical-solid/10 px-3 py-2.5">
      <XCircle
        aria-hidden="true"
        className="mt-0.5 size-4 shrink-0 text-critical"
        strokeWidth={2}
      />
      {children}
    </p>
  );
}
