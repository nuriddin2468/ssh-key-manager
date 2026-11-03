import { type ReactNode, useEffect, useId, useRef } from 'react';
import { Tile } from '@/components/ui/Tile';

interface VaultCardProps {
  icon: ReactNode;
  title: ReactNode;
  text?: ReactNode;
  /** Move focus to the heading when shown, e.g. after the previous step's button went away. */
  focusTitle?: boolean;
  children: ReactNode;
}

/** The centred card the vault's create, lock and recovery-key screens share. */
export function VaultCard({ icon, title, text, focusTitle = false, children }: VaultCardProps) {
  const id = useId();
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (focusTitle) heading.current?.focus();
  }, [focusTitle]);

  return (
    <section aria-labelledby={id} className="m-auto flex w-full max-w-[440px] flex-col gap-5 py-4">
      <div className="flex flex-col items-center gap-3 text-center">
        <Tile tone="pink" size={56} glow>
          {icon}
        </Tile>
        <h2
          id={id}
          ref={heading}
          tabIndex={-1}
          className="text-[22px] leading-7 font-semibold tracking-[-0.02em] outline-none"
        >
          {title}
        </h2>
        {text ? <p className="max-w-[400px] text-[13px] leading-5 text-muted">{text}</p> : null}
      </div>
      <div className="glass-raised flex flex-col gap-4 rounded-[20px] p-5">{children}</div>
    </section>
  );
}
