import { AlertTriangle, X } from 'lucide-react';
import { Dialog as RDialog } from 'radix-ui';
import {
  type ComponentProps,
  createContext,
  type ReactNode,
  type RefObject,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/cn';
import { IconButton } from './IconButton';

export const DialogClose = RDialog.Close;

/** A failure a dialog says above its buttons. */
export interface DialogFailure {
  text: string;
  /** What the system said, for an unexpected failure. */
  detail?: string;
}

/** What the commands of a dialog's form tell it ([`useDialogErrors`]). */
export interface DialogErrors {
  /**
   * Shows `failure` above the buttons of the dialog on screen; false when
   * none is (the dialog closed, or has no buttons), for a toast instead.
   */
  show: (failure: DialogFailure) => boolean;
  clear: () => void;
  /** After a refused save: brings the first field with a problem into view. */
  revealInvalid: () => void;
}

interface DialogInner {
  failure: DialogFailure | null;
  /** A footer, which shows failures, is on screen until the returned call. */
  footer: () => () => void;
  /** The dialog's content, where fields with problems are looked for. */
  content: (element: HTMLElement | null) => void;
}

const ErrorsContext = createContext<DialogErrors | null>(null);
const InnerContext = createContext<DialogInner | null>(null);

/**
 * The commands of the dialog a component is in, or `null` outside one: a
 * save that fails says why above the dialog's buttons, where the user is
 * looking, and the dialog stays open with what they typed.
 */
export function useDialogErrors(): DialogErrors | null {
  return useContext(ErrorsContext);
}

/**
 * Radix's dialog, with a place for what its commands fail with
 * ([`useDialogErrors`]), cleared when it closes.
 */
export function Dialog({
  open,
  onOpenChange,
  children,
  ...props
}: ComponentProps<typeof RDialog.Root>) {
  const [failure, setFailure] = useState<DialogFailure | null>(null);
  const footers = useRef(0);
  const content = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (open === false) setFailure(null);
  }, [open]);
  const errors = useMemo<DialogErrors>(
    () => ({
      show: (next) => {
        if (footers.current === 0) return false;
        setFailure(next);
        return true;
      },
      clear: () => setFailure(null),
      revealInvalid: () => revealInvalid(content.current),
    }),
    [],
  );
  const stable = useMemo(
    () => ({
      footer: () => {
        footers.current += 1;
        return () => {
          footers.current -= 1;
        };
      },
      content: (element: HTMLElement | null) => {
        content.current = element;
      },
    }),
    [],
  );
  const inner = useMemo<DialogInner>(() => ({ failure, ...stable }), [failure, stable]);
  return (
    <ErrorsContext.Provider value={errors}>
      <InnerContext.Provider value={inner}>
        <RDialog.Root
          open={open}
          onOpenChange={(next) => {
            if (!next) setFailure(null);
            onOpenChange?.(next);
          }}
          {...props}
        >
          {children}
        </RDialog.Root>
      </InnerContext.Provider>
    </ErrorsContext.Provider>
  );
}

/**
 * Brings the first field marked invalid into view and focuses it, after the
 * render that marks it; else the first problem said in words.
 */
function revealInvalid(container: HTMLElement | null) {
  if (!container) return;
  requestAnimationFrame(() => {
    const field = container.querySelector<HTMLElement>('[aria-invalid="true"]');
    const problem =
      field ??
      [...container.querySelectorAll<HTMLElement>('[role="alert"]')].find(
        (element) => !element.classList.contains('sr-only'),
      );
    if (!problem) return;
    problem.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
    if (field && !field.contains(document.activeElement)) field.focus({ preventScroll: true });
  });
}

/** A toast is not outside the dialog: reading or closing one keeps it open. */
export function fromToast(event: Event): boolean {
  const target = event.target;
  return target instanceof Element && target.closest('[data-sonner-toaster]') !== null;
}

interface DialogContentProps {
  /** Page section whose accent the dialog uses. */
  section: string;
  className?: string;
  /** `false` ignores Escape and clicks outside, for a step that must be finished. */
  dismissible?: boolean;
  /**
   * Escape goes back a step instead of closing, while this is set (a
   * dialog's second step).
   */
  onBack?: () => void;
  children: ReactNode;
}

export function DialogContent({
  section,
  className,
  dismissible = true,
  onBack,
  children,
}: DialogContentProps) {
  const block = dismissible ? undefined : (event: Event) => event.preventDefault();
  const onEscape = onBack
    ? (event: Event) => {
        event.preventDefault();
        if (dismissible) onBack();
      }
    : block;
  const outside = (event: Event) => {
    if (!dismissible || fromToast(event)) event.preventDefault();
  };
  const returnFocus = useReturnFocus();
  const inner = useContext(InnerContext);
  const errors = useDialogErrors();
  return (
    <RDialog.Portal>
      <RDialog.Overlay className="fixed inset-0 z-40 bg-scrim backdrop-blur-[6px] data-[state=open]:animate-fade-in" />
      <div className="pointer-events-none fixed inset-0 z-50 grid place-items-center overflow-y-auto p-4">
        <RDialog.Content
          data-section={section}
          ref={inner?.content}
          onEscapeKeyDown={onEscape}
          onInteractOutside={outside}
          // A submit the form refused shows its field, wherever it is.
          onSubmit={() => errors?.revealInvalid()}
          // Start in the first field rather than on the close button. Radix
          // radios and checkboxes add hidden inputs (tabindex -1) to forms;
          // skip those.
          onOpenAutoFocus={(event) => {
            returnFocus.remember();
            const field = (event.currentTarget as HTMLElement).querySelector<HTMLElement>(
              'input:not([type=hidden]):not([disabled]):not([tabindex="-1"]), textarea, select',
            );
            if (field) {
              event.preventDefault();
              field.focus();
            }
          }}
          onCloseAutoFocus={returnFocus.restore}
          // `overflow-clip`, not `overflow-hidden`: the glow is wider than the
          // dialog, and a scroll container could be scrolled sideways by a click.
          className={cn(
            'pointer-events-auto relative flex max-h-[calc(100vh-32px)] w-full max-w-[620px] flex-col overflow-clip rounded-[22px] border border-line-strong dialog-surface text-fg shadow-dialog outline-none data-[state=open]:animate-dialog-in',
            className,
          )}
        >
          <div
            aria-hidden="true"
            className="soft-glow absolute -top-[225px] left-1/2 h-[450px] w-[630px] -translate-x-1/2 [--glow-color:color-mix(in_srgb,var(--accent-2)_27%,transparent)]"
          />
          {children}
        </RDialog.Content>
      </div>
    </RDialog.Portal>
  );
}

/**
 * Radix returns focus to a `Dialog.Trigger`; dialogs here open from plain
 * buttons, menus and shortcuts, so remember what had focus when one opened
 * (Radix calls `onOpenAutoFocus` before moving focus) and go back to it.
 */
export function useReturnFocus() {
  const element = useRef<HTMLElement | null>(null);
  return {
    remember: () => {
      const active = document.activeElement;
      element.current = active instanceof HTMLElement && active !== document.body ? active : null;
    },
    restore: (event: Event) => {
      const target = element.current;
      if (!target?.isConnected) return;
      event.preventDefault();
      target.focus();
    },
  };
}

interface DialogHeaderProps {
  icon?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  /** `false` hides the close button, for a step that must be finished. */
  closable?: boolean;
}

export function DialogHeader({ icon, title, description, closable = true }: DialogHeaderProps) {
  const { t } = useTranslation();
  return (
    <header className="relative flex items-start gap-3.5 px-6 pt-[22px] pb-4">
      {icon}
      <div className="min-w-0 flex-1">
        <RDialog.Title className="text-[19px] leading-[26px] font-semibold tracking-[-0.02em]">
          {title}
        </RDialog.Title>
        {description ? (
          <RDialog.Description className="mt-0.5 text-[12.5px] text-muted">
            {description}
          </RDialog.Description>
        ) : (
          <RDialog.Description className="sr-only">{title}</RDialog.Description>
        )}
      </div>
      {closable ? (
        <RDialog.Close asChild>
          <IconButton
            label={t('common.close')}
            icon={<X className="size-4" />}
            variant="secondary"
          />
        </RDialog.Close>
      ) : null}
    </header>
  );
}

/** How far the fade at a scrolled edge reaches. */
const FADE = '28px';

export function DialogBody({ className, children }: { className?: string; children: ReactNode }) {
  const body = useRef<HTMLDivElement>(null);
  const { above, below } = useScrollEdges(body);
  // Scroll bars hide on macOS until used: a faded edge says there is more.
  // A mask reads only alpha: any opaque colour keeps the content as it is.
  const solid = 'rgb(var(--accent-rgb))';
  const mask =
    above || below
      ? `linear-gradient(to bottom, ${above ? 'transparent' : solid}, ${solid} ${above ? FADE : '0px'}, ${solid} calc(100% - ${below ? FADE : '0px'}), ${below ? 'transparent' : solid})`
      : undefined;
  return (
    <div
      ref={body}
      data-more-above={above || undefined}
      data-more-below={below || undefined}
      style={mask ? { maskImage: mask, WebkitMaskImage: mask } : undefined}
      className={cn(
        'relative flex min-h-0 flex-col gap-[18px] overflow-y-auto px-6 pt-1 pb-5',
        className,
      )}
    >
      {children}
    </div>
  );
}

/**
 * Whether `ref` can scroll up and down from where it is, kept as it
 * scrolls, resizes and its content changes.
 */
function useScrollEdges(ref: RefObject<HTMLElement | null>) {
  const [edges, setEdges] = useState({ above: false, below: false });
  useLayoutEffect(() => {
    const element = ref.current;
    if (!element) return;
    const update = () => {
      const above = element.scrollTop > 1;
      const below = element.scrollTop + element.clientHeight < element.scrollHeight - 1;
      setEdges((now) => (now.above === above && now.below === below ? now : { above, below }));
    };
    update();
    element.addEventListener('scroll', update, { passive: true });
    const sizes = typeof ResizeObserver === 'function' ? new ResizeObserver(update) : null;
    const watch = () => {
      if (!sizes) return;
      sizes.disconnect();
      sizes.observe(element);
      for (const child of element.children) sizes.observe(child);
    };
    watch();
    const changes =
      typeof MutationObserver === 'function'
        ? new MutationObserver(() => {
            watch();
            update();
          })
        : null;
    changes?.observe(element, { childList: true, subtree: true });
    return () => {
      element.removeEventListener('scroll', update);
      sizes?.disconnect();
      changes?.disconnect();
    };
  }, [ref]);
  return edges;
}

/** The dialog's buttons, and above them what its last command failed with. */
export function DialogFooter({ children }: { children: ReactNode }) {
  const inner = useContext(InnerContext);
  const footer = inner?.footer;
  useEffect(() => footer?.(), [footer]);
  const failure = inner?.failure;
  return (
    <>
      {failure ? (
        // An alert put on screen is read out as it comes.
        <div
          role="alert"
          className="relative mx-6 mb-3 flex items-start gap-2.5 rounded-xl border border-critical-solid/30 bg-critical-solid/[0.08] px-3 py-2.5 text-[12.5px] text-critical"
        >
          <AlertTriangle aria-hidden="true" className="mt-px size-4 shrink-0" strokeWidth={2} />
          <div className="min-w-0 flex-1">
            <p className="font-medium">{failure.text}</p>
            {failure.detail ? (
              <p className="selectable mt-0.5 break-words text-fg-2">{failure.detail}</p>
            ) : null}
          </div>
        </div>
      ) : null}
      <footer className="relative flex flex-wrap items-center justify-end gap-2.5 border-t border-ink/[0.07] px-6 pt-3.5 pb-[18px]">
        {children}
      </footer>
    </>
  );
}
