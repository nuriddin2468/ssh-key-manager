// Dragging an entry onto a group. Built on pointer events rather than HTML
// drag and drop, which the desktop shell takes over for dropped files.

import { type PointerEvent, type RefObject, useEffect, useRef, useState } from 'react';
import type { EntryRow } from './draft';

/** How far the pointer moves before a press on a handle becomes a drag. */
const THRESHOLD = 4;
/** Distance from the scroll area's top or bottom where a drag scrolls it. */
const EDGE = 56;

export interface EntryDrag {
  row: EntryRow;
  /** The `data-drop` value of the target under the pointer. */
  target: string | null;
  /** Where the drag began, for the ghost's first frame. */
  x: number;
  y: number;
}

/**
 * Drags rows between drop targets: elements with a `data-drop` attribute.
 * The ghost follows the pointer outside React, so rows don't re-render on
 * every move; Escape cancels.
 */
export function useEntryDrag(
  scroller: RefObject<HTMLElement | null>,
  onDrop: (row: EntryRow, target: string) => void,
) {
  const [drag, setDrag] = useState<EntryDrag | null>(null);
  const ghostEl = useRef<HTMLDivElement | null>(null);
  const last = useRef({ x: 0, y: 0 });
  const follow = (el: HTMLElement | null) =>
    el?.style.setProperty(
      'transform',
      `translate(${last.current.x + 14}px, ${last.current.y + 12}px)`,
    );
  // The ghost mounts a render after the drag starts; it picks up the pointer from there.
  const ghost = (el: HTMLDivElement | null) => {
    ghostEl.current = el;
    follow(el);
  };
  const drop = useRef(onDrop);
  const cancel = useRef<(() => void) | null>(null);
  useEffect(() => {
    drop.current = onDrop;
  });
  useEffect(() => () => cancel.current?.(), []);

  const start = (event: PointerEvent, row: EntryRow) => {
    if (event.button !== 0 || cancel.current) return;
    // Keeps the press from selecting text.
    event.preventDefault();
    const origin = { x: event.clientX, y: event.clientY };
    let point = origin;
    // Where the drag began; React renders the ghost there, moves go around it.
    let first = origin;
    let active = false;
    let target: string | null = null;
    let frame = 0;

    const place = () => {
      last.current = point;
      follow(ghostEl.current);
      const over =
        document.elementFromPoint(point.x, point.y)?.closest<HTMLElement>('[data-drop]')?.dataset
          .drop ?? null;
      if (over !== target) {
        target = over;
        setDrag({ row, target, x: first.x, y: first.y });
      }
    };
    const scroll = () => {
      const area = scroller.current;
      if (area) {
        const box = area.getBoundingClientRect();
        const step =
          point.y < box.top + EDGE
            ? point.y - (box.top + EDGE)
            : point.y > box.bottom - EDGE
              ? point.y - (box.bottom - EDGE)
              : 0;
        if (step !== 0) {
          area.scrollTop += step / 4;
          place();
        }
      }
      frame = requestAnimationFrame(scroll);
    };
    const move = (e: globalThis.PointerEvent) => {
      point = { x: e.clientX, y: e.clientY };
      if (!active) {
        if (Math.hypot(point.x - origin.x, point.y - origin.y) < THRESHOLD) return;
        active = true;
        first = point;
        document.body.classList.add('dragging');
        setDrag({ row, target: null, x: first.x, y: first.y });
        frame = requestAnimationFrame(scroll);
      }
      place();
    };
    const finish = (dropped: boolean) => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', stop);
      window.removeEventListener('keydown', key, true);
      cancelAnimationFrame(frame);
      document.body.classList.remove('dragging');
      cancel.current = null;
      setDrag(null);
      if (dropped && active && target) drop.current(row, target);
    };
    const up = () => finish(true);
    const stop = () => finish(false);
    const key = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      // Escape ends the drag only, not the page's dialogs or search.
      e.preventDefault();
      e.stopPropagation();
      finish(false);
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    window.addEventListener('pointercancel', stop);
    window.addEventListener('keydown', key, true);
    cancel.current = stop;
  };

  return { drag, ghost, start };
}
