import { useRef, useState } from 'react';

/** How a card shows its rows, and what its "Show all" does. */
export interface Fold {
  /** Shows all rows, not the first `CARD_LIMIT`. */
  all: boolean;
  /** Its "Show all" was pressed last: focused again if the card moved columns. */
  refocus: boolean;
  onToggle: () => void;
}

/**
 * Which cards show all their rows, kept by card id on the page rather than in
 * each card: a card that moves to the other column (its rows changed) is a
 * new element there, and stays unfolded, with the focus back on its button.
 */
export function useFolds(): (id: string) => Fold {
  const [unfolded, setUnfolded] = useState<ReadonlySet<string>>(new Set());
  const toggled = useRef<string | null>(null);
  return (id) => ({
    all: unfolded.has(id),
    refocus: toggled.current === id,
    onToggle: () => {
      toggled.current = id;
      setUnfolded((current) => {
        const next = new Set(current);
        if (!next.delete(id)) next.add(id);
        return next;
      });
    },
  });
}
