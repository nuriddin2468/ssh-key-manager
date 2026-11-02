import { useId } from 'react';
import { cn } from '@/lib/cn';

/** Keyhole with an orbiting satellite on the brand gradient. */
export function Logo({ size = 40, className }: { size?: number; className?: string }) {
  const gloss = useId();
  return (
    <span
      aria-hidden="true"
      className={cn('relative grid shrink-0 place-items-center overflow-hidden', className)}
      style={{
        width: size,
        height: size,
        borderRadius: size * 0.3,
        background: 'linear-gradient(150deg, #2DD4BF 0%, #4F46E5 56%, #9333EA 100%)',
        boxShadow:
          '0 10px 24px -8px rgb(79 70 229 / 0.8), inset 0 1px 0 rgb(255 255 255 / 0.45), inset 0 -8px 14px rgb(15 10 50 / 0.35)',
      }}
    >
      <svg
        aria-hidden="true"
        width={size * 0.7}
        height={size * 0.7}
        viewBox="0 0 24 24"
        className="relative"
      >
        <defs>
          <radialGradient id={gloss} cx="0.2" cy="0.05" r="0.7">
            <stop offset="0" stopColor="#fff" stopOpacity="0.35" />
            <stop offset="1" stopColor="#fff" stopOpacity="0" />
          </radialGradient>
        </defs>
        <ellipse
          cx="12"
          cy="13.2"
          rx="10.4"
          ry="3.8"
          transform="rotate(-18 12 13.2)"
          fill="none"
          stroke="rgb(255 255 255 / 0.45)"
          strokeWidth={size > 60 ? 0.7 : 1}
        />
        <circle cx="12" cy="9.2" r="4.1" fill="#fff" />
        <path
          d="M10.4 11.6 L9.1 18.4 Q8.9 19.7 10.2 19.7 H13.8 Q15.1 19.7 14.9 18.4 L13.6 11.6 Z"
          fill="#fff"
        />
        <circle cx="12" cy="9.2" r="1.5" fill="#4F46E5" opacity="0.9" />
        <circle cx="20.6" cy="9.7" r="1.4" fill="#99F6E4" />
        <rect x="0" y="0" width="24" height="24" fill={`url(#${gloss})`} />
      </svg>
    </span>
  );
}
