/** The AFR mark: a recorder's ring around a live dot. */
export const Logo = ({ size = 28 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 28 28" aria-hidden className="shrink-0">
    <rect width="28" height="28" rx="7" className="fill-fg" />
    <circle cx="14" cy="14" r="6" fill="none" strokeWidth="2" className="stroke-canvas" />
    <circle cx="14" cy="14" r="2" className="fill-accent" />
  </svg>
);
