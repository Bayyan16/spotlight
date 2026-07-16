// Minimal single-color line icons — inline SVG so we don't pull a library.
// Matches inspo-2 (Devin) sidebar iconography.
type IconProps = { className?: string; size?: number };

const wrap = (path: React.ReactNode, size = 16) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.75"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    {path}
  </svg>
);

export const IconHome = ({ size = 16 }: IconProps) =>
  wrap(<><path d="M3 10.5 12 3l9 7.5" /><path d="M5 9v11h14V9" /></>, size);

export const IconSweep = ({ size = 16 }: IconProps) =>
  wrap(<><circle cx="12" cy="12" r="8" /><path d="M12 6v6l4 2" /></>, size);

export const IconFindings = ({ size = 16 }: IconProps) =>
  wrap(<><path d="M4 5h16" /><path d="M4 12h16" /><path d="M4 19h10" /></>, size);

export const IconExploitPath = ({ size = 16 }: IconProps) =>
  wrap(
    <>
      <circle cx="5" cy="6" r="2" />
      <circle cx="19" cy="6" r="2" />
      <circle cx="12" cy="18" r="2" />
      <path d="M6.6 7.5 10.9 16.5" />
      <path d="M17.4 7.5 13.1 16.5" />
    </>,
    size
  );

export const IconWarden = ({ size = 16 }: IconProps) =>
  wrap(<><path d="M12 3 4 6v6c0 4.5 3 8 8 9 5-1 8-4.5 8-9V6l-8-3Z" /></>, size);

export const IconAttestation = ({ size = 16 }: IconProps) =>
  wrap(
    <>
      <path d="M6 3h9l4 4v14H6z" />
      <path d="M15 3v4h4" />
      <path d="M9 13h6" />
      <path d="M9 17h4" />
    </>,
    size
  );

export const IconSettings = ({ size = 16 }: IconProps) =>
  wrap(
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.4.9a7 7 0 0 0-2.1-1.2L14 3h-4l-.4 2.6A7 7 0 0 0 7.5 6.8L5 5.9l-2 3.4 2 1.5A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.5 2 3.4 2.4-.9c.6.5 1.3.9 2.1 1.2L10 21h4l.4-2.6c.8-.3 1.5-.7 2.1-1.2l2.4.9 2-3.4-2-1.5c.1-.4.1-.8.1-1.2Z" />
    </>,
    size
  );

export const IconPlay = ({ size = 14 }: IconProps) =>
  wrap(<path d="M6 4l14 8-14 8V4z" />, size);

export const IconChevron = ({ size = 12 }: IconProps) =>
  wrap(<path d="M9 6l6 6-6 6" />, size);

export const IconCheck = ({ size = 12 }: IconProps) =>
  wrap(<path d="M4 12l5 5L20 6" />, size);

export const IconDot = ({ size = 8 }: IconProps) =>
  wrap(<circle cx="12" cy="12" r="6" fill="currentColor" />, size);

export const IconAlert = ({ size = 14 }: IconProps) =>
  wrap(
    <>
      <path d="M12 3 2 21h20L12 3z" />
      <path d="M12 10v5" />
      <path d="M12 18h.01" />
    </>,
    size
  );
