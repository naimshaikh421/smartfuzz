import { resolveUrl } from "./api";

interface Props {
  base: string;
  url?: string | null;
  path?: string | null;
  redirect?: string | null;
}

export function UrlLink({ base, url, path, redirect }: Props) {
  const href = resolveUrl(base, url, path);
  if (!href) return <span className="muted">—</span>;

  const display = href;
  const redirectHref =
    redirect && (redirect.startsWith("http://") || redirect.startsWith("https://"))
      ? redirect
      : redirect
        ? resolveUrl(base, redirect, redirect)
        : null;

  return (
    <span className="url-cell">
      <a href={href} target="_blank" rel="noreferrer" className="url-link" title={href}>
        {display}
      </a>
      {redirectHref && redirectHref !== href && (
        <span className="redirect-hint">
          →{" "}
          <a href={redirectHref} target="_blank" rel="noreferrer" className="url-link muted-link">
            {redirectHref}
          </a>
        </span>
      )}
    </span>
  );
}
