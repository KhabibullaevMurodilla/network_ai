// Server file so the static (local-mode) export has one placeholder page; the real
// value arrives as ?id= (see lib/links.ts). Other builds still render any value on demand.
export function generateStaticParams() { return [{ id: "_" }]; }
export default function Layout({ children }: { children: React.ReactNode }) { return children; }
