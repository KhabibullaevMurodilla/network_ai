"use client";
import { useParams, useSearchParams } from "next/navigation";

// Local mode is a static export, which cannot have real dynamic routes, so the
// detail pages live at a placeholder segment ("_") and take the id as ?id=.
const LOCAL = process.env.NEXT_PUBLIC_LOCAL_MODE === "1";

export const anomalyHref = (id: number | string) => (LOCAL ? `/dashboard/anomalies/_/?id=${id}` : `/dashboard/anomalies/${id}`);
export const incidentHref = (id: string) => (LOCAL ? `/dashboard/incidents/_/?id=${encodeURIComponent(id)}` : `/dashboard/incidents/${id}`);
export const entityHref = (source: string) => (LOCAL ? `/dashboard/entities/_/?source=${encodeURIComponent(source)}` : `/dashboard/entities/${encodeURIComponent(source)}`);

/** The id/source of a detail page: ?name= in local mode, the route segment otherwise.
 *  (LOCAL is fixed at build time, so the same hook is always called.) */
export function useRouteValue(name: string): string {
  const params = useParams<Record<string, string>>();
  const search = useSearchParams();
  return LOCAL ? search.get(name) ?? "" : params?.[name] ?? "";
}
