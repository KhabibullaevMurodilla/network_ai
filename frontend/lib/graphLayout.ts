export const W = 960;
export const H = 560;

/** Small dependency-free force-directed layout (settled once, not animated). */
export function layout<T extends { id: string }>(nodes: T[], edges: { source: string; target: string }[]): (T & { x: number; y: number })[] {

  const n = nodes.length;
  if (n === 0) return [];
  const idx = new Map(nodes.map((node, i) => [node.id, i]));
  const pos = nodes.map((_, i) => {
    const angle = (i / n) * Math.PI * 2;
    const r = Math.min(W, H) * 0.3;
    return { x: W / 2 + r * Math.cos(angle), y: H / 2 + r * Math.sin(angle) };
  });

  const edgePairs = edges
    .map((e) => [idx.get(e.source), idx.get(e.target)] as [number | undefined, number | undefined])
    .filter((p): p is [number, number] => p[0] !== undefined && p[1] !== undefined);

  const REPULSION = 2800;
  const SPRING_LEN = 110;
  const SPRING_K = 0.02;
  const CENTER_K = 0.01;
  const ITERATIONS = n > 80 ? 80 : 220;

  for (let iter = 0; iter < ITERATIONS; iter++) {
    const fx = new Array(n).fill(0);
    const fy = new Array(n).fill(0);

    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let dx = pos[i].x - pos[j].x;
        let dy = pos[i].y - pos[j].y;
        let distSq = dx * dx + dy * dy || 0.01;
        const force = REPULSION / distSq;
        const dist = Math.sqrt(distSq);
        dx /= dist;
        dy /= dist;
        fx[i] += dx * force;
        fy[i] += dy * force;
        fx[j] -= dx * force;
        fy[j] -= dy * force;
      }
      fx[i] += (W / 2 - pos[i].x) * CENTER_K;
      fy[i] += (H / 2 - pos[i].y) * CENTER_K;
    }

    for (const [a, b] of edgePairs) {
      const dx = pos[b].x - pos[a].x;
      const dy = pos[b].y - pos[a].y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const stretch = dist - SPRING_LEN;
      const fxn = (dx / dist) * stretch * SPRING_K;
      const fyn = (dy / dist) * stretch * SPRING_K;
      fx[a] += fxn;
      fy[a] += fyn;
      fx[b] -= fxn;
      fy[b] -= fyn;
    }

    for (let i = 0; i < n; i++) {
      pos[i].x = Math.min(W - 20, Math.max(20, pos[i].x + fx[i]));
      pos[i].y = Math.min(H - 20, Math.max(20, pos[i].y + fy[i]));
    }
  }

  return nodes.map((node, i) => ({ ...node, x: pos[i].x, y: pos[i].y }));
}

