import { useEffect, useState } from "react";
export default function usePolling(fn, deps, intervalMs = 1500, stopWhen = () => false) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    let alive = true, timer;
    const tick = async () => {
      try {
        const d = await fn();
        if (!alive) return;
        setData(d); setError(null);
        if (stopWhen(d)) return;
      } catch (e) { if (alive) setError(e); }
      timer = setTimeout(tick, intervalMs);
    };
    tick();
    return () => { alive = false; clearTimeout(timer); };
    // eslint-disable-next-line
  }, deps);
  return { data, error };
}
