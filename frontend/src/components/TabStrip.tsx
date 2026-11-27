import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";

/** The top bar's tabs. When they don't all fit, arrows at either end scroll them, and the selected
 *  tab is kept in view. */
export function TabStrip({ children, selected }: { children: ReactNode; selected: string }) {
  const ref = useRef<HTMLElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });

  const measure = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const left = el.scrollLeft > 1;
    const right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    setEdges((e) => (e.left === left && e.right === right ? e : { left, right }));
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    el.addEventListener("scroll", measure, { passive: true });
    return () => { ro.disconnect(); el.removeEventListener("scroll", measure); };
  }, [measure]);

  useEffect(() => {
    const tab = ref.current?.querySelector<HTMLElement>('[aria-selected="true"]');
    tab?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
  }, [selected]);

  const scroll = (dir: -1 | 1) => {
    const el = ref.current;
    if (el) el.scrollBy({ left: dir * Math.max(120, el.clientWidth * 0.7), behavior: "smooth" });
  };

  return (
    <div className={`tab-strip${edges.left ? " more-left" : ""}${edges.right ? " more-right" : ""}`}>
      <button type="button" className="tab-arrow left" aria-label="Show earlier tabs" tabIndex={-1}
              hidden={!edges.left} onClick={() => scroll(-1)}>‹</button>
      <nav className="tabs" role="tablist" aria-label="View" ref={ref}>{children}</nav>
      <button type="button" className="tab-arrow right" aria-label="Show more tabs" tabIndex={-1}
              hidden={!edges.right} onClick={() => scroll(1)}>›</button>
    </div>
  );
}
