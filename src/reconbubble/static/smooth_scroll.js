/* ReconBubble — global smooth wheel scrolling.
 *
 * Wheel events over an inner scrollable container (modals, side panels,
 * list boxes, output viewers, ...) are converted into rAF-driven eased
 * scrolling — the same glide-and-settle feel as the Services port popup.
 *
 * Native scrolling is preserved for:
 *   - the page body (only inner containers glide)
 *   - text inputs / textareas / selects / contenteditable
 *   - Ctrl/⌘+wheel (browser zoom)
 *   - elements inside a .no-smooth surface (Cytoscape graphs own their wheel)
 *
 * To revert: remove the <script> tag that loads this file from base.html.
 */
(function () {
  const EASE = 0.22;
  const anims = new WeakMap();
  const overflowCache = new WeakMap();

  function overflowY(el) {
    let v = overflowCache.get(el);
    if (v === undefined) {
      v = getComputedStyle(el).overflowY;
      overflowCache.set(el, v);
    }
    return v;
  }

  // Innermost scrollable ancestor of `target` (excluding the page body).
  // Stops the walk entirely if a .no-smooth surface is in between.
  function pickBox(target) {
    let el = target;
    while (el && el !== document.documentElement) {
      if (el.classList && el.classList.contains("no-smooth")) return null;
      if (
        el !== document.body &&
        el.scrollHeight > el.clientHeight &&
        (overflowY(el) === "auto" || overflowY(el) === "scroll")
      ) {
        return el;
      }
      el = el.parentElement;
    }
    return null;
  }

  function animate(box) {
    let st = anims.get(box);
    if (!st) {
      st = { target: box.scrollTop, raf: 0 };
      anims.set(box, st);
    }
    if (st.raf) return;
    st.raf = requestAnimationFrame(function step() {
      if (!box.isConnected) { st.raf = 0; return; }
      const max = Math.max(0, box.scrollHeight - box.clientHeight);
      st.target = Math.max(0, Math.min(max, st.target));
      const diff = st.target - box.scrollTop;
      if (Math.abs(diff) < 0.5) {
        box.scrollTop = st.target;
        st.raf = 0;
        return;
      }
      box.scrollTop += diff * EASE;
      st.raf = requestAnimationFrame(step);
    });
  }

  document.addEventListener("wheel", (e) => {
    if (e.ctrlKey || e.metaKey) return;
    const t = e.target;
    if (!t || !t.closest) return;
    if (t.closest("input, textarea, select, [contenteditable], .no-smooth")) return;
    const box = pickBox(t);
    if (!box) return;
    e.preventDefault();
    let delta = e.deltaY;
    if (e.deltaMode === 1) delta *= 16;
    else if (e.deltaMode === 2) delta *= box.clientHeight;
    let st = anims.get(box);
    if (!st) {
      st = { target: box.scrollTop, raf: 0 };
      anims.set(box, st);
    }
    const max = Math.max(0, box.scrollHeight - box.clientHeight);
    st.target = Math.max(0, Math.min(max, st.target + delta));
    animate(box);
  }, { passive: false });
})();
