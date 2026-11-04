/* v1 - click a column header to sort its table alphabetically.
   Numeric-aware (IPs, ports, and numbers compare as numbers).
   Click again to reverse direction; clicking a different column
   resets to ascending. Blank cells always sort last.
   Opt out per column or per table with data-nosort. */
(function () {
  function columnCount(table) {
    const headRow = table.tHead && table.tHead.rows[0];
    return headRow ? headRow.cells.length : 0;
  }

  function isSortableTh(th) {
    if (th.hasAttribute("data-nosort")) return false;
    const table = th.closest("table");
    if (!table || table.hasAttribute("data-nosort")) return false;
    if (th.querySelector("input, button, select, textarea")) return false;
    if (th.textContent.trim() === "") return false;
    return true;
  }

  function cellText(row, idx) {
    const cell = row.cells[idx];
    return cell ? cell.textContent.trim() : "";
  }

  /* A data row plus any immediately-following continuation rows
     (e.g. the hidden URL expander rows in the subdomains table, or
     a full-width "no results" message) move together as one unit. */
  function rowGroup(table, tr) {
    const cols = columnCount(table);
    const group = [tr];
    let next = tr.nextElementSibling;
    while (next && next.tagName === "TR") {
      const firstCell = next.cells[0];
      const isContinuation =
        next.classList.contains("url-row") ||
        (firstCell && cols > 0 && firstCell.colSpan === cols && next.cells.length === 1);
      if (!isContinuation) break;
      group.push(next);
      next = next.nextElementSibling;
    }
    return group;
  }

  function mark(table, th, dir) {
    th.parentElement
      .querySelectorAll("th.sort-asc, th.sort-desc")
      .forEach((h) => h.classList.remove("sort-asc", "sort-desc"));
    th.classList.add(dir === "asc" ? "sort-asc" : "sort-desc");
  }

  document.addEventListener("click", (e) => {
    const th = e.target.closest ? e.target.closest("th") : null;
    if (!th || !isSortableTh(th)) return;
    const table = th.closest("table");
    const tbody = table.tBodies && table.tBodies[0];
    if (!tbody) return;
    const col = Array.prototype.indexOf.call(th.parentElement.cells, th);
    if (col < 0) return;

    const prev = table.__sortState || { col: -1, dir: "asc" };
    const dir = prev.col === col && prev.dir === "asc" ? "desc" : "asc";
    table.__sortState = { col, dir };

    const groups = [];
    let node = tbody.firstChild;
    while (node) {
      if (node.tagName === "TR") {
        const group = rowGroup(table, node);
        groups.push(group);
        /* jump past the whole group so continuation rows are not
           collected a second time as their own group */
        node = group[group.length - 1].nextElementSibling;
      } else {
        node = node.nextSibling;
      }
    }
    groups.sort((ga, gb) => {
      const a = cellText(ga[0], col);
      const b = cellText(gb[0], col);
      if (a === b) return 0;
      if (a === "") return 1; /* blank cells always last */
      if (b === "") return -1;
      return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
    });
    const ordered = dir === "asc" ? groups : groups.slice().reverse();
    ordered.forEach((group) => group.forEach((row) => tbody.appendChild(row)));
    mark(table, th, dir);
  });

  /* Hover affordance: tag sortable headers. Runs immediately (end-of-body
     script, DOM is ready) and again on DOMContentLoaded to pick up tables
     built by page scripts. Delegation above makes clicking work even for
     tables created later, so this only affects the pointer/hover hint. */
  function markSortable() {
    document.querySelectorAll("th:not([data-sortable])").forEach((th) => {
      if (isSortableTh(th)) th.setAttribute("data-sortable", "");
    });
  }
  markSortable();
  document.addEventListener("DOMContentLoaded", markSortable);
  /* Tables built after DOMContentLoaded (e.g. the upload log) get the
     affordance as soon as they appear. */
  let markQueued = false;
  const markObserver = new MutationObserver(() => {
    if (markQueued) return;
    markQueued = true;
    requestAnimationFrame(() => {
      markQueued = false;
      markSortable();
    });
  });
  markObserver.observe(document.documentElement, { childList: true, subtree: true });
})();
