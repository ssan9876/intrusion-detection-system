/* Packet-list style table: sortable columns, one selected row, keyboard
   navigation, and per-cell "apply as filter" values for the context menu. */
import { esc } from "./util.js";

export class Table {
  /**
   * columns: [{ key, label, cls?, render(row) -> html, sort?(row) -> value,
   *             filter?(row) -> "field == value", title?(row) }]
   */
  constructor(el, { columns, rowKey, rowClass, onSelect, onActivate, empty, sort, ariaLabel }) {
    this.el = el;
    this.columns = columns;
    this.rowKey = rowKey;
    this.rowClass = rowClass || (() => "");
    this.onSelect = onSelect || (() => {});
    this.onActivate = onActivate || (() => {});
    this.empty = empty || (() => "Nothing to show");
    this.rows = [];
    this.view = [];
    this.selected = null;
    this.sort = sort || null; // { key, dir: 1 | -1 }
    this.follow = false;      // keep the newest row in view (packet list behaviour)

    el.classList.add("table-scroll");
    el.innerHTML = `<table class="grid" role="grid" aria-label="${esc(ariaLabel || "")}">
      <thead><tr>${columns.map((c) => `<th scope="col" class="${c.cls || ""}" data-key="${c.key}"
        aria-sort="none"><button type="button" class="th-btn">${esc(c.label)}<span class="sort-ind" aria-hidden="true"></span></button></th>`).join("")}</tr></thead>
      <tbody></tbody></table>`;
    this.tbody = el.querySelector("tbody");
    this.table = el.querySelector("table");
    this.table.tabIndex = 0;

    el.querySelector("thead").addEventListener("click", (e) => {
      const th = e.target.closest("th"); if (!th) return;
      const key = th.dataset.key;
      const col = columns.find((c) => c.key === key);
      if (col && col.onHeader) { col.onHeader(); this.render(); return; }
      if (!col || col.sort === false) return;
      this.sort = this.sort && this.sort.key === key
        ? (this.sort.dir === 1 ? { key, dir: -1 } : null)
        : { key, dir: 1 };
      this.render();
    });
    this.tbody.addEventListener("click", (e) => {
      if (e.target.closest("a,button,input,label")) return;
      const tr = e.target.closest("tr[data-key]"); if (!tr) return;
      this.select(tr.dataset.key, { focus: true });
    });
    this.tbody.addEventListener("dblclick", (e) => {
      const tr = e.target.closest("tr[data-key]"); if (tr) this.onActivate(this.byKey(tr.dataset.key));
    });
    this.table.addEventListener("keydown", (e) => this.key(e));
    this.el.addEventListener("scroll", () => {
      // following stops when the reader scrolls up, resumes at the bottom
      const atEnd = this.el.scrollTop + this.el.clientHeight >= this.el.scrollHeight - 4;
      if (this.followable) this.follow = atEnd;
    });
  }

  byKey(k) { return this.view.find((r) => String(this.rowKey(r)) === String(k)); }

  setRows(rows) { this.rows = rows; this.render(); }

  render() {
    let view = this.filterFn ? this.rows.filter(this.filterFn) : this.rows.slice();
    if (this.sort) {
      const col = this.columns.find((c) => c.key === this.sort.key);
      const val = col.sort || ((r) => r[col.key]);
      const d = this.sort.dir;
      view.sort((a, b) => {
        const x = val(a), y = val(b);
        return (x > y ? 1 : x < y ? -1 : 0) * d;
      });
    }
    this.view = view;
    this.el.querySelectorAll("th").forEach((th) => {
      const on = this.sort && this.sort.key === th.dataset.key;
      th.setAttribute("aria-sort", on ? (this.sort.dir === 1 ? "ascending" : "descending") : "none");
    });
    const sel = this.selected;
    if (!view.length) {
      this.tbody.innerHTML = `<tr class="empty-row"><td colspan="${this.columns.length}">${this.empty()}</td></tr>`;
      return;
    }
    const cols = this.columns;
    this.tbody.innerHTML = view.map((r) => {
      const k = String(this.rowKey(r));
      const cls = this.rowClass(r) + (k === sel ? " is-selected" : "");
      return `<tr data-key="${esc(k)}" class="${cls}" aria-selected="${k === sel}">${cols.map((c) => {
        const t = c.title ? ` title="${esc(c.title(r))}"` : "";
        return `<td class="${c.cls || ""}"${t}>${c.render(r)}</td>`;
      }).join("")}</tr>`;
    }).join("");
    if (this.follow) this.el.scrollTop = this.el.scrollHeight;
  }

  select(key, { focus = false, scroll = true, silent = false } = {}) {
    key = key == null ? null : String(key);
    const prev = this.tbody.querySelector("tr.is-selected");
    if (prev) { prev.classList.remove("is-selected"); prev.setAttribute("aria-selected", "false"); }
    this.selected = key;
    const tr = key != null ? this.tbody.querySelector(`tr[data-key="${CSS.escape(key)}"]`) : null;
    if (tr) {
      tr.classList.add("is-selected"); tr.setAttribute("aria-selected", "true");
      if (scroll) tr.scrollIntoView({ block: "nearest" });
    }
    if (focus) this.table.focus({ preventScroll: true });
    if (!silent) this.onSelect(key != null ? this.byKey(key) : null);
  }

  move(delta) {
    if (!this.view.length) return;
    const i = this.view.findIndex((r) => String(this.rowKey(r)) === this.selected);
    const j = i < 0 ? (delta > 0 ? 0 : this.view.length - 1)
      : Math.max(0, Math.min(this.view.length - 1, i + delta));
    this.select(this.rowKey(this.view[j]));
  }

  key(e) {
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const page = Math.max(1, Math.floor(this.el.clientHeight / 24) - 1);
    const map = { ArrowDown: 1, j: 1, ArrowUp: -1, k: -1, PageDown: page, PageUp: -page };
    if (e.key in map) { e.preventDefault(); this.move(map[e.key]); return; }
    if (e.key === "Home") { e.preventDefault(); this.move(-1e9); }
    if (e.key === "End") { e.preventDefault(); this.move(1e9); }
    if (e.key === "Enter" && this.selected != null) { e.preventDefault(); this.onActivate(this.byKey(this.selected)); }
  }

  /* The filter expression for the cell under a context-menu click. */
  cellFilter(target) {
    const td = target.closest("td"); const tr = target.closest("tr[data-key]");
    if (!td || !tr) return null;
    const col = this.columns[td.cellIndex];
    const row = this.byKey(tr.dataset.key);
    return col && col.filter && row ? { expr: col.filter(row), text: td.textContent.trim(), row } : null;
  }
}
