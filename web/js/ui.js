/* Shared UI pieces: context menu, toasts, confirm dialog, splitters, and the
   dissection tree. */
import { $, esc, icon, store } from "./util.js";

// ---------- context menu ----------
const menu = $("ctx-menu");
let menuItems = [];

export function contextMenu(x, y, items) {
  menuItems = items.filter(Boolean);
  if (!menuItems.length) return;
  menu.innerHTML = menuItems.map((it, i) => {
    if (it === "-") return "<hr>";
    if (it.label && !it.run) return `<div class="ctx-label">${esc(it.label)}</div>`;
    return `<button type="button" role="menuitem" data-i="${i}">${it.icon ? icon(it.icon) : ""}<span>${esc(it.text)}</span>${it.code ? `<code>${esc(it.code)}</code>` : ""}</button>`;
  }).join("");
  menu.hidden = false;
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.min(x, innerWidth - r.width - 6) + "px";
  menu.style.top = Math.min(y, innerHeight - r.height - 6) + "px";
  menu.querySelector("button")?.focus();
}
export function closeMenu() { menu.hidden = true; }
menu.addEventListener("click", (e) => {
  const b = e.target.closest("button[data-i]"); if (!b) return;
  const it = menuItems[+b.dataset.i]; closeMenu(); it.run();
});
menu.addEventListener("keydown", (e) => {
  const btns = [...menu.querySelectorAll("button")];
  const i = btns.indexOf(document.activeElement);
  if (e.key === "ArrowDown") { e.preventDefault(); btns[(i + 1) % btns.length].focus(); }
  if (e.key === "ArrowUp") { e.preventDefault(); btns[(i - 1 + btns.length) % btns.length].focus(); }
  if (e.key === "Escape") { e.preventDefault(); closeMenu(); }
});
document.addEventListener("pointerdown", (e) => { if (!menu.hidden && !menu.contains(e.target)) closeMenu(); });
window.addEventListener("blur", closeMenu);
window.addEventListener("resize", closeMenu);

// ---------- toasts ----------
export function toast({ sev = "info", title, body = "", onClick, ms = 6000 }) {
  const box = $("toasts");
  const el = document.createElement("div");
  el.className = `toast t-${sev}`;
  el.setAttribute("role", "status");
  const mark = sev === "info"
    ? icon("bell", "sev-mark")
    : `<svg class="sev-mark sev-${esc(sev)}" aria-hidden="true" style="color:var(--sev-${esc(sev)}-mark)"><use href="#sev-${esc(sev)}"/></svg>`;
  el.innerHTML = `${mark}<div class="toast-title">${esc(title)}</div><div class="toast-body">${esc(body)}</div>`;
  el.addEventListener("click", () => { if (onClick) onClick(); dismiss(); });
  box.appendChild(el);
  while (box.children.length > 2) box.firstChild.remove();
  const t = setTimeout(dismiss, ms);
  function dismiss() { clearTimeout(t); el.classList.add("is-gone"); setTimeout(() => el.remove(), 320); }
}

// ---------- confirm ----------
export function confirmDialog({ title, body, ok = "Confirm", danger = false }) {
  const dlg = $("dlg-confirm");
  $("dlg-confirm-title").textContent = title;
  $("dlg-confirm-body").textContent = body;
  const okBtn = $("dlg-confirm-ok");
  okBtn.textContent = ok;
  okBtn.classList.toggle("btn-danger", danger);
  dlg.returnValue = "";
  dlg.showModal();
  okBtn.focus();
  return new Promise((resolve) => {
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true });
  });
}

// ---------- splitters ----------
/* Panes are grid rows sized by --r0..--rN fr values; dragging a splitter
   moves fr between the two rows it separates. Sizes persist per layout. */
export function splitters(container, key, defaults) {
  const rows = (store("split." + key) || defaults).slice();
  const apply = () => rows.forEach((v, i) => container.style.setProperty(`--r${i}`, v + "fr"));
  apply();
  const bars = [...container.querySelectorAll(":scope > .splitter")];
  bars.forEach((bar, i) => {
    const before = bar.previousElementSibling, after = bar.nextElementSibling;
    const shift = (dy) => {
      const hb = before.getBoundingClientRect().height, ha = after.getBoundingClientRect().height;
      const total = rows[i] + rows[i + 1], px = hb + ha;
      const nb = Math.max(60, Math.min(px - 60, hb + dy));
      rows[i] = (nb / px) * total; rows[i + 1] = total - rows[i];
      apply();
    };
    bar.addEventListener("pointerdown", (e) => {
      e.preventDefault();
      bar.setPointerCapture(e.pointerId);
      bar.classList.add("is-dragging");
      let last = e.clientY;
      const move = (ev) => { shift(ev.clientY - last); last = ev.clientY; };
      const up = () => {
        bar.classList.remove("is-dragging");
        bar.removeEventListener("pointermove", move);
        store("split." + key, rows);
      };
      bar.addEventListener("pointermove", move);
      bar.addEventListener("pointerup", up, { once: true });
      bar.addEventListener("pointercancel", up, { once: true });
    });
    bar.addEventListener("keydown", (e) => {
      const d = { ArrowUp: -24, ArrowDown: 24 }[e.key];
      if (!d) return;
      e.preventDefault(); shift(d); store("split." + key, rows);
    });
    bar.addEventListener("dblclick", () => {
      rows.splice(0, rows.length, ...defaults); apply(); store("split." + key, rows);
    });
  });
}

// ---------- dissection tree ----------
/* node: { id, label: html, val?: html, kids?: node[], open?: bool, head?: bool,
           filter?: "expr", bytes?: [start, end], act?: html, data?: any } */
export class Tree {
  constructor(el, { onSelect, onHover, onContext, persistKey } = {}) {
    this.el = el;
    this.onSelect = onSelect || (() => {});
    this.onHover = onHover || (() => {});
    this.onContext = onContext || (() => {});
    this.persistKey = persistKey;
    this.openState = store("tree." + persistKey) || {};
    this.nodes = new Map();
    this.selected = null;
    el.tabIndex = 0;
    el.addEventListener("click", (e) => {
      const tog = e.target.closest(".tn-toggle");
      const li = e.target.closest(".tn"); if (!li) return;
      if (tog) { this.toggle(li.dataset.id); return; }
      if (e.target.closest("a,button")) return;
      this.select(li.dataset.id);
    });
    el.addEventListener("dblclick", (e) => {
      const li = e.target.closest(".tn"); if (li && this.nodes.get(li.dataset.id)?.kids) this.toggle(li.dataset.id);
    });
    el.addEventListener("pointerover", (e) => {
      const li = e.target.closest(".tn"); this.onHover(li ? this.nodes.get(li.dataset.id) : null);
    });
    el.addEventListener("pointerleave", () => this.onHover(null));
    el.addEventListener("contextmenu", (e) => {
      const li = e.target.closest(".tn"); if (!li) return;
      e.preventDefault();
      this.select(li.dataset.id);
      this.onContext(this.nodes.get(li.dataset.id), e);
    });
    el.addEventListener("keydown", (e) => this.key(e));
  }

  render(nodes, emptyHtml = "") {
    this.nodes.clear();
    if (!nodes || !nodes.length) { this.el.innerHTML = emptyHtml; return; }
    const walk = (list, d) => `<ul class="tn" role="${d ? "group" : "none"}">${list.map((n) => {
      this.nodes.set(n.id, n);
      const has = n.kids && n.kids.length;
      const open = has ? (this.openState[n.id] ?? n.open ?? false) : undefined;
      const sel = n.id === this.selected;
      return `<li class="tn${n.head ? " tn-head" : ""}" role="treeitem" data-id="${esc(n.id)}"
        ${has ? `aria-expanded="${open}"` : ""} aria-selected="${sel}">
        <div class="tn-row${sel ? " is-selected" : ""}" style="--d:${d}">
          ${has ? `<button type="button" class="tn-toggle" tabindex="-1" aria-label="Expand">${icon("chev")}</button>` : `<span class="tn-leaf"></span>`}
          <span class="tn-label">${n.label}${n.val != null ? `: <span class="tn-val${n.mono ? " mono" : ""}">${n.val}</span>` : ""}</span>${n.act || ""}
        </div>
        ${has ? `<div class="tn-kids">${walk(n.kids, d + 1)}</div>` : ""}
      </li>`;
    }).join("")}</ul>`;
    this.el.innerHTML = walk(nodes, 0);
    if (this.selected && !this.nodes.has(this.selected)) this.selected = null;
  }

  li(id) { return this.el.querySelector(`.tn[data-id="${CSS.escape(id)}"]`); }

  toggle(id, force) {
    const li = this.li(id); if (!li || !li.hasAttribute("aria-expanded")) return;
    const open = force ?? li.getAttribute("aria-expanded") !== "true";
    li.setAttribute("aria-expanded", String(open));
    this.openState[id] = open;
    if (this.persistKey) store("tree." + this.persistKey, this.openState);
  }

  select(id, { silent = false, scroll = true } = {}) {
    this.el.querySelectorAll(".tn-row.is-selected").forEach((r) => r.classList.remove("is-selected"));
    this.el.querySelectorAll('.tn[aria-selected="true"]').forEach((r) => r.setAttribute("aria-selected", "false"));
    this.selected = id;
    const li = id && this.li(id);
    if (li) {
      // reveal: open every ancestor
      let p = li.parentElement.closest(".tn");
      while (p) { if (p.getAttribute("aria-expanded") === "false") this.toggle(p.dataset.id, true); p = p.parentElement.closest(".tn"); }
      li.setAttribute("aria-selected", "true");
      li.querySelector(":scope > .tn-row").classList.add("is-selected");
      if (scroll) li.querySelector(":scope > .tn-row").scrollIntoView({ block: "nearest" });
    }
    if (!silent) this.onSelect(id ? this.nodes.get(id) : null);
  }

  visibleIds() {
    return [...this.el.querySelectorAll(".tn")].filter((li) => li.offsetParent !== null).map((li) => li.dataset.id);
  }

  key(e) {
    const ids = this.visibleIds(); if (!ids.length) return;
    const i = ids.indexOf(this.selected);
    const n = this.nodes.get(this.selected);
    if (e.key === "ArrowDown") { e.preventDefault(); this.select(ids[Math.min(ids.length - 1, i + 1)]); }
    else if (e.key === "ArrowUp") { e.preventDefault(); this.select(ids[Math.max(0, i - 1)]); }
    else if (e.key === "ArrowRight" && n?.kids) { e.preventDefault(); this.toggle(this.selected, true); }
    else if (e.key === "ArrowLeft") {
      e.preventDefault();
      const li = this.li(this.selected);
      if (li?.getAttribute("aria-expanded") === "true") this.toggle(this.selected, false);
      else { const p = li?.parentElement.closest(".tn"); if (p) this.select(p.dataset.id); }
    }
  }
}
