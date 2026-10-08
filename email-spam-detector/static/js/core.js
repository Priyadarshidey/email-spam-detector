/* Shared client code: theme, sidebar navigation, navbar status, toasts, history storage, helpers.
   Exposed as window.ESA. Page-specific logic lives in analyzer.js / dashboard.js / history.js. */
(function () {
    'use strict';

    const HISTORY_KEY = 'esa.history.v1';
    const THEME_KEY = 'esa.theme';
    const HISTORY_LIMIT = 200;

    // ---- small helpers ------------------------------------------------------
    const $ = (sel, root = document) => root.querySelector(sel);
    const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

    function escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    function icon(name, cls = '') {
        return `<svg class="icon ${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
    }

    function formatDate(iso, withTime = true) {
        const d = new Date(iso);
        if (isNaN(d)) return '';
        const opts = withTime
            ? { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }
            : { day: '2-digit', month: 'short', year: 'numeric' };
        return d.toLocaleString(undefined, opts);
    }

    // Maps the model's risk level to UI naming used across pages.
    const LEVELS = {
        high: { key: 'high', label: 'Spam', risk: 'High Risk', css: 'high', icon: 'alert' },
        suspicious: { key: 'suspicious', label: 'Suspicious', risk: 'Suspicious', css: 'suspicious', icon: 'alert' },
        safe: { key: 'safe', label: 'Safe', risk: 'Safe', css: 'safe', icon: 'check' },
    };
    const levelMeta = (level) => LEVELS[level] || LEVELS.safe;

    // ---- theme ---------------------------------------------------------------
    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* storage unavailable */ }
        window.dispatchEvent(new CustomEvent('themechange', { detail: theme }));
    }

    function initTheme() {
        const btn = $('#themeToggle');
        if (!btn) return;
        btn.addEventListener('click', () => {
            const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            setTheme(next);
        });
    }

    // ---- sidebar -------------------------------------------------------------
    // Desktop/tablet: collapses to an icon rail (choice remembered). Mobile: slide-out drawer.
    // The initial data-sidebar attribute is set by the inline script in base.html before first paint.
    function initSidebar() {
        const root = document.documentElement;
        const sidebar = $('#sidebar');
        const toggle = $('#sidebarToggle');
        if (!sidebar || !toggle) return;
        const collapseBtn = $('#sidebarCollapse');
        const backdrop = $('#sidebarBackdrop');
        const links = $$('.sb-link', sidebar);
        const mobile = window.matchMedia('(max-width: 920px)');
        const baseActive = links.find((a) => a.getAttribute('aria-current') === 'page') || null;

        const isCollapsed = () => root.getAttribute('data-sidebar') === 'collapsed';
        const isOpen = () => root.classList.contains('sb-open');

        function render() {
            const expanded = mobile.matches ? isOpen() : !isCollapsed();
            toggle.setAttribute('aria-expanded', String(expanded));
            if (collapseBtn) collapseBtn.setAttribute('aria-label', isCollapsed() ? 'Expand sidebar' : 'Collapse sidebar');
            // Native tooltips name the icons while the rail is collapsed.
            const showTips = !mobile.matches && isCollapsed();
            links.forEach((a) => {
                if (showTips) a.setAttribute('title', a.dataset.label); else a.removeAttribute('title');
            });
        }

        function setCollapsed(collapsed) {
            root.setAttribute('data-sidebar', collapsed ? 'collapsed' : 'expanded');
            try { localStorage.setItem('esa.sidebar', collapsed ? 'collapsed' : 'expanded'); } catch (e) { /* storage unavailable */ }
            render();
        }

        function setOpen(open) {
            root.classList.toggle('sb-open', open);
            render();
            if (!open && mobile.matches && sidebar.contains(document.activeElement)) toggle.focus();
        }

        toggle.addEventListener('click', () => (mobile.matches ? setOpen(!isOpen()) : setCollapsed(!isCollapsed())));
        if (collapseBtn) collapseBtn.addEventListener('click', () => setCollapsed(!isCollapsed()));
        if (backdrop) backdrop.addEventListener('click', () => setOpen(false));
        links.forEach((a) => a.addEventListener('click', () => { if (mobile.matches) setOpen(false); }));
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && isOpen()) setOpen(false); });
        mobile.addEventListener('change', () => { root.classList.remove('sb-open'); render(); });

        // Links to a section of a page (Sample Emails, Model Performance) are highlighted from the URL hash.
        function syncActive() {
            const section = links.find((a) => a.dataset.anchor && a.dataset.host === sidebar.dataset.host && a.dataset.anchor === location.hash);
            const current = section || baseActive;
            links.forEach((a) => { a.classList.remove('active'); a.removeAttribute('aria-current'); });
            if (current) { current.classList.add('active'); current.setAttribute('aria-current', 'page'); }
        }
        window.addEventListener('hashchange', syncActive);

        render();
        syncActive();
    }

    // ---- navbar status indicator ------------------------------------------------
    // Reflects the real result of the server's /health endpoint (checked on load, then every minute).
    function initStatus() {
        const badge = $('#sysStatus');
        if (!badge) return;
        const text = $('.sys-text', badge);
        const render = (ok) => {
            badge.dataset.state = ok ? 'ok' : 'down';
            badge.title = ok ? 'Server health check passed' : 'Server is not responding';
            text.textContent = ok ? 'System Secure' : 'System Offline';
        };
        const check = () => fetch('/health', { cache: 'no-store' }).then((r) => render(r.ok)).catch(() => render(false));
        check();
        setInterval(check, 60000);
    }

    // ---- toasts --------------------------------------------------------------
    function toast(message, type = 'info', timeout = 4500) {
        const region = $('#toastRegion');
        if (!region) return;
        const el = document.createElement('div');
        el.className = `toast ${type}`;
        el.innerHTML = `${icon(type === 'error' ? 'alert' : type === 'success' ? 'check' : 'info')}<span>${escapeHtml(message)}</span>`
            + '<button type="button" aria-label="Dismiss">&times;</button>';
        const close = () => { el.classList.add('leaving'); setTimeout(() => el.remove(), 250); };
        el.querySelector('button').addEventListener('click', close);
        region.appendChild(el);
        if (timeout) setTimeout(close, timeout);
    }

    // ---- confirm dialog (replaces window.confirm) -----------------------------
    function confirmDialog({ title, message, confirmText = 'Confirm', danger = true }) {
        return new Promise((resolve) => {
            const dlg = document.createElement('dialog');
            dlg.className = 'modal';
            dlg.innerHTML = `<h3>${escapeHtml(title)}</h3><p class="muted" style="margin:0">${escapeHtml(message)}</p>
                <div class="modal-actions"><button class="btn btn-secondary" value="cancel">Cancel</button>
                <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" value="ok">${escapeHtml(confirmText)}</button></div>`;
            document.body.appendChild(dlg);
            const done = (result) => { dlg.close(); dlg.remove(); resolve(result); };
            dlg.querySelector('[value=cancel]').addEventListener('click', () => done(false));
            dlg.querySelector('[value=ok]').addEventListener('click', () => done(true));
            dlg.addEventListener('cancel', (e) => { e.preventDefault(); done(false); });
            if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
        });
    }

    // ---- history storage (localStorage; no database in this project) -----------
    const Store = {
        list() {
            try {
                const items = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
                return Array.isArray(items) ? items : [];
            } catch (e) { return []; }
        },
        _save(items) {
            try { localStorage.setItem(HISTORY_KEY, JSON.stringify(items)); return true; }
            catch (e) { return false; }
        },
        get(id) { return this.list().find((x) => x.id === id) || null; },
        add(text, analysis) {
            const entry = {
                id: (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2)),
                createdAt: analysis.analyzed_at || new Date().toISOString(),
                text, analysis,
            };
            let items = [entry, ...this.list()].slice(0, HISTORY_LIMIT);
            // If storage is full, drop the oldest entries until it fits.
            while (!this._save(items) && items.length > 1) items = items.slice(0, Math.floor(items.length * 0.8));
            return entry;
        },
        remove(id) { this._save(this.list().filter((x) => x.id !== id)); },
        clear() { try { localStorage.removeItem(HISTORY_KEY); } catch (e) { /* ignore */ } },
    };

    // ---- client-side mirror of the backend's keyword / URL counting ------------
    // Uses the same lexicon + URL pattern the server sends, so real-time numbers
    // match what the backend reports after analysis.
    function buildMatcher(config) {
        const entries = config.lexicon.map((e) => ({ re: new RegExp(e.pattern, 'gi'), category: e.category, severity: e.severity }));
        const urlRe = new RegExp(config.urlPattern, 'gi');

        function keywordSpans(text) {
            const found = [];
            for (const { re, category, severity } of entries) {
                re.lastIndex = 0;
                let m;
                while ((m = re.exec(text)) !== null) {
                    if (m[0].length === 0) { re.lastIndex++; continue; }
                    found.push({ start: m.index, end: m.index + m[0].length, category, severity });
                }
            }
            // leftmost-longest, non-overlapping (same rule as the backend)
            found.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
            const spans = [];
            let cursor = 0;
            for (const s of found) { if (s.start >= cursor) { spans.push(s); cursor = s.end; } }
            return spans;
        }

        function urls(text) {
            const out = [];
            urlRe.lastIndex = 0;
            let m;
            while ((m = urlRe.exec(text)) !== null) {
                const cleaned = m[0].replace(/[.,;:!?]+$/, '');
                if (cleaned) out.push(cleaned);
            }
            return out;
        }

        function stats(raw) {
            const text = raw.trim();
            const chars = Array.from(text);
            const sentences = text.split(/[.!?]+(?:\s+|$)/).filter((s) => s.trim()).length;
            return {
                characters: chars.length,
                words: (text.match(/\S+/g) || []).length,
                sentences,
                urls: urls(text).length,
                suspicious_keywords: keywordSpans(text).length,
                capital_letters: chars.filter((c) => c !== c.toLowerCase() && c === c.toUpperCase()).length,
                special_characters: chars.filter((c) => !/[\p{L}\p{N}\s]/u.test(c)).length,
                exclamation_marks: (text.match(/!/g) || []).length,
            };
        }
        return { stats, keywordSpans, urls };
    }

    // ---- API helper with friendly errors ------------------------------------
    async function api(path, options = {}) {
        let response;
        try {
            response = await fetch(path, options);
        } catch (e) {
            const err = new Error('Server unavailable.');
            err.network = true;
            throw err;
        }
        if (!response.ok) {
            let message = response.status >= 500 ? 'Unable to analyze email. Please try again.' : 'Something went wrong.';
            try { const body = await response.json(); if (body && body.error) message = body.error; } catch (e) { /* non-JSON error */ }
            throw new Error(message);
        }
        return response;
    }

    // ---- init ---------------------------------------------------------------
    document.addEventListener('DOMContentLoaded', () => {
        initTheme();
        initSidebar();
        initStatus();
        const year = $('#year');
        if (year) year.textContent = new Date().getFullYear();
    });

    window.ESA = { $, $$, escapeHtml, icon, formatDate, levelMeta, LEVELS, toast, confirmDialog, Store, buildMatcher, api };
})();
