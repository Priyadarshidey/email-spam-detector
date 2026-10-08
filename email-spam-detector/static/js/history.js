/* Analysis History page: search, filter, view, delete, clear. */
(function () {
    'use strict';
    const { $, $$, escapeHtml, icon, levelMeta, formatDate, toast, confirmDialog, Store } = window.ESA;

    let filter = 'all';
    let query = '';

    function render() {
        const all = Store.list();
        $('#histEmpty').hidden = all.length > 0;
        $('#histData').hidden = all.length === 0;
        if (!all.length) return;

        const q = query.trim().toLowerCase();
        const rows = all.filter((e) => (filter === 'all' || e.analysis.model.risk_level === filter)
            && (!q || e.text.toLowerCase().includes(q)));

        $('#histBody').innerHTML = rows.map((e) => {
            const m = e.analysis.model, meta = levelMeta(m.risk_level);
            const preview = e.text.replace(/\s+/g, ' ').trim();
            return `<tr data-id="${escapeHtml(e.id)}">
                <td data-label="Date">${escapeHtml(formatDate(e.createdAt))}</td>
                <td data-label="Email" class="cell-email">${escapeHtml(preview.slice(0, 110))}${preview.length > 110 ? '…' : ''}</td>
                <td data-label="Result"><span class="badge ${meta.css}">${meta.label}</span></td>
                <td data-label="Risk">${m.risk_score}/100 <span class="muted">· ${meta.risk}</span></td>
                <td data-label="Probability">${m.spam_probability}% spam</td>
                <td class="cell-actions">
                    <a class="btn btn-secondary btn-sm" href="/analyzer?view=${encodeURIComponent(e.id)}">${icon('eye')} View</a>
                    <button class="btn btn-ghost btn-sm" data-delete type="button" aria-label="Delete analysis">${icon('trash')} Delete</button>
                </td></tr>`;
        }).join('');
        $('#histNoMatch').hidden = rows.length > 0;
        $('.table-wrap').hidden = rows.length === 0;
        $('#histCount').textContent = `Showing ${rows.length} of ${all.length} analyses`;
    }

    $('#histSearch').addEventListener('input', (e) => { query = e.target.value; render(); });

    $('#histFilters').addEventListener('click', (e) => {
        const chip = e.target.closest('[data-filter]');
        if (!chip) return;
        filter = chip.dataset.filter;
        $$('#histFilters .chip').forEach((c) => c.setAttribute('aria-pressed', String(c === chip)));
        render();
    });

    $('#histBody').addEventListener('click', (e) => {
        const btn = e.target.closest('[data-delete]');
        if (!btn) return;
        Store.remove(btn.closest('tr').dataset.id);
        toast('Analysis deleted.', 'success', 2200);
        render();
    });

    $('#clearAll').addEventListener('click', async () => {
        const ok = await confirmDialog({ title: 'Clear all history?', message: 'This permanently deletes every saved analysis from this browser.', confirmText: 'Clear all' });
        if (!ok) return;
        Store.clear();
        toast('History cleared.', 'success', 2200);
        render();
    });

    render();
})();
