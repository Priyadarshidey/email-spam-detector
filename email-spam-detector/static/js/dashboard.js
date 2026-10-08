/* Dashboard: KPIs and charts computed from the analysis history in localStorage. */
(function () {
    'use strict';
    const { $, escapeHtml, icon, levelMeta, formatDate, Store } = window.ESA;
    const entries = Store.list();
    const charts = [];

    if (!entries.length) { $('#dashEmpty').hidden = false; return; }
    $('#dashData').hidden = false;

    const level = (e) => e.analysis.model.risk_level;
    const count = (lv) => entries.filter((e) => level(e) === lv).length;
    const total = entries.length, spam = count('high'), suspicious = count('suspicious'), safe = count('safe');

    // ---- KPI cards ------------------------------------------------------------
    const kpis = [
        { label: 'Total emails analyzed', value: total, icon: 'mail', cls: '' },
        { label: 'Spam emails', value: spam, icon: 'alert', cls: 'danger' },
        { label: 'Safe emails', value: safe, icon: 'shield-check', cls: 'safe' },
        { label: 'Suspicious emails', value: suspicious, icon: 'eye', cls: 'warn' },
        { label: 'Spam detection rate', value: `${Math.round((spam / total) * 100)}%`, icon: 'target', cls: '' },
    ];
    $('#kpis').innerHTML = kpis.map((k) => `<div class="card kpi ${k.cls}"><div class="k-icon">${icon(k.icon)}</div><div><b>${k.value}</b><span>${k.label}</span></div></div>`).join('');

    // ---- recent list ------------------------------------------------------------
    $('#recent').innerHTML = entries.slice(0, 6).map((e) => {
        const meta = levelMeta(level(e));
        const preview = e.text.replace(/\s+/g, ' ').slice(0, 90);
        return `<a class="recent-item" href="/analyzer?view=${encodeURIComponent(e.id)}" style="color:inherit;text-decoration:none">
            <span class="badge ${meta.css}">${meta.label}</span><p>${escapeHtml(preview)}</p>
            <small>${e.analysis.model.risk_score}/100 · ${formatDate(e.createdAt, false)}</small></a>`;
    }).join('');

    // ---- charts (colors read from CSS variables so they follow the theme) ---------------
    const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const palette = () => ({ safe: '#22c55e', warn: '#f59e0b', danger: '#ef4444', primary: css('--primary'), text: css('--muted'), grid: css('--border'), surface: css('--surface') });

    function baseOptions(p, extra = {}) {
        return Object.assign({
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { labels: { color: p.text, usePointStyle: true, boxWidth: 8 } }, tooltip: { padding: 10, cornerRadius: 8 } },
        }, extra);
    }
    const axes = (p, extra = {}) => ({
        x: Object.assign({ ticks: { color: p.text, maxRotation: 0, autoSkip: true }, grid: { display: false }, border: { color: p.grid } }, extra.x || {}),
        y: Object.assign({ beginAtZero: true, ticks: { color: p.text, precision: 0 }, grid: { color: p.grid }, border: { display: false } }, extra.y || {}),
    });

    function build() {
        charts.splice(0).forEach((c) => c.destroy());
        const p = palette();

        // 1. Spam vs safe (doughnut)
        charts.push(new Chart($('#chartSplit'), {
            type: 'doughnut',
            data: { labels: ['Spam', 'Suspicious', 'Safe'], datasets: [{ data: [spam, suspicious, safe], backgroundColor: [p.danger, p.warn, p.safe], borderColor: p.surface, borderWidth: 3 }] },
            options: baseOptions(p, { cutout: '64%', plugins: { legend: { position: 'bottom', labels: { color: p.text, usePointStyle: true, boxWidth: 8 } } } }),
        }));

        // 2. Detection over time (stacked bars per day, most recent 14 days with data)
        const perDay = {};
        entries.forEach((e) => {
            const d = new Date(e.createdAt); if (isNaN(d)) return;
            const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
            (perDay[key] = perDay[key] || { high: 0, suspicious: 0, safe: 0 })[level(e)]++;
        });
        const days = Object.keys(perDay).sort().slice(-14);
        const label = (k) => new Date(k + 'T00:00:00').toLocaleDateString(undefined, { day: '2-digit', month: 'short' });
        charts.push(new Chart($('#chartTime'), {
            type: 'bar',
            data: { labels: days.map(label), datasets: [
                { label: 'Spam', data: days.map((d) => perDay[d].high), backgroundColor: p.danger, borderRadius: 4 },
                { label: 'Suspicious', data: days.map((d) => perDay[d].suspicious), backgroundColor: p.warn, borderRadius: 4 },
                { label: 'Safe', data: days.map((d) => perDay[d].safe), backgroundColor: p.safe, borderRadius: 4 },
            ] },
            options: baseOptions(p, { scales: { x: Object.assign(axes(p).x, { stacked: true }), y: Object.assign(axes(p).y, { stacked: true }) }, plugins: { legend: { position: 'bottom', labels: { color: p.text, usePointStyle: true, boxWidth: 8 } } } }),
        }));

        // 3. Risk distribution (10-point buckets, coloured by risk band)
        const buckets = new Array(10).fill(0);
        entries.forEach((e) => { buckets[Math.min(9, Math.floor(e.analysis.model.risk_score / 10))]++; });
        const bucketColor = (i) => (i * 10 + 9 <= 30 ? p.safe : i * 10 < 60 ? p.warn : p.danger);
        charts.push(new Chart($('#chartRisk'), {
            type: 'bar',
            data: { labels: buckets.map((_, i) => `${i * 10}–${i === 9 ? 100 : i * 10 + 9}`), datasets: [{ label: 'Emails', data: buckets, backgroundColor: buckets.map((_, i) => bucketColor(i)), borderRadius: 4 }] },
            options: baseOptions(p, { scales: axes(p), plugins: { legend: { display: false } } }),
        }));

        // 4. Detection categories (how many emails triggered each rule-based indicator)
        const names = { keywords: 'Suspicious keywords', urgency: 'Urgency', prize_money: 'Prize / money', phishing: 'Account / credentials', promotional: 'Promotional', urls: 'Suspicious URLs', caps: 'Capitalization', formatting: 'Formatting' };
        const tally = {};
        entries.forEach((e) => e.analysis.rules.indicators.forEach((i) => { tally[i.id] = (tally[i.id] || 0) + 1; }));
        const ids = Object.keys(names).filter((id) => tally[id]).sort((a, b) => tally[b] - tally[a]);
        charts.push(new Chart($('#chartCats'), {
            type: 'bar',
            data: { labels: ids.map((id) => names[id]), datasets: [{ label: 'Emails', data: ids.map((id) => tally[id]), backgroundColor: p.primary, borderRadius: 4 }] },
            options: baseOptions(p, { indexAxis: 'y', scales: { x: axes(p).y, y: Object.assign(axes(p).x, { ticks: { color: p.text } }) }, plugins: { legend: { display: false } } }),
        }));
    }

    build();
    window.addEventListener('themechange', build);
})();
