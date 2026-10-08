/* Email Analyzer page: live stats, samples, upload, scanning UI, results rendering. */
(function () {
    'use strict';
    const { $, $$, escapeHtml, icon, levelMeta, toast, Store, api, formatDate } = window.ESA;

    const config = JSON.parse($('#esaConfig').textContent);
    const matcher = window.ESA.buildMatcher(config);
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const el = {
        input: $('#emailInput'), counter: $('#charCounter'), analyze: $('#analyzeBtn'), clear: $('#clearBtn'),
        sampleBtn: $('#sampleBtn'), upload: $('#uploadBtn'), file: $('#fileInput'), chips: $('#sampleChips'),
        stats: $('#statsGrid'), loading: $('#loading'), loadingBar: $('#loadingBar'), loadingTitle: $('#loadingTitle'),
        steps: $$('#scanSteps li'), results: $('#results'), banner: $('#viewBanner'), bannerText: $('#viewBannerText'),
        reportBtn: $('#reportBtn'), whyBtn: $('#whyBtn'), whyBody: $('#whyBody'),
    };

    let busy = false;
    let current = null; // { text, analysis } currently displayed

    // ---- live statistics -----------------------------------------------------
    function updateStats() {
        const text = el.input.value;
        el.counter.textContent = text.length.toLocaleString();
        const s = matcher.stats(text);
        $$('.stat', el.stats).forEach((node) => {
            const key = node.dataset.stat;
            node.querySelector('b').textContent = s[key].toLocaleString();
            node.classList.toggle('flag', (key === 'suspicious_keywords' && s[key] > 0 && s[key] < 5) || (key === 'exclamation_marks' && s[key] >= 3));
            node.classList.toggle('flag-high', key === 'suspicious_keywords' && s[key] >= 5);
        });
    }

    // ---- samples ---------------------------------------------------------------
    const samples = window.ESA_SAMPLES || [];
    el.chips.innerHTML = samples.map((s) => `<button type="button" class="chip" data-id="${s.id}" aria-pressed="false">${escapeHtml(s.label)}</button>`).join('');

    function setText(text, sampleId) {
        el.input.value = text;
        $$('.chip', el.chips).forEach((c) => c.setAttribute('aria-pressed', String(c.dataset.id === sampleId)));
        updateStats();
    }

    el.chips.addEventListener('click', (e) => {
        const chip = e.target.closest('.chip');
        if (!chip) return;
        const sample = samples.find((s) => s.id === chip.dataset.id);
        if (sample) { setText(sample.text, sample.id); el.input.focus({ preventScroll: true }); }
    });

    el.sampleBtn.addEventListener('click', () => {
        const sample = samples[Math.floor(Math.random() * samples.length)];
        if (sample) { setText(sample.text, sample.id); toast(`Loaded sample: ${sample.label}`, 'info', 2200); }
    });

    el.input.addEventListener('input', () => {
        $$('.chip', el.chips).forEach((c) => c.setAttribute('aria-pressed', 'false'));
        updateStats();
    });

    el.clear.addEventListener('click', () => {
        setText('');
        el.results.hidden = true;
        el.banner.hidden = true;
        current = null;
        if (location.search) history.replaceState(null, '', location.pathname);
        el.input.focus();
    });

    // ---- scanning animation (UI only; the real request runs in parallel) ----------
    const sleep = (ms) => new Promise((r) => setTimeout(r, reduceMotion ? 0 : ms));

    function resetSteps() {
        el.steps.forEach((s) => s.className = '');
        el.loadingBar.style.width = '0%';
    }

    async function playSteps(isSettled) {
        for (let i = 0; i < el.steps.length; i++) {
            el.steps[i].className = 'active';
            el.loadingBar.style.width = `${Math.round(((i + 0.6) / el.steps.length) * 100)}%`;
            await sleep(i === 3 ? 520 : 340);
            // "Running ML model" and "Generating security score" only tick once the real response is back.
            if (i >= 3) { while (!isSettled()) await sleep(80); }
            el.steps[i].className = 'done';
        }
    }

    // ---- analysis ---------------------------------------------------------------
    async function analyze() {
        if (busy) return;
        const text = el.input.value.trim();
        if (!text) {
            toast('No email content provided.', 'error');
            el.input.classList.remove('shake'); void el.input.offsetWidth; el.input.classList.add('shake');
            el.input.focus();
            return;
        }
        busy = true;
        el.analyze.disabled = true;
        el.banner.hidden = true;
        el.results.hidden = true;
        resetSteps();
        el.loading.hidden = false;
        el.loadingTitle.textContent = 'Analyzing email…';
        el.loading.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'center' });

        let settled = false, analysis = null, failure = null;
        const request = api('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) })
            .then((r) => r.json()).then((data) => { analysis = data; })
            .catch((err) => { failure = err; })
            .finally(() => { settled = true; });

        await Promise.all([request, playSteps(() => settled)]);
        el.loadingBar.style.width = '100%';
        await sleep(250);
        el.loading.hidden = true;
        busy = false;
        el.analyze.disabled = false;

        if (failure) { toast(failure.message || 'Something went wrong.', 'error', 6000); return; }
        current = { text, analysis };
        Store.add(text, analysis);
        renderResults(analysis, text);
    }

    // ---- results rendering -----------------------------------------------------------
    function countUp(node, to, suffix = '', duration = 900) {
        if (reduceMotion) { node.textContent = to + suffix; return; }
        const start = performance.now();
        const tick = (now) => {
            const t = Math.min(1, (now - start) / duration);
            node.textContent = Math.round(to * (1 - Math.pow(1 - t, 3))) + suffix;
            if (t < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
    }

    function renderResults(analysis, text, { scroll = true } = {}) {
        const m = analysis.model, r = analysis.rules, meta = levelMeta(m.risk_level);
        const color = { safe: 'var(--safe)', suspicious: 'var(--warn)', high: 'var(--danger)' }[meta.key];

        // main card
        const card = $('#resultCard');
        card.className = `result-card ${meta.css}`;
        $('#verdictIcon').innerHTML = icon(meta.key === 'safe' ? 'shield-check' : 'alert');
        $('#verdictTitle').textContent = analysis.verdict.title;
        $('#verdictSub').textContent = analysis.verdict.subtitle;
        $('#mSpam').textContent = `${m.spam_probability}%`;
        $('#mConf').textContent = m.confidence_label;
        $('#mConf').title = `${m.confidence}% for the predicted class`;
        $('#mPred').textContent = m.prediction === 'spam' ? 'Spam' : 'Not spam';
        $('#ring').style.setProperty('--ring-color', color);

        // risk meter
        const pos = Math.max(0, Math.min(100, m.risk_score));
        $('#meterTrack').style.setProperty('--pos', '0%');
        $('#meterTrack').style.setProperty('--marker', color);
        const badge = $('#meterBadge');
        badge.className = `badge ${meta.css}`;
        badge.textContent = meta.risk;

        // probabilities + recommendation
        $('#pSpamTxt').textContent = `${m.spam_probability}%`;
        $('#pHamTxt').textContent = `${m.not_spam_probability}%`;
        $('#recommendation').innerHTML = `<strong>Recommendation:</strong> ${escapeHtml(analysis.recommendation)}`;

        renderWhy(m, r);
        renderHighlights(r);
        renderUrls(r.urls);
        renderBreakdown(r.breakdown);

        el.results.hidden = false;
        // animate after layout so transitions run
        requestAnimationFrame(() => requestAnimationFrame(() => {
            const circumference = 326.7;
            $('#ringFill').style.strokeDashoffset = String(circumference * (1 - m.spam_probability / 100));
            countUp($('#ringValue'), Math.round(m.spam_probability), '%');
            $('#meterTrack').style.setProperty('--pos', `${pos}%`);
            countUp($('#meterScore'), m.risk_score);
            $('#pSpamBar').style.width = `${m.spam_probability}%`;
            $('#pHamBar').style.width = `${m.not_spam_probability}%`;
            $$('#breakdown .bar i').forEach((bar) => { bar.style.width = `${bar.dataset.value}%`; });
        }));
        if (scroll) setTimeout(() => $('#resultCard').scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' }), 60);
    }

    function renderWhy(m, r) {
        const terms = (items, cls) => items.length
            ? items.map((t) => `<span class="term ${cls}" title="influence ${t.weight}">${escapeHtml(t.term)}</span>`).join('')
            : '<span class="muted" style="font-size:.85rem">None</span>';
        $('#termsSpam').innerHTML = terms(m.top_terms.spam, 'spam');
        $('#termsHam').innerHTML = terms(m.top_terms.ham, 'ham');

        const cov = m.vocabulary_coverage;
        const note = $('#coverageNote');
        note.className = 'note' + (m.no_recognized_terms || cov.recognized < Math.max(3, cov.total * 0.2) ? ' warn' : '');
        note.textContent = m.no_recognized_terms
            ? `None of this email's words appear in the model's ${cov.vocabulary_size}-word vocabulary, so this result reflects only the model's prior, not the email's content.`
            : `The model recognised ${cov.recognized} of ${cov.total} distinct words in this email (its vocabulary has ${cov.vocabulary_size} words). Words it has never seen are ignored.`;

        $('#indicators').innerHTML = r.indicators.length
            ? r.indicators.map((i) => `<li class="indicator ${i.severity}">${icon('alert')}<div><b>${escapeHtml(i.title)}</b><span>${escapeHtml(i.detail)}</span></div></li>`).join('')
            : `<li class="indicator">${icon('check')}<div><b>No rule-based warning indicators detected</b><span>No suspicious keywords, risky links or unusual formatting were found.</span></div></li>`;
    }

    function renderHighlights(r) {
        $('#emailView').innerHTML = r.segments.map((seg) => seg.severity
            ? `<mark class="${seg.severity}" title="${escapeHtml(seg.category.replace('_', ' / '))}">${escapeHtml(seg.text)}</mark>`
            : escapeHtml(seg.text)).join('');
        $('#kwChips').innerHTML = r.keywords.length
            ? r.keywords.map((k) => `<span class="kw-chip ${k.severity}">${escapeHtml(k.text)}${k.count > 1 ? ` <em>×${k.count}</em>` : ''}</span>`).join('')
            : '<span class="muted" style="font-size:.9rem">No suspicious keywords detected.</span>';
    }

    function renderUrls(urls) {
        const body = $('#urlBody');
        if (!urls.length) { body.innerHTML = '<p class="muted" style="margin:0">No URLs found in this email.</p>'; return; }
        const badge = { 'Safe-looking': 'safe', Suspicious: 'high', Unknown: 'neutral' };
        const https = { yes: 'Yes', no: 'No', unknown: 'Not specified' };
        body.innerHTML = `<div class="table-wrap"><table class="data stack"><thead><tr><th>URL</th><th>Domain</th><th>HTTPS</th><th>Assessment</th></tr></thead><tbody>`
            + urls.map((u) => `<tr>
                <td data-label="URL" class="cell-url">${escapeHtml(u.url)}</td>
                <td data-label="Domain">${escapeHtml(u.domain)}</td>
                <td data-label="HTTPS">${https[u.https]}</td>
                <td data-label="Assessment"><span class="badge ${badge[u.label]}">${u.label}</span>
                    <div class="cell-reason">${escapeHtml(u.reasons.join('; '))}</div></td></tr>`).join('')
            + '</tbody></table></div><p class="note" style="margin-top:12px">Assessments are rule-based and unverified: links are not visited or checked against any blocklist, so “Suspicious” does not mean a link is confirmed malicious.</p>';
    }

    function renderBreakdown(rows) {
        $('#breakdown').innerHTML = rows.map((b) => {
            const na = b.applicable === false;
            const tone = b.value >= 70 ? 'var(--danger)' : b.value >= 35 ? 'var(--warn)' : 'var(--safe)';
            return `<div class="brow${na ? ' na' : ''}"><span>${escapeHtml(b.label)}</span>
                <div class="bar"><i data-value="${na ? 0 : b.value}" style="--bar-color:${tone}"></i></div>
                <span class="val">${na ? 'n/a' : b.value + '%'}</span></div>`;
        }).join('');
    }

    // ---- "Why this result?" expander ------------------------------------------------
    el.whyBtn.addEventListener('click', () => {
        const open = el.whyBtn.getAttribute('aria-expanded') !== 'true';
        el.whyBtn.setAttribute('aria-expanded', String(open));
        el.whyBody.classList.toggle('open', open);
    });

    // ---- upload -----------------------------------------------------------------------
    async function handleFile(file) {
        if (!file || busy) return;
        if (!/\.(txt|eml)$/i.test(file.name)) { toast('Invalid file format. Please upload a .txt or .eml file.', 'error'); return; }
        const form = new FormData();
        form.append('file', file);
        el.upload.disabled = true;
        try {
            const data = await (await api('/api/upload', { method: 'POST', body: form })).json();
            setText(data.text);
            toast(`Loaded ${data.filename}`, 'success', 2500);
            await analyze();
        } catch (err) {
            toast(err.message || 'Something went wrong.', 'error', 6000);
        } finally {
            el.upload.disabled = false;
            el.file.value = '';
        }
    }
    el.upload.addEventListener('click', () => el.file.click());
    el.file.addEventListener('change', () => handleFile(el.file.files[0]));
    ['dragenter', 'dragover'].forEach((ev) => el.input.addEventListener(ev, (e) => { e.preventDefault(); el.input.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach((ev) => el.input.addEventListener(ev, (e) => { e.preventDefault(); el.input.classList.remove('drag'); }));
    el.input.addEventListener('drop', (e) => { const f = e.dataTransfer && e.dataTransfer.files[0]; if (f) handleFile(f); });

    // ---- report download ------------------------------------------------------------------
    el.reportBtn.addEventListener('click', async () => {
        if (!current) return;
        el.reportBtn.disabled = true;
        try {
            const response = await api('/api/report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: current.text }) });
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = 'email-security-report.pdf';
            document.body.appendChild(a); a.click(); a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            toast('Report downloaded.', 'success', 2500);
        } catch (err) {
            toast(err.message || 'Something went wrong.', 'error', 6000);
        } finally { el.reportBtn.disabled = false; }
    });

    $('#analyzeAnotherBtn').addEventListener('click', () => {
        setText('');
        el.results.hidden = true;
        window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' });
        el.input.focus({ preventScroll: true });
    });

    el.analyze.addEventListener('click', analyze);
    el.input.addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyze(); });

    // ---- entry points: ?view=<id> (from History), /predict form fallback ------------------
    function init() {
        updateStats();
        if (window.ESA_INITIAL_ERROR) toast(window.ESA_INITIAL_ERROR, 'error');
        const viewId = new URLSearchParams(location.search).get('view');
        if (viewId) {
            const entry = Store.get(viewId);
            if (!entry) { toast('That analysis could not be found. It may have been deleted.', 'error'); return; }
            setText(entry.text);
            current = { text: entry.text, analysis: entry.analysis };
            el.banner.hidden = false;
            el.bannerText.textContent = `Viewing saved analysis from ${formatDate(entry.createdAt)}. Press Analyze Email to run it again.`;
            renderResults(entry.analysis, entry.text, { scroll: false });
        } else if (window.ESA_AUTORUN) {
            analyze();
        }
    }
    init();
})();
