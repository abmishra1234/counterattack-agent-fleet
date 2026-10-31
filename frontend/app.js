const app = document.querySelector('#app');
const drawerRoot = document.querySelector('#drawer-root');
const toastRoot = document.querySelector('#toast-root');
let model;
let activePage = location.hash.slice(1) || 'overview';
let selectedReview = 0;
let priorityFilter = 'All';
let query = '';
let ownerFilter = 'all';

const escapeHtml = (value = '') => String(value).replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));
const niceDate = (value) => value ? new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'Not recorded';
const friendlyName = (value = '') => value.split(/[-_]/).map((part) => part ? part[0].toUpperCase() + part.slice(1) : '').join(' ');
const priorityClass = (priority = 'P4') => `priority-${priority}`;
const sourceLabel = (advisory) => advisory?.source === 'nvd' ? 'NVD fixture' : advisory?.source === 'vendor_bulletin' ? 'Vendor bulletin fixture' : 'Local fixture';

async function loadData() {
  try {
    const response = await fetch('/api/data', { cache: 'no-store' });
    if (!response.ok) throw new Error(`API returned ${response.status}`);
    model = await response.json();
    document.querySelector('#top-run-status').textContent = model.lastRun ? `Latest run · ${model.lastRun}` : 'No run recorded';
    document.querySelector('.status-dot').classList.toggle('warning-dot', !model.lastRun);
    document.querySelector('#nav-alert-count').textContent = model.alerts.length;
    document.querySelector('#nav-review-count').textContent = model.needsHuman.length;
    render();
    const initialHash = location.hash.slice(1);
    if (initialHash.startsWith('alert/')) openAlert(decodeURIComponent(initialHash.slice(6)));
  } catch (error) {
    app.innerHTML = `<section class="error-state"><div><div class="empty-icon">!</div><strong>Could not load preview data</strong><p>${escapeHtml(error.message)}. Run the Counterstrike CLI first, then refresh this page.</p><code>python -m counterstrike run --data data --out out</code></div></section>`;
  }
}

function render() {
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.page === activePage));
  const crumb = document.querySelector('#crumb-page');
  if (crumb) crumb.textContent = ({ overview: 'Today', alerts: 'Alerts', review: 'Needs review', health: 'Run health' })[activePage] || 'Today';
  if (activePage === 'alerts') renderAlerts();
  else if (activePage === 'review') renderReview();
  else if (activePage === 'health') renderHealth();
  else { activePage = 'overview'; renderOverview(); }
}

function pageHeading(eyebrow, title, description, actions = '') {
  return `<div class="page-heading"><div><div class="eyebrow">${eyebrow}</div><h1>${title}</h1><p class="page-description">${description}</p></div>${actions ? `<div class="heading-actions">${actions}</div>` : ''}</div>`;
}

function priorityBadge(priority) {
  return `<span class="priority-badge ${priorityClass(priority)}">${escapeHtml(priority)}</span>`;
}

function statusBadge(label, kind = 'affected') {
  return `<span class="state-badge ${kind}"><span aria-hidden="true">${kind === 'affected' ? '●' : kind === 'healthy' ? '✓' : '!'}</span>${escapeHtml(label)}</span>`;
}

function topPreviewBanner() {
  return `<div class="banner"><div class="banner-content"><span class="banner-icon">i</span><span><strong>Local preview data.</strong> These results come from synthetic fixture files; no live feeds or delivery channels are connected.</span></div><span class="feed-mode">● Fixture mode</span></div>`;
}

function metricCard(label, value, foot, accent, icon) {
  return `<article class="metric-card" style="--accent:${accent};--accent-bg:${accent}16"><div class="metric-top"><span>${label}</span><span class="metric-icon" aria-hidden="true">${icon}</span></div><div class="metric-value">${value}</div><div class="metric-foot">${foot}</div></article>`;
}

function countsByPriority() {
  return ['P1', 'P2', 'P3', 'P4'].map((priority) => ({ priority, count: model.alerts.filter((a) => a.priority === priority).length }));
}

function priorityChart() {
  const rows = countsByPriority();
  const max = Math.max(1, ...rows.map((row) => row.count));
  const classMap = { P1: '#b42318', P2: '#9a3412', P3: '#a16207', P4: '#64748b' };
  const total = Math.max(1, model.alerts.length);
  return rows.map(({ priority, count }) => `<div class="priority-row"><span class="priority-label" style="color:${classMap[priority]}">${priority}</span><div class="priority-track" role="img" aria-label="${priority}: ${count} alerts"><div class="priority-fill" style="width:${Math.max(count ? 6 : 0, count / max * 100)}%;background:${classMap[priority]}"></div></div><span class="priority-number">${count}</span><span class="priority-share">${Math.round(count / total * 100)}%</span></div>`).join('');
}

function alertRows(items) {
  if (!items.length) return `<tr><td colspan="6"><div class="no-results">No alerts match these filters.</div></td></tr>`;
  return items.map((alert) => `
    <tr tabindex="0" role="button" aria-label="Open ${escapeHtml(alert.cve_id)} for ${escapeHtml(alert.service)}" data-alert-id="${escapeHtml(alert.alert_id)}">
      <td>${priorityBadge(alert.priority)}</td>
      <td><a class="cve-link mono" href="#alert/${encodeURIComponent(alert.alert_id)}">${escapeHtml(alert.cve_id)}</a><div class="mono-label">${escapeHtml(alert.alert_id)}</div></td>
      <td><div class="asset-cell"><span class="service-name">${escapeHtml(alert.component)}</span><small>v${escapeHtml(alert.installed_version)}</small></div></td>
      <td><div class="asset-cell"><span class="service-name">${escapeHtml(alert.service)}</span><small>${escapeHtml(alert.asset_id)}</small></div></td>
      <td><div class="owner-cell"><span class="owner-avatar">${escapeHtml((alert.owner || '??').slice(0, 2).toUpperCase())}</span><span class="owner-name">${escapeHtml(alert.owner)}</span></div></td>
      <td>${statusBadge('Affected')}</td>
    </tr>`).join('');
}

function alertsTable(items, compact = false) {
  return `<div class="table-wrap"><table><thead><tr><th>Priority</th><th>Advisory</th><th>Component</th><th>Service / asset</th><th>Owner</th><th>Assessment</th></tr></thead><tbody>${alertRows(items)}</tbody></table></div>${compact ? `<div class="table-foot"><span>Showing ${items.length} affected assets in this run</span><a href="#alerts" data-go="alerts">View all alerts <span class="arrow">→</span></a></div>` : `<div class="table-foot"><span>Preview data · ${items.length} results</span><span>Sorted by priority and risk score</span></div>`}`;
}

function renderOverview() {
  const report = model.report;
  const ranked = [...model.alerts].sort((a, b) => a.priority.localeCompare(b.priority) || b.risk_score - a.risk_score);
  const featured = ranked[0];
  const remaining = ranked.slice(1, 4);
  const p1Count = model.alerts.filter((a) => a.priority === 'P1').length;
  const scanCount = report?.trace?.find((x) => x.agent === 'ingest')?.assets ?? '—';
  app.innerHTML = `${pageHeading('SECURITY WORKSPACE', 'Good morning', 'Your latest local run, prioritized for a quick review.', '<span class="scope-pill">Latest run</span>')}
    <section class="overview-hero-grid" aria-label="Today overview">
      <article class="featured-alert">
        <div class="featured-eyebrow"><span class="featured-star">✦</span> HIGHEST PRIORITY · ${featured ? escapeHtml(featured.priority) : 'CLEAR'}</div>
        <h2>${featured ? escapeHtml(featured.cve_id) : 'No affected assets found'}</h2>
        <p class="featured-summary">${featured ? escapeHtml(featured.summary) : 'The latest run did not identify any confirmed matches.'}</p>
        ${featured ? `<div class="featured-meta"><span>${escapeHtml(featured.service)}</span><span>${escapeHtml(featured.component)} ${escapeHtml(featured.installed_version)}</span><span>Owner · ${escapeHtml(featured.owner)}</span></div><div class="featured-actions"><button class="button featured-button" type="button" data-featured-alert="${escapeHtml(featured.alert_id)}">Review finding <span aria-hidden="true">→</span></button><span class="featured-hint">${escapeHtml(featured.sla_hours)}h response target</span></div>` : ''}
      </article>
      <div class="overview-side-stack">
        <article class="overview-stat-card run-stat-card"><div class="overview-card-top"><span class="overview-card-icon run-icon">✓</span><span class="card-kicker">LATEST RUN</span>${statusBadge('Completed', 'healthy')}</div><strong>${escapeHtml(model.lastRun || 'Time not recorded')}</strong><p>${report?.advisories_ingested ?? 0} advisories checked · ${report?.matches ?? 0} matches</p><a href="#health" data-go="health" class="panel-link">View run details <span class="arrow">→</span></a></article>
        <article class="overview-stat-card"><div class="overview-card-top"><span class="overview-card-icon review-icon">◎</span><span class="card-kicker">HUMAN REVIEW</span></div><div class="review-stat-line"><strong>${model.needsHuman.length}</strong><span>item${model.needsHuman.length === 1 ? '' : 's'} need attention</span></div><p>Uncertain advisories stay in the review queue.</p><a href="#review" data-go="review" class="panel-link">Open review queue <span class="arrow">→</span></a></article>
      </div>
    </section>
    <section class="overview-lower-grid">
      <article class="panel today-panel"><div class="panel-header"><div><div class="panel-title">Also in this run</div><div class="panel-subtitle">A short list of other confirmed affected assets</div></div><a class="panel-link" href="#alerts" data-go="alerts">All ${model.alerts.length} findings →</a></div>${remaining.length ? `<div class="finding-list">${remaining.map((item) => `<button class="finding-row" type="button" data-featured-alert="${escapeHtml(item.alert_id)}"><span class="finding-priority ${priorityClass(item.priority)}">${escapeHtml(item.priority)}</span><span class="finding-main"><strong>${escapeHtml(item.cve_id)} <span>· ${escapeHtml(item.component)}</span></strong><small>${escapeHtml(item.service)} · ${escapeHtml(item.owner)}</small></span><span class="finding-score">${Number(item.risk_score).toFixed(1)}<small>risk</small></span><span class="finding-arrow">→</span></button>`).join('')}</div>` : '<div class="empty-inline">No additional findings in this run.</div>'}</article>
      <article class="panel posture-panel"><div class="panel-header"><div><div class="panel-title">Run snapshot</div><div class="panel-subtitle">Local fixture data</div></div><span class="snapshot-count">${model.alerts.length}</span></div><div class="snapshot-total"><strong>${model.alerts.length}</strong><span>affected assets</span></div><div class="priority-chart snapshot-chart">${priorityChart()}</div><div class="snapshot-footer"><span>${scanCount} inventory assets scanned</span><span>${p1Count} P1</span></div></article>
    </section>`;
  bindPageLinks();
  document.querySelectorAll('[data-featured-alert]').forEach((button) => button.addEventListener('click', () => openAlert(button.dataset.featuredAlert)));
}

function renderAlerts() {
  const items = model.alerts.filter((alert) => {
    const matchesPriority = priorityFilter === 'All' || alert.priority === priorityFilter;
    const matchesOwner = ownerFilter === 'all' || alert.owner === ownerFilter;
    const searchText = [alert.cve_id, alert.asset_id, alert.service, alert.component, alert.owner].join(' ').toLowerCase();
    return matchesPriority && matchesOwner && searchText.includes(query.trim().toLowerCase());
  });
  app.innerHTML = `${pageHeading('WORKSPACE / ALERTS', 'Affected assets', 'Review each confirmed match, its priority and the evidence used by the prototype.', '<span class="feed-mode">LOCAL RUN</span>')}
    <div class="page-toolbar"><label class="searchbox"><span aria-hidden="true">⌕</span><input id="alert-search" type="search" placeholder="Search CVE, product, service or owner" value="${escapeHtml(query)}" aria-label="Search alerts"></label><select class="select-control" id="owner-filter" aria-label="Filter by owner"><option value="all">All owners</option>${[...new Set(model.alerts.map((a) => a.owner))].sort().map((owner) => `<option value="${escapeHtml(owner)}" ${ownerFilter === owner ? 'selected' : ''}>${escapeHtml(owner)}</option>`).join('')}</select><button class="button small" id="clear-filters">Clear filters</button></div>
    <div class="filter-chips" aria-label="Filter by priority">${['All', 'P1', 'P2', 'P3', 'P4'].map((p) => `<button class="filter-chip ${priorityFilter === p ? 'active' : ''}" data-priority="${p}">${p === 'All' ? 'All priorities' : p}<span class="chip-count">${p === 'All' ? model.alerts.length : model.alerts.filter((a) => a.priority === p).length}</span></button>`).join('')}</div>
    <article class="panel table-panel"><div class="panel-header"><div class="panel-title">Affected asset list</div><span class="table-caption" id="results-count">${items.length} results</span></div><div id="alerts-table">${alertsTable(items)}</div></article>`;
  const search = document.querySelector('#alert-search');
  search.addEventListener('input', (event) => { query = event.target.value; document.querySelector('#global-search').value = query; updateAlertsTable(); });
  document.querySelectorAll('[data-priority]').forEach((chip) => chip.addEventListener('click', () => { priorityFilter = chip.dataset.priority; renderAlerts(); }));
  document.querySelector('#clear-filters').addEventListener('click', () => { priorityFilter = 'All'; query = ''; ownerFilter = 'all'; renderAlerts(); });
  document.querySelector('#owner-filter').addEventListener('change', (event) => { ownerFilter = event.target.value; updateAlertsTable(); });
  bindAlertRows();
}

function updateAlertsTable() {
  const items = model.alerts.filter((alert) => {
    const matchesPriority = priorityFilter === 'All' || alert.priority === priorityFilter;
    const matchesOwner = ownerFilter === 'all' || alert.owner === ownerFilter;
    const searchText = [alert.cve_id, alert.asset_id, alert.service, alert.component, alert.owner].join(' ').toLowerCase();
    return matchesPriority && matchesOwner && searchText.includes(query.trim().toLowerCase());
  });
  document.querySelector('#alerts-table').innerHTML = alertsTable(items);
  document.querySelector('#results-count').textContent = `${items.length} results`;
  bindAlertRows();
}

function renderReview() {
  const items = model.needsHuman;
  if (!items.length) {
    app.innerHTML = `${pageHeading('WORKSPACE / REVIEW', 'Needs review', 'Advisories the fleet could not safely resolve from the available evidence.')}<article class="panel"><div class="empty-state"><div><div class="empty-icon">✓</div><strong>No advisories need review</strong><p>Unclear or ungrounded items from the latest run will appear here.</p></div></div></article>`;
    return;
  }
  selectedReview = Math.min(selectedReview, items.length - 1);
  const item = items[selectedReview];
  const advisory = model.advisories.find((a) => a.id === item.advisory_id);
  app.innerHTML = `${pageHeading('WORKSPACE / REVIEW QUEUE', 'Needs review', 'The fleet leaves uncertain cases for a human instead of guessing.', `<span class="state-badge review">${items.length} open item${items.length === 1 ? '' : 's'}</span>`)}
    <div class="review-layout"><article class="panel"><div class="panel-header"><div class="panel-title">Review queue</div><span class="table-caption">${items.length} item${items.length === 1 ? '' : 's'}</span></div><div class="review-list">${items.map((entry, index) => `<button class="review-item ${index === selectedReview ? 'selected' : ''}" data-review-index="${index}"><div class="review-item-top"><strong>${escapeHtml(entry.advisory_id)}</strong><small>Extract stage</small></div><div class="review-item-title">${escapeHtml(model.advisories.find((a) => a.id === entry.advisory_id)?.title || 'Advisory details unavailable')}</div><div class="review-item-reason">${escapeHtml(entry.reason)}</div></button>`).join('')}</div></article>
    <article class="panel review-detail"><div class="review-detail-header">${statusBadge('Human review required', 'review')}<h2>${escapeHtml(item.advisory_id)}</h2><p class="lead">${escapeHtml(advisory?.title || 'Advisory details unavailable')}</p></div><div class="review-callout"><strong>Why it was held:</strong> ${escapeHtml(item.reason)} The system did not produce a confirmed affected-product and version-range match.</div><div class="review-section-title">Source bulletin</div><div class="bulletin">${escapeHtml(advisory?.text || 'Source text is not available in the fixture.')}</div><div class="review-section-title">Available context</div><div class="source-list-inline"><span class="tag">Source: ${escapeHtml(sourceLabel(advisory))}</span><span class="tag">Published: ${escapeHtml(advisory?.published || 'Unknown')}</span><span class="tag">CVSS: ${advisory?.cvss ?? 'Not provided'}</span></div><div class="review-note"><span aria-hidden="true">i</span><span><strong>Read-only preview.</strong> Review decisions are not saved in this frontend. No owner alert has been created for this advisory.</span></div></article></div>`;
  document.querySelectorAll('[data-review-index]').forEach((button) => button.addEventListener('click', () => { selectedReview = Number(button.dataset.reviewIndex); renderReview(); }));
}

function renderHealth() {
  const report = model.report;
  const trace = report?.trace || [];
  const fixtureSources = [
    { key: 'NVD', file: 'advisories.json', count: model.advisories.length, note: 'Synthetic advisory and vendor bulletin fixture records' },
    { key: 'KEV', file: 'kev.json', count: model.kev?.cve_ids?.length || 0, note: 'Synthetic KEV-style identifiers' },
    { key: 'Inventory', file: 'inventory.json', count: model.inventory.length, note: 'Local sample asset inventory' },
  ];
  app.innerHTML = `${pageHeading('WORKSPACE / RUN HEALTH', 'Run health', 'Inspect what the latest local execution processed and where the data came from.', '<span class="feed-mode">● FIXTURE INPUTS</span>')}
    <section class="health-summary"><article class="panel health-card"><div class="health-card-label">LATEST EXECUTION</div><div class="health-card-value">${model.lastRun ? escapeHtml(model.lastRun) : 'Time unavailable'}</div><div class="health-card-note">Local output files · no scheduler attached</div></article><article class="panel health-card"><div class="health-card-label">PIPELINE RESULT</div><div class="health-card-value"><span class="state-badge healthy">Completed</span></div><div class="health-card-note">${report?.advisories_ingested ?? 0} advisories processed</div></article><article class="panel health-card"><div class="health-card-label">HUMAN REVIEW</div><div class="health-card-value">${report?.needs_human ?? 0} item${report?.needs_human === 1 ? '' : 's'}</div><div class="health-card-note">Unresolved extraction cases</div></article></section>
    <article class="panel" style="margin-bottom:15px"><div class="panel-header"><div><div class="panel-title">Pipeline stages</div><div class="panel-subtitle">Agent counts and timings from run_report.json</div></div><span class="mono-label">${trace.length} stages recorded</span></div><div class="pipeline">${trace.map((stage) => `<div class="pipeline-step"><span class="pipeline-circle">✓</span><strong>${escapeHtml(friendlyName(stage.agent))}</strong><small>${stage.ms ?? '—'} ms</small></div>`).join('')}</div></article>
    <article class="panel" style="margin-bottom:15px"><div class="panel-header"><div><div class="panel-title">Input sources</div><div class="panel-subtitle">These are local fixtures, not live integrations</div></div></div><div class="source-list">${fixtureSources.map((source) => `<div class="source-card"><div class="source-card-head"><span class="source-symbol">${escapeHtml(source.key.slice(0,3).toUpperCase())}</span>${escapeHtml(source.key)}<span class="state-badge healthy" style="margin-left:auto">Loaded</span></div><p><span class="mono">${escapeHtml(source.file)}</span> · ${source.count} records<br>${escapeHtml(source.note)}</p></div>`).join('')}</div></article>
    <article class="panel"><div class="panel-header"><div><div class="panel-title">Agent trace</div><div class="panel-subtitle">Detailed output from the latest run</div></div></div><div class="agent-list"><div class="agent-row agent-header"><div class="agent-name">Stage</div><div class="agent-cell">Items<small>output</small></div><div class="agent-cell">Duration<small>milliseconds</small></div><div class="agent-cell">LLM calls<small>recorded</small></div><div class="agent-cell">State<small>from trace</small></div></div>${trace.map((stage) => {
      const count = stage.alerts ?? stage.scored ?? stage.matches ?? stage.extracted ?? stage.advisories ?? stage.owners ?? '—';
      return `<div class="agent-row"><div class="agent-name"><span class="agent-icon">✓</span>${escapeHtml(friendlyName(stage.agent))}</div><div class="agent-cell">${count}<small>items</small></div><div class="agent-cell">${stage.ms ?? '—'}<small>ms</small></div><div class="agent-cell">${stage.llm_calls ?? 0}<small>${stage.llm || 'no LLM'}</small></div><div>${statusBadge('Recorded', 'healthy')}</div></div>`;
    }).join('')}</div></article>`;
}

function bindPageLinks() {
  document.querySelectorAll('[data-go]').forEach((link) => link.addEventListener('click', () => { activePage = link.dataset.go; }));
}

function bindAlertRows() {
  document.querySelectorAll('tr[data-alert-id]').forEach((row) => {
    row.addEventListener('click', (event) => {
      if (event.target.closest('a')) event.preventDefault();
      openAlert(row.dataset.alertId);
    });
    row.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openAlert(row.dataset.alertId); }
    });
  });
}

function openAlert(alertId) {
  const alert = model.alerts.find((item) => item.alert_id === alertId);
  if (!alert) return;
  const advisory = model.advisories.find((item) => item.id === alert.cve_id);
  const asset = model.inventory.find((item) => item.asset_id === alert.asset_id);
  const criticality = asset?.criticality ? friendlyName(asset.criticality) : 'Not available';
  const isKev = model.kev?.cve_ids?.includes(alert.cve_id) || false;
  const breakdown = {
    CVSS: advisory?.cvss ?? 'Unavailable',
    'KEV bonus': isKev ? '+2.0' : '+0.0',
    'Internet-facing': asset?.internet_facing ? '+1.5' : '+0.0',
    'Asset criticality': ({ critical: '+2.0', high: '+1.0', medium: '+0.0', low: '−1.0' })[asset?.criticality] ?? 'Unavailable',
  };
  drawerRoot.innerHTML = `<div class="drawer-backdrop" data-close-drawer></div><aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title"><div class="drawer-head"><div class="drawer-kicker"><span>ALERT DETAIL · ${escapeHtml(alert.alert_id)}</span><button class="icon-button" type="button" aria-label="Close alert details" data-close-drawer>×</button></div><h2 class="drawer-title" id="drawer-title">${escapeHtml(advisory?.title || alert.cve_id)}</h2><div class="drawer-subtitle mono">${escapeHtml(alert.cve_id)} · ${escapeHtml(sourceLabel(advisory))}</div></div><div class="drawer-body">
    <div class="drawer-status-row">${priorityBadge(alert.priority)}${statusBadge('Affected')}<span class="tag">SLA ${alert.sla_hours} h</span>${isKev ? '<span class="tag kev-tag">KEV-listed</span>' : ''}</div>
    <section class="drawer-block"><h3>Affected service</h3><div class="asset-box"><strong>${escapeHtml(alert.service)}</strong><p>${escapeHtml(alert.component)} ${escapeHtml(alert.installed_version)} → fix ${escapeHtml(alert.fixed_version || 'not published')}</p><div class="asset-meta"><span>Asset <strong class="mono">${escapeHtml(alert.asset_id)}</strong></span><span>Owner <strong>${escapeHtml(alert.owner)}</strong></span><span>${asset?.internet_facing ? 'Internet-facing' : 'Internal'}</span><span>${escapeHtml(criticality)} criticality</span></div></div></section>
    <section class="drawer-block"><h3>Why this priority</h3><div class="score-box"><div class="score-top"><span>Risk score</span><strong>${Number(alert.risk_score).toFixed(1)}</strong></div><div class="score-factors">${Object.entries(breakdown).map(([name, value]) => `<div class="factor-row"><span>${name}</span><strong>${typeof value === 'number' ? value.toFixed(1) : value}</strong></div>`).join('')}</div></div></section>
    <section class="drawer-block"><h3>Recommended action</h3><div class="fix-box"><strong>Upgrade available · source citation not included</strong>${escapeHtml(alert.remediation)}</div></section>
    <section class="drawer-block"><h3>Evidence</h3><ul class="evidence-list">${alert.evidence.map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul></section>
    <section class="drawer-block"><h3>Advisory context</h3><div class="review-callout" style="margin:0">${escapeHtml(advisory?.text || alert.summary)}<br><br><span class="mono-label">Published ${escapeHtml(advisory?.published || 'date unavailable')} · CVSS ${advisory?.cvss ?? 'unavailable'} · KEV ${isKev ? 'Yes' : 'No'}</span></div></section>
    <div class="drawer-footer"><span>Preview only · no status changes are saved</span><button class="button small" type="button" data-copy-alert="${escapeHtml(alert.cve_id)}">Copy CVE ID</button></div>
    </div></aside>`;
  drawerRoot.querySelectorAll('[data-close-drawer]').forEach((element) => element.addEventListener('click', closeDrawer));
  drawerRoot.querySelector('[data-copy-alert]').addEventListener('click', async (event) => {
    const value = event.currentTarget.dataset.copyAlert;
    try { await navigator.clipboard.writeText(value); toast('CVE ID copied'); }
    catch { toast(`CVE ID: ${value}`); }
  });
  document.addEventListener('keydown', onDrawerKeydown, { once: true });
}

function onDrawerKeydown(event) {
  if (event.key === 'Escape') closeDrawer();
  else if (drawerRoot.querySelector('.drawer')) document.addEventListener('keydown', onDrawerKeydown, { once: true });
}

function closeDrawer() { drawerRoot.innerHTML = ''; }
function toast(message) {
  toastRoot.innerHTML = `<div class="toast">${escapeHtml(message)}</div>`;
  setTimeout(() => { toastRoot.innerHTML = ''; }, 2200);
}

  document.querySelectorAll('.nav-item').forEach((link) => link.addEventListener('click', () => { activePage = link.dataset.page; }));
document.querySelector('#global-search').addEventListener('keydown', (event) => {
  if (event.key !== 'Enter') return;
  query = event.currentTarget.value;
  activePage = 'alerts';
  location.hash = 'alerts';
  render();
  document.querySelector('#alert-search')?.focus();
});
document.querySelector('#global-search').addEventListener('input', (event) => {
  if (activePage === 'alerts') {
    query = event.currentTarget.value;
    const localSearch = document.querySelector('#alert-search');
    if (localSearch) localSearch.value = query;
    updateAlertsTable();
  }
});
window.addEventListener('hashchange', () => {
  const hash = location.hash.slice(1);
  if (hash.startsWith('alert/')) { openAlert(decodeURIComponent(hash.slice(6))); return; }
  if (['overview', 'alerts', 'review', 'health'].includes(hash)) { activePage = hash; closeDrawer(); render(); }
  else if (!hash) { activePage = 'overview'; render(); }
});
loadData();
