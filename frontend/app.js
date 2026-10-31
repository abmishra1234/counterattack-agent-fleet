const app = document.querySelector('#app');
const drawerRoot = document.querySelector('#drawer-root');
const toastRoot = document.querySelector('#toast-root');
let model;
let activePage = location.hash.slice(1) || 'overview';
let selectedReview = 0;
let priorityFilter = 'All';
let query = '';
let ownerFilter = 'all';
let usageOffset = 0;
let usageReportOffset = 0;
let usageLoadSequence = 0;

const escapeHtml = (value = '') => String(value).replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));
const checkedHttpUrl = (value) => {
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
};
const niceDate = (value) => value ? new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'Not recorded';
const friendlyName = (value = '') => value.split(/[-_]/).map((part) => part ? part[0].toUpperCase() + part.slice(1) : '').join(' ');
const priorityClass = (priority = 'P4') => `priority-${priority}`;
const sourceLabel = (advisory) => advisory?.source ? friendlyName(advisory.source) : 'Source unavailable';

async function apiRequest(path, options = {}) {
  const response = await fetch(path, { cache: 'no-store', ...options });
  let body;
  try { body = await response.json(); }
  catch { body = null; }
  return { response, body };
}

async function apiGet(path) {
  const { response, body } = await apiRequest(path);
  if (!response.ok) throw new Error(body?.error?.message || `Request failed (${response.status})`);
  return body;
}

async function apiPost(path, payload, headers = {}) {
  const requestHeaders = { ...headers };
  const options = { method: 'POST', headers: requestHeaders };
  if (payload !== undefined) {
    requestHeaders['Content-Type'] = 'application/json';
    options.body = JSON.stringify(payload);
  }
  const { response, body } = await apiRequest(path, options);
  if (!response.ok) throw new Error(body?.error?.message || `Request failed (${response.status})`);
  return body;
}

async function apiCollection(path) {
  const items = [];
  let offset = 0;
  let total = 0;
  do {
    const separator = path.includes('?') ? '&' : '?';
    const result = await apiGet(`${path}${separator}limit=100&offset=${offset}`);
    items.push(...(result.items || []));
    total = Number(result.total ?? items.length);
    const pageSize = Number(result.limit || 100);
    if (!pageSize) break;
    offset += pageSize;
  } while (offset < total);
  return items;
}

async function loadData() {
  try {
    const [context, dashboard, alerts] = await Promise.all([
      apiGet('/api/v1/auth/context'),
      apiGet('/api/v1/dashboard'),
      apiCollection('/api/v1/alerts'),
    ]);
    const optional = await Promise.allSettled([
      context.capabilities.includes('review') ? apiCollection('/api/v1/reviews?state=open') : Promise.resolve([]),
      apiGet('/api/v1/sources'),
      apiGet('/api/v1/health/ready'),
      dashboard.latest_run ? apiGet(`/api/v1/runs/${encodeURIComponent(dashboard.latest_run.id)}`) : Promise.resolve(null),
    ]);
    const partialErrors = [];
    const readOptional = (index, label, fallback) => {
      const result = optional[index];
      if (result.status === 'fulfilled') return result.value;
      partialErrors.push(`${label}: ${result.reason?.message || 'unavailable'}`);
      return fallback;
    };
    const reviews = readOptional(0, 'Review queue', []);
    const sourceResponse = readOptional(1, 'Sources', { items: [] });
    const readinessResult = readOptional(2, 'Readiness', { body: { status: 'unknown', checks: {} } });
    const runDetail = readOptional(3, 'Latest run detail', null);
    const latestRun = dashboard.latest_run;
    const report = latestRun ? {
      ...(runDetail?.summary || latestRun.summary || {}),
      trace: runDetail?.trace || [],
      status: latestRun.status,
    } : null;
    const mappedAlerts = alerts.map((item) => ({ ...item, alert_id: item.id, asset_id: item.asset_key }));
    model = {
      alerts: mappedAlerts,
      needsHuman: reviews,
      sources: sourceResponse.items || [],
      readiness: readinessResult || { status: 'unknown', checks: {} },
      report,
      lastRun: latestRun ? niceDate(latestRun.completed_at || latestRun.created_at) : null,
      capabilities: context.capabilities || [],
      dataMode: context.data_mode || 'unknown',
      persistenceMode: context.persistence_mode || 'unknown',
      llmProvider: context.llm_provider || 'unknown',
      llmLiveCallsEnabled: Boolean(context.llm_live_calls_enabled),
      partialErrors,
    };
    document.querySelectorAll('.nav-item[data-page="review"]').forEach((item) => {
      item.hidden = !model.capabilities.includes('review');
    });
    document.querySelectorAll('.nav-item[data-page="usage"]').forEach((item) => {
      item.hidden = !model.capabilities.includes('usage');
    });
    if (activePage === 'review' && !model.capabilities.includes('review')) activePage = 'overview';
    if (activePage === 'usage' && !model.capabilities.includes('usage')) activePage = 'overview';
    document.querySelector('#top-run-status').textContent = model.lastRun ? `Latest run: ${model.lastRun}` : 'No run recorded';
    document.querySelector('.status-dot').classList.toggle('warning-dot', !model.lastRun);
    document.querySelector('#nav-alert-count').textContent = model.alerts.length;
    document.querySelector('#nav-review-count').textContent = model.needsHuman.length;
    render();
    const initialHash = location.hash.slice(1);
    if (initialHash.startsWith('alert/')) openAlert(decodeURIComponent(initialHash.slice(6)));
  } catch (error) {
    app.innerHTML = `<section class="error-state"><div><div class="empty-icon">!</div><strong>Could not load the workspace</strong><p>${escapeHtml(error.message)} Check the API and database status, then retry.</p><button class="button" id="retry-load" type="button">Retry</button></div></section>`;
    document.querySelector('#retry-load')?.addEventListener('click', loadData);
  }
}
function render() {
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.page === activePage));
  const crumb = document.querySelector('#crumb-page');
  if (crumb) crumb.textContent = ({ overview: 'Today', alerts: 'Alerts', review: 'Needs review', health: 'Run health', usage: 'LLM usage' })[activePage] || 'Today';
  if (activePage === 'alerts') renderAlerts();
  else if (activePage === 'review') renderReview();
  else if (activePage === 'health') renderHealth();
  else if (activePage === 'usage' && model.capabilities.includes('usage')) renderUsage();
  else { activePage = 'overview'; renderOverview(); }
  if (model.partialErrors?.length) {
    app.insertAdjacentHTML('afterbegin', `<div class="banner"><div class="banner-content"><span class="banner-icon">!</span><span><strong>Some workspace details are unavailable.</strong> ${escapeHtml(model.partialErrors.join(' | '))}</span></div></div>`);
  }
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
  return `<div class="table-wrap"><table><thead><tr><th>Priority</th><th>Advisory</th><th>Component</th><th>Service / asset</th><th>Owner</th><th>Assessment</th></tr></thead><tbody>${alertRows(items)}</tbody></table></div>${compact ? `<div class="table-foot"><span>Showing ${items.length} affected assets in this run</span><a href="#alerts" data-go="alerts">View all alerts <span class="arrow">→</span></a></div>` : `<div class="table-foot"><span>API-backed results · ${items.length} items</span><span>Sorted by priority and risk score</span></div>`}`;
}

function renderOverview() {
  const report = model.report;
  const ranked = [...model.alerts].sort((a, b) => a.priority.localeCompare(b.priority) || b.risk_score - a.risk_score);
  const featured = ranked[0];
  const remaining = ranked.slice(1, 4);
  const p1Count = model.alerts.filter((a) => a.priority === 'P1').length;
  const scanCount = report?.trace?.find((x) => x.agent === 'ingest')?.assets ?? '—';
  const runAction = model.capabilities.includes('run')
    ? '<button class="button" id="start-run" type="button">Start analysis</button>'
    : '<span class="scope-pill">Latest run</span>';
  const modeLabel = `Input: ${model.dataMode} | Persistence: ${model.persistenceMode} | LLM: ${model.llmProvider} | live calls ${model.llmLiveCallsEnabled ? 'enabled' : 'gated'}`;
  app.innerHTML = `${pageHeading('SECURITY WORKSPACE', 'Good morning', 'Your latest local run, prioritized for a quick review.', runAction)}
    <div class="page-description">${escapeHtml(modeLabel)}</div>
    <section class="overview-hero-grid" aria-label="Today overview">
      <article class="featured-alert">
        <div class="featured-eyebrow"><span class="featured-star">✦</span> HIGHEST PRIORITY · ${featured ? escapeHtml(featured.priority) : 'CLEAR'}</div>
        <h2>${featured ? escapeHtml(featured.cve_id) : 'No affected assets found'}</h2>
        <p class="featured-summary">${featured ? escapeHtml(featured.summary) : 'The latest run did not identify any confirmed matches.'}</p>
        ${featured ? `<div class="featured-meta"><span>${escapeHtml(featured.service)}</span><span>${escapeHtml(featured.component)} ${escapeHtml(featured.installed_version)}</span><span>Owner · ${escapeHtml(featured.owner)}</span></div><div class="featured-actions"><button class="button featured-button" type="button" data-featured-alert="${escapeHtml(featured.alert_id)}">Review finding <span aria-hidden="true">→</span></button><span class="featured-hint">${escapeHtml(featured.sla_hours)}h response target</span></div>` : ''}
      </article>
      <div class="overview-side-stack">
        <article class="overview-stat-card run-stat-card"><div class="overview-card-top"><span class="overview-card-icon run-icon">✓</span><span class="card-kicker">LATEST RUN</span>${statusBadge(friendlyName(report?.status || 'No run'), report?.status === 'succeeded' ? 'healthy' : 'review')}</div><strong>${escapeHtml(model.lastRun || 'Time not recorded')}</strong><p>${report?.advisories_ingested ?? 0} advisories checked · ${report?.matches ?? 0} matches</p><a href="#health" data-go="health" class="panel-link">View run details <span class="arrow">→</span></a></article>
        <article class="overview-stat-card"><div class="overview-card-top"><span class="overview-card-icon review-icon">◎</span><span class="card-kicker">HUMAN REVIEW</span></div><div class="review-stat-line"><strong>${model.needsHuman.length}</strong><span>item${model.needsHuman.length === 1 ? '' : 's'} need attention</span></div><p>Uncertain advisories stay in the review queue.</p><a href="#review" data-go="review" class="panel-link">Open review queue <span class="arrow">→</span></a></article>
      </div>
    </section>
    <section class="overview-lower-grid">
      <article class="panel today-panel"><div class="panel-header"><div><div class="panel-title">Also in this run</div><div class="panel-subtitle">A short list of other confirmed affected assets</div></div><a class="panel-link" href="#alerts" data-go="alerts">All ${model.alerts.length} findings →</a></div>${remaining.length ? `<div class="finding-list">${remaining.map((item) => `<button class="finding-row" type="button" data-featured-alert="${escapeHtml(item.alert_id)}"><span class="finding-priority ${priorityClass(item.priority)}">${escapeHtml(item.priority)}</span><span class="finding-main"><strong>${escapeHtml(item.cve_id)} <span>· ${escapeHtml(item.component)}</span></strong><small>${escapeHtml(item.service)} · ${escapeHtml(item.owner)}</small></span><span class="finding-score">${Number(item.risk_score).toFixed(1)}<small>risk</small></span><span class="finding-arrow">→</span></button>`).join('')}</div>` : '<div class="empty-inline">No additional findings in this run.</div>'}</article>
      <article class="panel posture-panel"><div class="panel-header"><div><div class="panel-title">Run snapshot</div><div class="panel-subtitle">Latest persisted run</div></div><span class="snapshot-count">${model.alerts.length}</span></div><div class="snapshot-total"><strong>${model.alerts.length}</strong><span>affected assets</span></div><div class="priority-chart snapshot-chart">${priorityChart()}</div><div class="snapshot-footer"><span>${scanCount} inventory assets scanned</span><span>${p1Count} P1</span></div></article>
    </section>`;
  bindPageLinks();
  document.querySelectorAll('[data-featured-alert]').forEach((button) => button.addEventListener('click', () => openAlert(button.dataset.featuredAlert)));
  document.querySelector('#start-run')?.addEventListener('click', startManualRun);
}

async function startManualRun(event) {
  const button = event.currentTarget;
  button.disabled = true;
  const status = document.querySelector('#top-run-status');
  const idempotencyKey = globalThis.crypto?.randomUUID?.()
    || `manual-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  try {
    status.textContent = 'Queueing analysis...';
    const accepted = await apiPost('/api/v1/runs', undefined, { 'Idempotency-Key': idempotencyKey });
    const runId = accepted.run_id || accepted.run?.id;
    if (!runId) throw new Error('The API accepted the run without returning its ID.');
    toast(accepted.deduplicated ? 'Existing analysis run resumed' : 'Analysis queued');
    status.textContent = `Analysis ${accepted.run?.status || 'queued'} · ${runId}`;
    for (let attempt = 0; attempt < 90; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      const run = await apiGet(`/api/v1/runs/${encodeURIComponent(runId)}`);
      status.textContent = `Analysis ${run.status} · ${runId}`;
      if (['succeeded', 'failed', 'partial'].includes(run.status)) {
        toast(run.status === 'succeeded' ? 'Analysis completed' : `Analysis ${run.status}`);
        await loadData();
        return;
      }
    }
    status.textContent = `Analysis still running · ${runId}`;
    toast('Analysis is still running; check Run health for updates');
  } catch (error) {
    status.textContent = 'Analysis request failed';
    toast(error.message || 'Could not start analysis');
  } finally {
    const currentButton = document.querySelector('#start-run');
    if (currentButton) currentButton.disabled = false;
  }
}

function renderAlerts() {
  const items = model.alerts.filter((alert) => {
    const matchesPriority = priorityFilter === 'All' || alert.priority === priorityFilter;
    const matchesOwner = ownerFilter === 'all' || alert.owner === ownerFilter;
    const searchText = [alert.cve_id, alert.asset_id, alert.service, alert.component, alert.owner].join(' ').toLowerCase();
    return matchesPriority && matchesOwner && searchText.includes(query.trim().toLowerCase());
  });
  app.innerHTML = `${pageHeading('WORKSPACE / ALERTS', 'Affected assets', 'Review each confirmed match, its priority and the evidence used by the latest run.', '<span class="feed-mode">LATEST RUN</span>')}
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
    app.innerHTML = `${pageHeading('WORKSPACE / REVIEW', 'Needs review', 'Advisories the fleet could not safely resolve from the available evidence.')}<article class="panel"><div class="empty-state"><div><div class="empty-icon">!</div><strong>No advisories need review</strong><p>Unclear or ungrounded items from the latest run will appear here.</p></div></div></article>`;
    return;
  }
  selectedReview = Math.min(selectedReview, items.length - 1);
  const item = items[selectedReview];
  const evidence = item.source_evidence || {};
  const decisionHistory = (item.decisions || []).map((decision) => `<div class="decision-history-row"><strong>${escapeHtml(friendlyName(decision.disposition))}</strong> - ${escapeHtml(decision.actor_id)} - ${escapeHtml(niceDate(decision.created_at))}<p>${escapeHtml(decision.note || '')}</p></div>`).join('');
  const candidateMatches = item.candidate_matches || [];
  const candidateMatchHtml = candidateMatches.length ? candidateMatches.map((match) => `<div class="review-callout"><strong>${escapeHtml(friendlyName(match.outcome))}</strong> · ${escapeHtml(match.asset_id)} · ${escapeHtml(match.component)} ${escapeHtml(match.installed_version)}<p>Affected range: ${escapeHtml(match.affected_range || 'Unavailable')} · Comparator confidence: ${match.confidence == null ? 'Unknown' : `${Math.round(match.confidence * 100)}%`}</p><p>${escapeHtml((match.evidence || []).join(' · '))}</p></div>`).join('') : '<p class="page-description">No comparable asset version was available for this review case.</p>';
  const candidateMatchLimit = item.candidate_matches_truncated ? '<p class="page-description">Additional candidate comparisons are omitted from this response.</p>' : '';
  app.innerHTML = `${pageHeading('WORKSPACE / REVIEW QUEUE', 'Needs review', 'The fleet leaves uncertain cases for a human instead of guessing.', `<span class="state-badge review">${items.length} open item${items.length === 1 ? '' : 's'}</span>`)}
    <div class="review-layout"><article class="panel"><div class="panel-header"><div class="panel-title">Review queue</div><span class="table-caption">${items.length} item${items.length === 1 ? '' : 's'}</span></div><div class="review-list">${items.map((entry, index) => `<button class="review-item ${index === selectedReview ? 'selected' : ''}" data-review-index="${index}"><div class="review-item-top"><strong>${escapeHtml(entry.cve_id || entry.advisory_id)}</strong><small>${escapeHtml(friendlyName(entry.stage))}</small></div><div class="review-item-title">${escapeHtml(entry.title || 'Advisory details unavailable')}</div><div class="review-item-reason">${escapeHtml(entry.reason)}</div></button>`).join('')}</div></article>
    <article class="panel review-detail"><div class="review-detail-header">${statusBadge('Human review required', 'review')}<h2>${escapeHtml(item.cve_id || item.advisory_id)}</h2><p class="lead">${escapeHtml(item.title || 'Advisory details unavailable')}</p></div><div class="review-callout"><strong>Why it was held:</strong> ${escapeHtml(item.reason)} The system did not produce a confirmed affected-product and version-range match.</div><div class="review-section-title">Candidate version comparisons</div>${candidateMatchHtml}${candidateMatchLimit}<div class="review-section-title">Source bulletin</div><div class="bulletin">${escapeHtml(evidence.text || 'Source text is not available.')}</div><div class="review-section-title">Available context</div><div class="source-list-inline"><span class="tag">Source: ${escapeHtml(sourceLabel(evidence))}</span><span class="tag">Published: ${escapeHtml(evidence.published || 'Unknown')}</span><span class="tag">CVSS: ${evidence.cvss ?? 'Not provided'}</span></div><div class="review-section-title">Decision history</div>${decisionHistory || '<p class="page-description">No decisions have been recorded for this case.</p>'}<form id="review-decision-form" class="review-decision-form"><strong>Record an analyst decision</strong><label class="field-label" for="review-disposition">Disposition</label><select id="review-disposition" class="select-control" required><option value="affected_confirmed">Affected confirmed</option><option value="possible_match">Possible match</option><option value="not_affected">Not affected</option><option value="insufficient_evidence">Insufficient evidence</option></select><label class="field-label" for="review-note-input">Decision note</label><textarea id="review-note-input" class="text-input" minlength="1" maxlength="2000" required></textarea><button class="button small" type="submit">Save audited decision</button></form></article></div>`;
  document.querySelectorAll('[data-review-index]').forEach((button) => button.addEventListener('click', () => { selectedReview = Number(button.dataset.reviewIndex); renderReview(); }));
  document.querySelector('#review-decision-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await apiPost(`/api/v1/reviews/${encodeURIComponent(item.id)}/decision`, {
        disposition: document.querySelector('#review-disposition').value,
        note: document.querySelector('#review-note-input').value,
      });
      toast('Decision saved to the audit trail');
      await loadData();
    } catch (error) {
      toast(error.message || 'Could not save decision');
      button.disabled = false;
    }
  });
}

function renderHealth() {
  const report = model.report;
  const trace = report?.trace || [];
  const readiness = model.readiness || { status: 'unknown', checks: {} };
  const sourceCards = model.sources.length ? model.sources.map((source) => {
    const state = source.health || source.last_status || (source.enabled ? 'unknown' : 'disabled');
    const kind = state === 'healthy' ? 'healthy' : 'review';
    const failures = Number(source.failure_count || 0);
    return `<div class="source-card"><div class="source-card-head"><span class="source-symbol">${escapeHtml(source.name.slice(0, 3).toUpperCase())}</span>${escapeHtml(source.name)}<span class="state-badge ${kind}" style="margin-left:auto">${escapeHtml(friendlyName(state))}</span></div><p>${escapeHtml(friendlyName(source.source_type))}<br>${source.last_success_at ? `Last success ${escapeHtml(niceDate(source.last_success_at))}` : 'No successful poll recorded'}${failures ? `<br>Consecutive failures: ${escapeHtml(String(failures))}` : ''}${source.last_error_code ? `<br>Error: ${escapeHtml(source.last_error_code)}` : ''}</p></div>`;
  }).join('') : '<div class="empty-inline">No configured sources are registered.</div>';
  const checkCards = Object.entries(readiness.checks || {}).map(([name, state]) => `<span class="tag">${escapeHtml(friendlyName(name))}: ${escapeHtml(state)}</span>`).join('');
  const runState = report?.status || 'No run recorded';
  const runKind = ['succeeded', 'completed'].includes(String(runState).toLowerCase()) ? 'healthy' : 'review';
  app.innerHTML = `${pageHeading('WORKSPACE / RUN HEALTH', 'Run health', 'Inspect the latest persisted execution, configured sources and service readiness.', `<span class="feed-mode">${escapeHtml(String(readiness.status || 'unknown').toUpperCase())}</span>`)}
    <section class="health-summary"><article class="panel health-card"><div class="health-card-label">LATEST EXECUTION</div><div class="health-card-value">${model.lastRun ? escapeHtml(model.lastRun) : 'Time unavailable'}</div><div class="health-card-note">Persisted run history</div></article><article class="panel health-card"><div class="health-card-label">PIPELINE RESULT</div><div class="health-card-value">${statusBadge(friendlyName(runState), runKind)}</div><div class="health-card-note">${report?.advisories_ingested ?? 0} advisories processed</div></article><article class="panel health-card"><div class="health-card-label">HUMAN REVIEW</div><div class="health-card-value">${report?.needs_human ?? 0} items</div><div class="health-card-note">Cases opened by latest run</div></article></section>
    <article class="panel" style="margin-bottom:15px"><div class="panel-header"><div><div class="panel-title">Service checks</div><div class="panel-subtitle">Readiness is reported without exposing connection details</div></div></div><div class="source-list-inline">${checkCards || '<span class="tag">No readiness checks reported</span>'}</div></article>
    <article class="panel" style="margin-bottom:15px"><div class="panel-header"><div><div class="panel-title">Pipeline stages</div><div class="panel-subtitle">Agent counts and timings from the latest persisted run</div></div><span class="mono-label">${trace.length} stages recorded</span></div><div class="pipeline">${trace.map((stage) => `<div class="pipeline-step"><span class="pipeline-circle">&#10003;</span><strong>${escapeHtml(friendlyName(stage.agent))}</strong><small>${stage.ms ?? 'Not recorded'} ms</small></div>`).join('')}</div></article>
    <article class="panel" style="margin-bottom:15px"><div class="panel-header"><div><div class="panel-title">Configured sources</div><div class="panel-subtitle">Feed state and the latest successful poll</div></div></div><div class="source-list">${sourceCards}</div></article>
    <article class="panel"><div class="panel-header"><div><div class="panel-title">Agent trace</div><div class="panel-subtitle">Detailed output from the latest run</div></div></div><div class="agent-list"><div class="agent-row agent-header"><div class="agent-name">Stage</div><div class="agent-cell">Items<small>output</small></div><div class="agent-cell">Duration<small>milliseconds</small></div><div class="agent-cell">LLM calls<small>recorded</small></div><div class="agent-cell">State<small>from trace</small></div></div>${trace.map((stage) => {
      const count = stage.alerts ?? stage.scored ?? stage.matches ?? stage.extracted ?? stage.advisories ?? stage.owners ?? 'Not recorded';
      return `<div class="agent-row"><div class="agent-name"><span class="agent-icon">&#10003;</span>${escapeHtml(friendlyName(stage.agent))}</div><div class="agent-cell">${count}<small>items</small></div><div class="agent-cell">${stage.ms ?? 'Not recorded'}<small>ms</small></div><div class="agent-cell">${stage.llm_calls ?? 0}<small>${stage.llm || 'no LLM'}</small></div><div>${statusBadge('Recorded', 'healthy')}</div></div>`;
    }).join('')}</div></article>`;
}
function renderUsage() {
  app.innerHTML = `${pageHeading('OPERATIONS / MODEL AUDIT', 'LLM usage & cost', 'Review model attempts, spend estimates, usage totals and protected prompt or response artifacts.')}
    <section class="usage-filter-panel panel">
      <form id="llm-usage-filter" class="usage-filter-grid">
        <label><span>Since</span><input class="usage-input" name="since" type="datetime-local"></label>
        <label><span>Until</span><input class="usage-input" name="until" type="datetime-local"></label>
        <label><span>Run ID</span><input class="usage-input" name="run_id" maxlength="36" placeholder="Filter by run"></label>
        <label><span>Request ID</span><input class="usage-input" name="request_id" maxlength="64" placeholder="Filter by request"></label>
        <label><span>Job ID</span><input class="usage-input" name="job_id" maxlength="36" placeholder="Filter by job"></label>
        <label><span>Provider</span><input class="usage-input" name="provider" maxlength="80" placeholder="Provider"></label>
        <label><span>Model</span><input class="usage-input" name="model" maxlength="160" placeholder="Model"></label>
        <label><span>Task</span><input class="usage-input" name="task" maxlength="40" placeholder="extract, summarise…"></label>
        <label><span>Advisory</span><input class="usage-input" name="advisory_id" maxlength="80" placeholder="CVE or advisory ID"></label>
        <label><span>Actor</span><input class="usage-input" name="actor_id" maxlength="200" placeholder="Actor identity"></label>
        <label><span>Prompt version</span><input class="usage-input" name="prompt_version" maxlength="100" placeholder="Prompt version"></label>
        <label><span>Outcome</span><select class="select-control" name="outcome"><option value="">All outcomes</option><option value="succeeded">Succeeded</option><option value="failed">Failed</option><option value="unknown">Unknown</option><option value="pending">Pending</option></select></label>
        <label><span>Group report by</span><select class="select-control" name="group_by"><option value="day">Day (UTC)</option><option value="run">Run</option><option value="task">Task</option><option value="provider">Provider</option><option value="model">Model</option><option value="prompt_version">Prompt version</option><option value="advisory">Advisory</option><option value="actor">Actor</option><option value="outcome">Outcome</option></select></label>
        <button class="button primary usage-filter-submit" type="submit">Apply filters</button>
      </form>
    </section>
    <div id="llm-usage-results" class="usage-results"><div class="panel loading-inline"><span class="spinner"></span>Loading usage records…</div></div>`;
  const filter = document.querySelector('#llm-usage-filter');
  filter.addEventListener('submit', (event) => {
    event.preventDefault();
    usageOffset = 0;
    usageReportOffset = 0;
    loadUsageResults(filter);
  });
  loadUsageResults(filter);
}

function usageQuery(values) {
  const params = new URLSearchParams();
  for (const key of ['run_id', 'request_id', 'job_id', 'provider', 'model', 'task', 'advisory_id', 'actor_id', 'prompt_version', 'outcome']) {
    const value = String(values[key] || '').trim();
    if (value) params.set(key, value);
  }
  for (const key of ['since', 'until']) {
    if (values[key]) {
      const date = new Date(values[key]);
      if (!Number.isNaN(date.valueOf())) params.set(key, date.toISOString());
    }
  }
  return params;
}

async function loadUsageResults(filterForm) {
  const sequence = ++usageLoadSequence;
  const values = Object.fromEntries(new FormData(filterForm).entries());
  const baseParams = usageQuery(values);
  const reportParams = new URLSearchParams(baseParams);
  reportParams.set('group_by', values.group_by || 'day');
  reportParams.set('limit', '50');
  reportParams.set('offset', String(usageReportOffset));
  const callParams = new URLSearchParams(baseParams);
  callParams.set('limit', '25');
  callParams.set('offset', String(usageOffset));
  const results = document.querySelector('#llm-usage-results');
  if (!results) return;
  results.innerHTML = '<div class="panel loading-inline"><span class="spinner"></span>Loading usage records…</div>';
  try {
    const runId = String(values.run_id || '').trim();
    const budgetPath = runId ? `/api/v1/llm/budgets?run_id=${encodeURIComponent(runId)}` : '/api/v1/llm/budgets';
    const [usage, report, budgets] = await Promise.all([
      apiGet(`/api/v1/llm/usage?${callParams.toString()}`),
      apiGet(`/api/v1/llm/usage/report?${reportParams.toString()}`),
      apiGet(budgetPath),
    ]);
    if (sequence !== usageLoadSequence || !document.querySelector('#llm-usage-results')) return;
    const knownCosts = Object.entries(usage.known_cost_by_currency || {})
      .map(([currency, amount]) => `${escapeHtml(currency)} ${escapeHtml(amount)}`).join(' · ') || 'No priced calls';
    const month = budgets.month_to_date || {};
    const runBudget = budgets.run || null;
    const calls = (usage.items || []).map((item) => `<tr>
      <td>${escapeHtml(niceDate(item.started_at))}<small class="usage-subline">${escapeHtml(item.id.slice(0, 8))} · attempt ${item.attempt_number}</small></td>
      <td><strong>${escapeHtml(friendlyName(item.task))}</strong><small class="usage-subline">${escapeHtml(item.provider)} · ${escapeHtml(item.model)}</small></td>
      <td>${statusBadge(friendlyName(item.outcome), item.outcome === 'succeeded' ? 'healthy' : 'review')}</td>
      <td>${item.input_tokens ?? '—'} in · ${item.output_tokens ?? '—'} out<small class="usage-subline">${item.total_tokens ?? 'Usage unknown'} tokens</small></td>
      <td>${item.cost_amount == null ? 'Unknown' : `${escapeHtml(item.cost_currency || 'USD')} ${escapeHtml(item.cost_amount)}`}<small class="usage-subline">Reserve ${item.budget_estimate_usd == null ? '—' : `$${escapeHtml(item.budget_estimate_usd)}`}</small></td>
      <td class="mono">${escapeHtml(item.run_id || '—')}<small class="usage-subline">Request ${escapeHtml(item.request_id || '—')}</small></td>
      <td><button class="button small" type="button" data-llm-call="${escapeHtml(item.id)}">Details</button></td>
    </tr>`).join('') || '<tr><td colspan="7"><div class="no-results">No model calls match these filters.</div></td></tr>';
    const groups = (report.groups || []).map((group) => `<tr>
      <td>${escapeHtml(String(group.key ?? 'Unassigned'))}</td><td>${group.calls}</td><td>${group.retries}</td>
      <td>${group.total_tokens || 0}<small class="usage-subline">${group.unknown_token_calls} calls without full token counts</small></td>
      <td>${escapeHtml(group.currency)} ${escapeHtml(group.known_cost)}<small class="usage-subline">Reserved USD ${escapeHtml(group.budget_enforced_cost_usd)}</small></td>
      <td>${group.unknown_outcome_calls}<small class="usage-subline">${group.pending_calls} pending</small></td>
      <td>${group.unknown_cost_calls}</td>
    </tr>`).join('') || '<tr><td colspan="7"><div class="no-results">No grouped usage data matches these filters.</div></td></tr>';
    const total = Number(usage.total || 0);
    const limit = Number(usage.limit || 25);
    const offset = Number(usage.offset || 0);
    results.innerHTML = `
      <section class="usage-metrics">
        ${metricCard('Recorded calls', report.total_calls || 0, `${report.total_retries || 0} retries`, '#3b5ccc', '↗')}
        ${metricCard('Known cost', knownCosts, `${usage.unknown_cost_calls || 0} calls have unknown cost`, '#07856f', '$')}
        ${metricCard('Unresolved outcome', Number(report.unknown_outcome_calls || 0) + Number(report.pending_calls || 0), `${report.unknown_outcome_calls || 0} unknown · ${report.pending_calls || 0} pending`, '#b76e0d', '!')}
        ${metricCard('Month budget used', `$${escapeHtml(month.budget_enforced_usd || '0')}`, `${escapeHtml(friendlyName(month.limit_status || 'unknown'))} · configured ${budgets.configured_limits_usd?.per_month || 'not set'}`, '#6547c7', '◷')}
      </section>
      ${runBudget ? `<article class="panel usage-budget-note"><strong>Selected run budget:</strong> $${escapeHtml(runBudget.budget_enforced_usd || '0')} · ${escapeHtml(friendlyName(runBudget.limit_status || 'unknown'))} · ${runBudget.remaining_usd == null ? 'remaining amount unavailable' : `${escapeHtml(runBudget.remaining_usd)} USD remaining`}</article>` : ''}
      <article class="panel usage-report-panel"><div class="panel-header"><div><div class="panel-title">Aggregate report</div><div class="panel-subtitle">${escapeHtml(friendlyName(report.group_by))} · ${report.total_groups} groups</div></div><span class="tag">${report.unknown_outcome_calls} unknown outcomes</span></div>
        <div class="table-wrap"><table class="usage-table"><thead><tr><th>${escapeHtml(friendlyName(report.group_by))}</th><th>Calls</th><th>Retries</th><th>Tokens</th><th>Known cost</th><th>Unknown / pending</th><th>Unknown cost</th></tr></thead><tbody>${groups}</tbody></table></div>
        <div class="table-foot"><span>Showing ${report.total_groups ? report.offset + 1 : 0}–${Math.min(report.offset + report.limit, report.total_groups)} of ${report.total_groups} groups</span><div class="usage-pagination"><button class="button small" type="button" id="usage-report-prev" ${report.offset <= 0 ? 'disabled' : ''}>Previous</button><button class="button small" type="button" id="usage-report-next" ${!report.has_more ? 'disabled' : ''}>Next</button></div></div>
      </article>
      <article class="panel usage-calls-panel"><div class="panel-header"><div><div class="panel-title">Individual attempts</div><div class="panel-subtitle">${total} calls match the filters · prompt/response content is permission-gated</div></div><span class="tag">${total ? offset + 1 : 0}–${Math.min(offset + limit, total)} of ${total}</span></div>
        <div class="table-wrap"><table class="usage-table"><thead><tr><th>Started</th><th>Task / model</th><th>Outcome</th><th>Token usage</th><th>Cost</th><th>Run / request</th><th></th></tr></thead><tbody>${calls}</tbody></table></div>
        <div class="table-foot"><span>Page ${Math.floor(offset / limit) + 1}</span><div class="usage-pagination"><button class="button small" type="button" id="usage-prev" ${offset <= 0 ? 'disabled' : ''}>Previous</button><button class="button small" type="button" id="usage-next" ${offset + limit >= total ? 'disabled' : ''}>Next</button></div></div>
      </article>`;
    results.querySelector('#usage-prev')?.addEventListener('click', () => { usageOffset = Math.max(0, offset - limit); loadUsageResults(filterForm); });
    results.querySelector('#usage-next')?.addEventListener('click', () => { usageOffset = offset + limit; loadUsageResults(filterForm); });
    results.querySelector('#usage-report-prev')?.addEventListener('click', () => { usageReportOffset = Math.max(0, Number(report.offset || 0) - Number(report.limit || 50)); loadUsageResults(filterForm); });
    results.querySelector('#usage-report-next')?.addEventListener('click', () => { usageReportOffset = Number(report.offset || 0) + Number(report.limit || 50); loadUsageResults(filterForm); });
    results.querySelectorAll('[data-llm-call]').forEach((button) => button.addEventListener('click', () => openLLMCall(button.dataset.llmCall)));
  } catch (error) {
    if (sequence !== usageLoadSequence || !document.querySelector('#llm-usage-results')) return;
    results.innerHTML = `<div class="panel error-inline"><strong>Usage report unavailable</strong><p>${escapeHtml(error.message)}</p><button class="button" type="button" id="usage-retry">Retry</button></div>`;
    results.querySelector('#usage-retry')?.addEventListener('click', () => loadUsageResults(filterForm));
  }
}

async function openLLMCall(callId) {
  drawerRoot.innerHTML = '<div class="drawer-backdrop" data-close-drawer></div><aside class="drawer" role="dialog" aria-modal="true"><div class="drawer-body">Loading call metadata…</div></aside>';
  try {
    const item = await apiGet(`/api/v1/llm/usage/${encodeURIComponent(callId)}`);
    const contentCapability = model.capabilities.includes('llm_content');
    const artifacts = (item.artifacts || []).map((artifact) => `<button class="button small" type="button" data-artifact-kind="${escapeHtml(artifact.kind)}">View ${escapeHtml(friendlyName(artifact.kind))}</button>`).join('');
    drawerRoot.innerHTML = `<div class="drawer-backdrop" data-close-drawer></div><aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="llm-drawer-title"><div class="drawer-head"><div class="drawer-kicker"><span>MODEL CALL · ${escapeHtml(item.id)}</span><button class="icon-button" type="button" aria-label="Close call details" data-close-drawer>&times;</button></div><h2 class="drawer-title" id="llm-drawer-title">${escapeHtml(friendlyName(item.task))}</h2><div class="drawer-subtitle">${escapeHtml(item.provider)} · ${escapeHtml(item.model)} · ${escapeHtml(friendlyName(item.outcome))}</div></div><div class="drawer-body">
      <section class="drawer-block"><h3>Correlation</h3><div class="usage-detail-grid"><span>Run<strong>${escapeHtml(item.run_id || '—')}</strong></span><span>Request<strong>${escapeHtml(item.request_id || '—')}</strong></span><span>Job<strong>${escapeHtml(item.job_id || '—')}</strong></span><span>Parent call<strong>${escapeHtml(item.parent_call_id || '—')}</strong></span><span>Actor<strong>${escapeHtml(item.actor_id || '—')}</strong></span><span>Advisory<strong>${escapeHtml(item.advisory_id || '—')}</strong></span><span>Prompt version<strong>${escapeHtml(item.prompt_version)}</strong></span><span>Prompt hash<strong>${escapeHtml(item.prompt_hash)}</strong></span><span>Attempt<strong>${item.attempt_number}</strong></span></div></section>
      <section class="drawer-block"><h3>Usage and cost</h3><div class="review-callout">Input ${item.input_tokens ?? 'unknown'} tokens · output ${item.output_tokens ?? 'unknown'} · total ${item.total_tokens ?? 'unknown'}<br>Cost ${item.cost_amount == null ? 'unknown' : `${escapeHtml(item.cost_currency || 'USD')} ${escapeHtml(item.cost_amount)}`} · reserved USD ${item.budget_estimate_usd == null ? '—' : escapeHtml(item.budget_estimate_usd)}<br>Outcome ${escapeHtml(item.outcome)} · ${item.latency_ms ?? 'latency unavailable'} ms${item.safe_error_code ? `<br>Recorded error: ${escapeHtml(item.safe_error_code)}` : ''}</div></section>
      <section class="drawer-block"><h3>Captured artifacts</h3>${contentCapability ? `<p class="page-description">Each read requires a purpose and is recorded in the audit log.</p><label class="field-label" for="artifact-purpose">Access purpose</label><input id="artifact-purpose" class="usage-input" minlength="8" maxlength="500" placeholder="Explain why you need to inspect this content"><div class="artifact-buttons">${artifacts || '<span class="page-description">No retained artifacts are available.</span>'}</div><pre class="artifact-content" id="artifact-content" hidden></pre>` : '<p class="page-description">Artifact content requires the LLM audit reader capability. Metadata remains visible to usage readers.</p>'}</section>
      </div></aside>`;
    drawerRoot.querySelectorAll('[data-close-drawer]').forEach((element) => element.addEventListener('click', closeDrawer));
    drawerRoot.querySelectorAll('[data-artifact-kind]').forEach((button) => button.addEventListener('click', async () => {
      const purpose = drawerRoot.querySelector('#artifact-purpose').value.trim();
      if (purpose.length < 8) { toast('Add a specific access purpose of at least 8 characters.'); return; }
      button.disabled = true;
      try {
        const result = await apiPost(`/api/v1/llm/usage/${encodeURIComponent(callId)}/content`, { kind: button.dataset.artifactKind, purpose });
        const content = typeof result.content === 'string' ? result.content : JSON.stringify(result.content, null, 2);
        const panel = drawerRoot.querySelector('#artifact-content');
        panel.textContent = content;
        panel.hidden = false;
      } catch (error) { toast(error.message || 'Could not read captured content'); }
      finally { button.disabled = false; }
    }));
    document.addEventListener('keydown', onDrawerKeydown, { once: true });
  } catch (error) {
    closeDrawer();
    toast(error.message || 'Could not load model call details');
  }
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

async function openAlert(alertId) {
  const baseAlert = model.alerts.find((item) => item.alert_id === alertId);
  if (!baseAlert) return;
  drawerRoot.innerHTML = '<div class="drawer-backdrop" data-close-drawer></div><aside class="drawer" role="dialog" aria-modal="true"><div class="drawer-body">Loading finding details...</div></aside>';
  try {
    const detail = await apiGet(`/api/v1/alerts/${encodeURIComponent(alertId)}`);
    const alert = { ...baseAlert, ...detail, alert_id: detail.id, asset_id: detail.asset_key };
    const advisory = detail.advisory || {};
    const asset = detail.asset_context || {};
    const match = detail.match || {};
    const matchHistory = detail.match_history || [];
    const matchHistoryHtml = matchHistory.length
      ? matchHistory.map((entry) => `<div class="review-callout match-history-item"><strong>${escapeHtml(friendlyName(entry.outcome))}</strong> · ${escapeHtml(entry.component)} ${escapeHtml(entry.installed_version)}<p>Compared ${escapeHtml(entry.compared_at || 'date unavailable')} · Run ${escapeHtml((entry.run_id || '').slice(0, 8) || 'unknown')} · ${escapeHtml(entry.comparator || 'comparator unavailable')}</p><p>Affected range: ${escapeHtml(entry.affected_range || 'unavailable')} · Confidence: ${entry.confidence == null ? 'not quantified' : `${Math.round(entry.confidence * 100)}%`}</p><p>${escapeHtml((entry.evidence || []).join(' · '))}</p></div>`).join('')
      : '<p class="page-description">No earlier comparison records are available.</p>';
    const matchHistoryLimit = detail.match_history_truncated
      ? '<p class="page-description">Showing the 20 most recent comparisons.</p>'
      : '';
    const criticality = asset.criticality ? friendlyName(asset.criticality) : 'Not available';
    const isKev = Boolean(advisory.in_kev);
    const epss = advisory.epss || null;
    const epssUrl = checkedHttpUrl(epss?.source_url);
    const epssHtml = !epss
      ? '<p class="page-description">EPSS enrichment is not available for this advisory.</p>'
      : epss.status === 'available'
        ? `<p class="page-description">EPSS likelihood: ${typeof epss.score === 'number' ? `${(epss.score * 100).toFixed(2)}%` : 'unavailable'}${typeof epss.percentile === 'number' ? ` · ${(epss.percentile * 100).toFixed(1)}th percentile` : ''} · Score date ${escapeHtml(epss.score_date || 'unavailable')} · Retrieved ${escapeHtml(niceDate(epss.observed_at))}${epssUrl ? ` · <a href="${escapeHtml(epssUrl)}" target="_blank" rel="noopener noreferrer">EPSS source</a>` : ''}</p>`
        : `<p class="page-description">No EPSS score was returned · Retrieved ${escapeHtml(niceDate(epss.observed_at))}${epssUrl ? ` · <a href="${escapeHtml(epssUrl)}" target="_blank" rel="noopener noreferrer">EPSS source</a>` : ''}</p>`;
    const sourceLinks = (Array.isArray(detail.source_references) ? detail.source_references : [])
      .map((reference) => {
        const url = checkedHttpUrl(reference?.url);
        if (!url) return null;
        const label = reference.source || new URL(url).hostname;
        return `<li><a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>${Array.isArray(reference.tags) && reference.tags.length ? ` · ${escapeHtml(reference.tags.join(', '))}` : ''}</li>`;
      })
      .filter(Boolean);
    const remediationSourceLinks = (Array.isArray(detail.remediation_sources) ? detail.remediation_sources : [])
      .map((reference) => {
        const url = checkedHttpUrl(reference?.url);
        if (!url) return null;
        const label = reference.source || new URL(url).hostname;
        return `<li><a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>${Array.isArray(reference.tags) && reference.tags.length ? ` · ${escapeHtml(reference.tags.join(', '))}` : ''}</li>`;
      })
      .filter(Boolean);
    const citationsHtml = sourceLinks.length
      ? `<ul class="evidence-list">${sourceLinks.join('')}</ul>`
      : '<div class="review-callout" style="margin:0">No validated advisory reference is available.</div>';
    const remediationCitationsHtml = remediationSourceLinks.length
      ? `<ul class="evidence-list">${remediationSourceLinks.join('')}</ul>`
      : '<div class="review-callout" style="margin:0">No patch or mitigation reference is tagged in the source data. Treat this action as unverified and request analyst review.</div>';
    const citationStatusLabel = detail.remediation_citation_status === 'cited' && remediationSourceLinks.length
      ? 'Supporting patch or mitigation reference available'
      : 'Unverified · no tagged supporting reference';
    const storedBreakdown = alert.score_breakdown || {};
    const breakdown = {
      CVSS: storedBreakdown.cvss ?? advisory.cvss ?? 'Unavailable',
      'KEV bonus': storedBreakdown.kev ?? 'Unavailable',
      'Internet-facing': storedBreakdown.internet_facing ?? 'Unavailable',
      'Asset criticality': storedBreakdown.criticality ?? 'Unavailable',
      'KEV + internet-facing P1 rule': storedBreakdown.kev_internet_p1_override
        ? 'Applied'
        : 'Not applied',
    };
    drawerRoot.innerHTML = `<div class="drawer-backdrop" data-close-drawer></div><aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title"><div class="drawer-head"><div class="drawer-kicker"><span>ALERT DETAIL - ${escapeHtml(alert.alert_id)}</span><button class="icon-button" type="button" aria-label="Close alert details" data-close-drawer>&times;</button></div><h2 class="drawer-title" id="drawer-title">${escapeHtml(advisory.title || alert.cve_id)}</h2><div class="drawer-subtitle mono">${escapeHtml(alert.cve_id)} - ${escapeHtml(sourceLabel(advisory))}</div></div><div class="drawer-body">
      <div class="drawer-status-row">${priorityBadge(alert.priority)}${statusBadge('Affected')}<span class="tag">SLA ${alert.sla_hours} h</span>${isKev ? '<span class="tag kev-tag">KEV-listed</span>' : ''}</div>
      <section class="drawer-block"><h3>Affected service</h3><div class="asset-box"><strong>${escapeHtml(alert.service)}</strong><p>${escapeHtml(alert.component)} ${escapeHtml(alert.installed_version)} -&gt; fix ${escapeHtml(alert.fixed_version || 'not published')}</p><div class="asset-meta"><span>Asset <strong class="mono">${escapeHtml(alert.asset_id)}</strong></span><span>Owner <strong>${escapeHtml(alert.owner)}</strong></span><span>${asset.internet_facing ? 'Internet-facing' : 'Internal'}</span><span>${escapeHtml(criticality)} criticality</span></div></div></section>
      <section class="drawer-block"><h3>Why this priority <span class="mono-label">Policy ${escapeHtml(detail.policy_version || 'unknown')}</span></h3><div class="score-box"><div class="score-top"><span>Risk score</span><strong>${Number(alert.risk_score).toFixed(1)}</strong></div><div class="score-factors">${Object.entries(breakdown).map(([name, value]) => `<div class="factor-row"><span>${escapeHtml(name)}</span><strong>${typeof value === 'number' ? value.toFixed(1) : escapeHtml(value)}</strong></div>`).join('')}</div></div></section>
      <section class="drawer-block"><h3>Recommended action</h3><div class="fix-box"><strong>Recommended remediation</strong><p>${escapeHtml(alert.remediation)}</p><span class="mono-label">${escapeHtml(citationStatusLabel)}</span></div></section>
      <section class="drawer-block"><h3>Remediation evidence</h3>${remediationCitationsHtml}</section>
      <section class="drawer-block"><h3>Source references</h3>${citationsHtml}</section>
      <section class="drawer-block"><h3>Impact assessment</h3><div class="review-callout" style="margin:0">${escapeHtml(alert.summary)}</div></section>
      <section class="drawer-block"><h3>Match decision</h3><div class="review-callout" style="margin:0">${escapeHtml(friendlyName(match.outcome || 'affected'))} · ${escapeHtml(match.comparator || 'comparator unavailable')} · Confidence ${match.confidence == null ? 'not quantified' : `${Math.round(match.confidence * 100)}%`}<br>Affected range: ${escapeHtml(match.affected_range || 'unavailable')}</div><ul class="evidence-list">${[...new Set([...(match.evidence || []), ...(alert.evidence || [])])].map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul></section>
       <section class="drawer-block"><h3>Comparison history</h3>${matchHistoryHtml}${matchHistoryLimit}</section>
      <section class="drawer-block"><h3>Advisory context</h3><div class="review-callout" style="margin:0">${escapeHtml(advisory.text || alert.summary)}<br><br><span class="mono-label">Published ${escapeHtml(advisory.published || 'date unavailable')} | CVSS ${advisory.cvss ?? 'unavailable'} | KEV ${isKev ? 'Yes' : 'No'}</span>${epssHtml}</div></section>
      <div class="drawer-footer"><span>Evidence from the persisted run</span><button class="button small" type="button" data-copy-alert="${escapeHtml(alert.cve_id)}">Copy CVE ID</button></div>
      </div></aside>`;
    drawerRoot.querySelectorAll('[data-close-drawer]').forEach((element) => element.addEventListener('click', closeDrawer));
    drawerRoot.querySelector('[data-copy-alert]').addEventListener('click', async (event) => {
      const value = event.currentTarget.dataset.copyAlert;
      try { await navigator.clipboard.writeText(value); toast('CVE ID copied'); }
      catch { toast(`CVE ID: ${value}`); }
    });
    document.addEventListener('keydown', onDrawerKeydown, { once: true });
  } catch (error) {
    closeDrawer();
    toast(error.message || 'Could not load finding details');
  }
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
  if (['overview', 'alerts', 'review', 'health', 'usage'].includes(hash)) { activePage = hash; closeDrawer(); render(); }
  else if (!hash) { activePage = 'overview'; render(); }
});
loadData();
