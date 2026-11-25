const state = {
  apiUrl: localStorage.getItem('safeguard.apiUrl') || 'http://localhost:8000/v1',
  token: localStorage.getItem('safeguard.token') || '',
  gatewayId: localStorage.getItem('safeguard.gatewayId') || 'ussd',
  gatewaySecret: localStorage.getItem('safeguard.gatewaySecret') || '',
  gatewayMsisdn: localStorage.getItem('safeguard.gatewayMsisdn') || '0241234567',
  authPhone: localStorage.getItem('safeguard.authPhone') || '',
  // Live API is the product path. Demo mode must be explicitly enabled and
  // never masquerades as a backend fraud decision.
  demo: localStorage.getItem('safeguard.demo') === 'true',
  liteStep: 'menu',
  ussdAwarenessDraft: null,
  ussdAwarenessCheckup: null,
  ussdAwarenessPollTimer: null,
  ussdAwarenessRefreshing: false,
  voiceMemoryEnabled: false,
  voiceMessages: [],
  voiceStatus: '',
  voiceRecorder: null,
  voiceRecognition: null,
  voiceRecordingTimer: null,
  caseId: localStorage.getItem('safeguard.caseId') || '',
  gatewayCaseId: localStorage.getItem('safeguard.gatewayCaseId') || '',
  lastRisk: null,
  nexusEntityId: null,
  nexusGraphHistory: [],
  nexusActiveCase: null,
  nexusSelectedEvidence: null,
  nexusGraphView: { scale: 1, x: 0, y: 0 },
  nexusGraphData: null,
  nexusVisibleTreeEdgeIndexes: null,
  nexusGraphSize: { width: 920, height: 520 },
  nexusNodePositions: null,
  nexusSelectedNodeId: null,
  nexusDetailRequestId: 0,
  nexusIntakeContext: null,
  nexusReportId: null,
  nexusCollection: null,
  nexusCollectionTab: 'overview',
  nexusReferralPartners: [],
  nexusReferrals: [],
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

// Keep the Atlas navigation available even if a later, optional admin widget
// fails during startup initialization.
document.addEventListener('click', event => {
  const atlasButton = event.target.closest('#open-atlas');
  if (!atlasButton) return;
  event.preventDefault();
  switchView('atlas');
});

function setModeLabel() {
  $('#mode-pill').textContent = state.demo ? 'DEMO' : 'LIVE API';
  $('#connection-label').textContent = state.demo ? 'Demo mode active' : 'Connected to API';
}

function mockShield(text) {
  const lower = text.toLowerCase();
  const suspicious = /(otp|pin|password|urgent|send money|verify|account.*close|bit\.ly|tinyurl)/.test(lower);
  const rules = [];
  if (/otp|pin|password/.test(lower)) rules.push('credential request');
  if (/bank|momo|official|support/.test(lower)) rules.push('impersonation');
  if (/urgent|immediately|now|close/.test(lower)) rules.push('urgency');
  if (/https?:\/\/|bit\.ly|tinyurl/.test(lower)) rules.push('suspicious link');
  const level = rules.length >= 3 ? 'critical' : rules.length ? 'high' : 'low';
  return { risk_level: level, risk_score: suspicious ? Math.min(.96, .52 + rules.length * .11) : .04, ai: { label: rules.includes('credential request') ? 'account_takeover' : suspicious ? 'suspicious' : 'benign', confidence: suspicious ? .89 : .62 }, rules, explanation: suspicious ? `Detected ${rules.join(', ')}. Do not share PINs, codes or money.` : 'No high-signal scam pattern detected.' };
}

async function apiRequest(path, options = {}) {
  if (state.demo) return null;
  const isBlobBody = typeof Blob !== 'undefined' && options.body instanceof Blob;
  const headers = { ...(isBlobBody ? {} : { 'Content-Type': 'application/json' }), ...(options.headers || {}) };
  if (isBlobBody && !headers['Content-Type']) headers['Content-Type'] = options.body.type || 'application/octet-stream';
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const requestOptions = { ...options };
  if (options.gateway) {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const rawBody = options.body || '';
    const bodyBytes = isBlobBody ? new Uint8Array(await rawBody.arrayBuffer()) : new TextEncoder().encode(rawBody);
    const signaturePrefix = new TextEncoder().encode(`${timestamp}.`);
    const signingBytes = new Uint8Array(signaturePrefix.length + bodyBytes.length);
    signingBytes.set(signaturePrefix);
    signingBytes.set(bodyBytes, signaturePrefix.length);
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(state.gatewaySecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, signingBytes);
    headers['X-Gateway-Id'] = state.gatewayId;
    headers['X-Timestamp'] = timestamp;
    headers['X-Signature'] = [...new Uint8Array(signature)].map(byte => byte.toString(16).padStart(2, '0')).join('');
    delete requestOptions.gateway;
  }
  let response;
  try {
    response = await fetch(`${state.apiUrl.replace(/\/$/, '')}${path}`, { ...requestOptions, headers });
  } catch (error) {
    const origin = window.location.origin;
    throw new Error(`Cannot reach SafeGuard API at ${state.apiUrl}. Check that FastAPI is running, the API URL is correct, and this frontend origin (${origin}) is allowed by backend CORS settings. ${error.message || ''}`.trim());
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) {
      state.token = '';
      localStorage.removeItem('safeguard.token');
      throw new Error('Your session is invalid or expired. Open Settings and sign in again.');
    }
    throw new Error(body?.error?.message || `API request failed (${response.status})`);
  }
  return body;
}

async function authRequest(path, body) {
  const response = await fetch(`${state.apiUrl.replace(/\/$/, '')}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data?.error?.message || `Authentication failed (${response.status})`);
  return data;
}

async function conversationAdapterTurn(message, channel) {
  if (!state.token) throw new Error('Connect with a SafeGuard access token first.');
  const data = await apiRequest('/conversation/adapter-turn', {
    method: 'POST',
    body: JSON.stringify({ message, channel, case_id: state.caseId || undefined }),
  });
  rememberCase(data.case_id);
  return data;
}

async function requestOtp() {
  const phone = $('#auth-phone').value.trim();
  if (!phone) return $('#auth-status').textContent = 'Enter your phone number first.';
  try { await authRequest('/auth/otp/request', { phone }); state.authPhone = phone; localStorage.setItem('safeguard.authPhone', phone); $('#auth-status').textContent = 'OTP requested. Read the code in the backend console, then enter it above.'; } catch (error) { $('#auth-status').textContent = error.message; }
}

async function verifyOtp() {
  const phone = $('#auth-phone').value.trim(); const code = $('#auth-code').value.trim();
  if (!phone || !code) return $('#auth-status').textContent = 'Enter both your phone number and OTP code.';
  try { const data = await authRequest('/auth/otp/verify', { phone, code }); state.authPhone = phone; state.token = data.access_token; state.demo = false; $('#api-token').value = data.access_token; $('#demo-mode').checked = false; localStorage.setItem('safeguard.authPhone', phone); localStorage.setItem('safeguard.token', data.access_token); localStorage.setItem('safeguard.demo', 'false'); setModeLabel(); $('#auth-status').textContent = 'Token received. You can now use live API mode.'; loadSmartReports(); } catch (error) { $('#auth-status').textContent = error.message; }
}

function showResult(target, title, message, level = 'low') {
  const box = $(target); box.classList.remove('hidden', 'danger'); if (level === 'high' || level === 'critical') box.classList.add('danger');
  box.innerHTML = `<strong>${title}</strong><span>${message}</span>`;
}

function rememberCase(caseId) {
  if (!caseId) return;
  state.caseId = caseId;
  localStorage.setItem('safeguard.caseId', caseId);
}

function rememberGatewayCase(caseId) {
  if (!caseId) return;
  state.gatewayCaseId = caseId;
  localStorage.setItem('safeguard.gatewayCaseId', caseId);
}

async function loadIntelligenceCapabilities() {
  if (state.demo) return;
  try {
    const data = await apiRequest('/intelligence/capabilities');
    const source = data.source_of_truth || 'backend';
    logGateway('READY', `Unified intelligence ${data.contract_version || 'contract'} loaded from ${source}.`);
  } catch (error) {
    logGateway('ERROR', `Unified intelligence contract unavailable: ${error.message}`);
  }
}

function rememberRisk(data) {
  if (!data) return;
  state.lastRisk = data;
  rememberCase(data.case_id);
}

async function analyzeSmartMessage() {
  const text = $('#smart-message').value.trim(); if (!text) return showResult('#smart-result', 'Add a message first', 'Paste the SMS or chat message you want to check.');
  try {
    if (state.demo) { const data = mockShield(text); rememberRisk(data); return showResult('#smart-result', `${data.risk_level.toUpperCase()} risk · ${data.ai.label}`, data.explanation, data.risk_level); }
    const data = await conversationAdapterTurn(text, 'app');
    const intel = data.intelligence || {};
    const risk = String(intel.risk_level || 'unknown').toLowerCase();
    rememberRisk({ ...intel, case_id: data.case_id, reasons: intel.risk_evidence || [] });
    showResult('#smart-result', `${risk.toUpperCase()} risk · SafeGuard`, data.reply, risk);
  } catch (error) { showResult('#smart-result', 'Could not analyze message', error.message, 'high'); }
}

async function checkSmartNumber() {
  const number = $('#smart-number').value.trim();
  if (!number) return showResult('#smart-number-result', 'Enter a phone number', 'Enter the number you want to check.');
  const body = { number, channel: 'app', case_id: state.caseId || undefined };
  try {
    const data = state.demo
      ? { phone: number, known: false, risk_level: 'low', risk_score: .04, verified_reports: 0, pending_reports: 0, short_message: `No reports for ${number}. Still, never share your PIN or codes.` }
      : await apiRequest('/numbers/lookup', { method: 'POST', body: JSON.stringify(body) });
    rememberCase(data.case_id);
    rememberRisk(data);
    const counts = `${data.verified_reports || 0} verified, ${data.pending_reports || 0} pending report(s).`;
    const graph = data.graph_exposure_sentence ? ` NEXUS graph: ${data.graph_exposure_sentence}` : '';
    showResult('#smart-number-result', `${String(data.risk_level || 'unknown').toUpperCase()} risk`, `${data.short_message || data.advice} ${counts}${graph}`, data.risk_level);
  } catch (error) {
    showResult('#smart-number-result', 'Could not check number', error.message, 'high');
  }
}

async function submitSmartReport() {
  const report = $('#smart-report-message').value.trim();
  if (report.length < 10) return showResult('#smart-report-result', 'Add report details', 'Enter at least 10 characters describing the scam.');
  const body = { subject: report.slice(0, 512), report_type: 'other', channel: 'app', description: report, case_id: state.caseId || undefined };
  try {
    const data = state.demo ? { status: 'submitted', message: 'Your report was submitted for review.' } : await apiRequest('/community/reports', { method: 'POST', body: JSON.stringify(body) });
    rememberCase(data.case_id);
    showResult('#smart-report-result', 'Report received', data.message || `Report status: ${data.status || 'pending'}. Thank you for helping protect the community.`);
    if (!state.demo) void loadSmartReports();
  } catch (error) { showResult('#smart-report-result', 'Could not submit report', error.message, 'high'); }
}

function reportHistoryTitle(report) {
  const text = String(report.description || report.subject || '').toLowerCase();
  if (/delivery|package|courier|parcel/.test(text)) return 'Delivery scam report';
  if (/momo|mobile money|mobilemoney/.test(text)) return /stole|stolen|theft|lost|loss|took/.test(text) ? 'Mobile money theft report' : 'Mobile money scam report';
  if (/phish|link|otp|pin|password|verify|verification/.test(text)) return 'Phishing or account access report';
  if (/impersonat|pretend|posing as|fake agent/.test(text)) return 'Impersonation scam report';
  if (/stole|stolen|theft|lost|loss/.test(text)) return 'Money loss report';
  return 'Scam report';
}

async function loadSmartReports() {
  const list = $('#smart-reports-list');
  const owner = $('#smart-reports-owner');
  if (owner) owner.textContent = state.authPhone ? `Reports submitted from ${state.authPhone}` : 'Reports submitted from your verified phone number';
  if (!state.token || state.demo) {
    list.innerHTML = '<p class="helper">Sign in to view reports submitted from your phone number.</p>';
    return;
  }
  list.innerHTML = '<p class="helper">Loading your reports…</p>';
  try {
    const [community, legacy] = await Promise.all([
      apiRequest('/community/reports/mine?limit=100&offset=0'),
      apiRequest('/reports/mine?limit=100&offset=0'),
    ]);
    const reports = [
      ...(community?.items || []).map(report => ({ ...report, history_title: reportHistoryTitle(report) })),
      ...(legacy?.items || []).map(report => ({ ...report, history_title: reportHistoryTitle(report) })),
    ].sort((left, right) => new Date(right.created_at) - new Date(left.created_at));
    list.innerHTML = reports.length ? reports.map(report => {
      const status = String(report.status || 'submitted').replaceAll('_', ' ');
      const statusClass = ['under review', 'accepted', 'verified'].includes(status) ? 'review' : 'pending';
      return `<div class="intelligence-signal"><div><strong>${escapeHtml(report.history_title)}<small>${escapeHtml(relativeTime(report.created_at))}</small></strong><span class="status ${statusClass}">${escapeHtml(status)}</span></div></div>`;
    }).join('') : '<p class="helper">No reports submitted from this phone number yet.</p>';
  } catch (error) {
    list.innerHTML = `<p class="helper">Could not load your reports: ${escapeHtml(error.message)}</p>`;
  }
}

function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char])); }
function relativeTime(value) { const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60000)); return minutes < 60 ? `${minutes} min ago` : `${Math.round(minutes / 60)} hr ago`; }
function renderAdminDashboard(data) {
  $('#metric-fir-reports').textContent = Number(data.fraud_reports || 0).toLocaleString();
  $('#metric-investigations').textContent = Number(data.active_investigations || 0).toLocaleString();
  $('#metric-signals').textContent = Number(data.suspicious_signals || 0).toLocaleString();
  $('#metric-partners').textContent = Number(data.connected_partners || 0).toLocaleString();
  renderAdminReportRows(data.recent_reports || [], { limit: 5 });
  $('#admin-data-status').textContent = `Live admin data loaded at ${new Date().toLocaleTimeString()}.`;
}
function adminReportRowMarkup(report) {
  return `<tr><td>${escapeHtml(report.phone)}</td><td>${escapeHtml(report.report_type)}</td><td>${relativeTime(report.created_at)}</td><td><span class="status ${report.status === 'under_review' ? 'review' : 'pending'}">${escapeHtml(String(report.status).replace('_', ' '))}</span></td><td><button class="table-action" data-report-id="${escapeHtml(report.id)}" data-report-action="open">Open</button></td></tr>`;
}
function renderAdminReportRows(reports, options = {}) {
  const limit = options.limit;
  const slice = limit ? reports.slice(0, limit) : reports;
  const empty = '<tr><td colspan="5">No reports found.</td></tr>';
  const html = slice.length ? slice.map(adminReportRowMarkup).join('') : empty;
  $('#reports-table').innerHTML = html;
  if ($('#admin-reports-table')) {
    const full = reports.length ? reports.map(adminReportRowMarkup).join('') : empty;
    $('#admin-reports-table').innerHTML = full;
  }
}
function renderMonitoringSignalActions(signal) {
  const entityId = signal.entity_ids?.[0];
  if (entityId) {
    return `<div class="monitoring-actions" aria-label="Investigate signal"><button type="button" class="table-action" data-open-nexus="${escapeHtml(entityId)}">NEXUS</button></div>`;
  }
  return `<div class="monitoring-actions" aria-label="Investigate signal"><button type="button" class="table-action" data-open-atlas-signal="${escapeHtml(signal.signal_type || '')}">ATLAS</button></div>`;
}
function renderMonitoringEntityRow(entity) {
  const label = escapeHtml(entity.display_value || entity.type || 'Entity');
  const title = escapeHtml(entity.display_value || entity.type || 'Entity');
  const atlasQuery = escapeHtml(entity.display_value || entity.type || '');
  return `<tr><td class="entity-cell"><span class="entity-cell-label" title="${title}">${label}</span><small class="entity-type">${escapeHtml(entity.type || 'unknown')}</small></td><td><span class="status ${['high', 'critical'].includes(entity.risk_level) ? 'pending' : 'review'}">${escapeHtml(entity.risk_level || '—')}</span></td><td>${Math.round(Number(entity.risk_score || 0) * 100)}%</td><td class="entity-activity-cell"><span class="entity-activity-label" title="${Number(entity.graph_features?.transaction_count || 0)} tx · ${Number(entity.graph_features?.partner_count || 0)} providers">${Number(entity.graph_features?.transaction_count || 0)} tx · ${Number(entity.graph_features?.partner_count || 0)} providers</span></td><td class="entity-investigate-col"><div class="monitoring-actions"><button type="button" class="table-action" data-open-nexus="${escapeHtml(entity.id)}">NEXUS</button><button type="button" class="table-action" data-open-atlas-entity="${atlasQuery}">ATLAS</button></div></td></tr>`;
}
function renderMonitoringSignals(signals) {
  $('#intelligence-signals').innerHTML = signals.length ? signals.map(signal => `<article class="intelligence-signal"><div class="intelligence-signal-heading"><b>${escapeHtml(signal.signal_type.replaceAll('_', ' '))}</b><span class="status ${['high', 'critical'].includes(signal.risk_level) ? 'pending' : 'review'}">${escapeHtml(signal.risk_level)} · ${Math.round(Number(signal.score || 0) * 100)}%</span></div><p>${escapeHtml((signal.reasons || []).join(' '))}</p><small>${escapeHtml((signal.partner_codes || []).join(' · '))} · ${relativeTime(signal.created_at)}</small>${renderMonitoringSignalActions(signal)}</article>`).join('') : '<p class="helper">No active detections or shared signals.</p>';
}
function renderMonitoringEntities(entities) {
  $('#intelligence-entities').innerHTML = entities.length ? entities.map(renderMonitoringEntityRow).join('') : '<tr><td colspan="5">No ranked entity profiles yet.</td></tr>';
}
function renderAdminMonitoring(data) {
  const distribution = data.risk_distribution || {};
  const total = Object.values(distribution).reduce((sum, value) => sum + value, 0) || 1;
  const riskOrder = [['low', 'bar-low'], ['medium', 'bar-medium'], ['high', 'bar-high'], ['critical', 'bar-critical']];
  $$('#admin-fraud-monitoring .risk-bars>div').forEach((row, index) => {
    const [level, barClass] = riskOrder[index];
    const count = distribution[level] || 0;
    const percent = Math.round(count / total * 100);
    const bar = row.querySelector('b');
    bar.className = barClass;
    bar.style.width = `${Math.max(percent, count ? 3 : 0)}%`;
    row.querySelector('strong').textContent = `${percent}%`;
  });
  const effectiveness = data.feedback_effectiveness || {};
  const note = $('#admin-monitoring-note p');
  if (note) {
    note.innerHTML = `<b>Feedback loop</b><br />${Number(effectiveness.interventions_delivered || 0).toLocaleString()} interventions · ${Math.round(Number(effectiveness.follow_rate || 0) * 100)}% advice followed.`;
  }
  renderMonitoringSignals(data.recent_signals || []);
  renderMonitoringEntities(data.top_entities || []);
}
async function loadAdminMonitoring() {
  if (state.demo) {
    renderMonitoringSignals([]);
    renderMonitoringEntities([]);
    return;
  }
  try {
    const data = await apiRequest('/admin/monitoring');
    renderAdminMonitoring(data);
  } catch (error) {
    $('#intelligence-signals').innerHTML = `<p class="helper">${escapeHtml(error.message)}</p>`;
    $('#intelligence-entities').innerHTML = `<tr><td colspan="5">${escapeHtml(error.message)}</td></tr>`;
  }
}
async function openAdminNexus(entityId, title = 'Investigation') {
  if (!entityId) return;
  switchView('nexus');
  await openNexusEntity(entityId, title);
}
function openAdminAtlasSearch(query) {
  if (query) $('#atlas-search').value = query;
  switchView('atlas', { skipAtlasLoad: true });
  loadAtlas();
}
function configureAwarenessCampaignStudio() {
  const frame = $('#awareness-campaign-studio');
  if (!frame || !state.apiUrl.trim()) return;
  const apiRoot = state.apiUrl.trim().replace(/(?:\/api)?\/v\d+\/?$/, '').replace(/\/+$/, '');
  const studioUrl = `${apiRoot}/campaign-studio`;
  if (frame.dataset.studioUrl !== studioUrl) {
    frame.dataset.studioUrl = studioUrl;
    frame.src = studioUrl;
  }
}
function showAdminDashboardError(message) {
  $('#metric-fir-reports').textContent = '—';
  $('#metric-investigations').textContent = '—';
  $('#metric-signals').textContent = '—';
  $('#metric-partners').textContent = '—';
  $('#reports-table').innerHTML = `<tr><td colspan="5">${escapeHtml(message)}</td></tr>`;
  $$('#admin-fraud-monitoring .risk-bars>div').forEach(row => {
    row.querySelector('b').style.width = '0%';
    row.querySelector('strong').textContent = '—';
  });
  const note = $('#admin-monitoring-note p');
  if (note) note.innerHTML = `<b>Live data unavailable.</b><br />${escapeHtml(message)}`;
  $('#admin-data-status').textContent = message;
}
async function loadAdminDashboard() {
  if (state.demo) {
    showAdminDashboardError('Demo mode is enabled. Switch to Live API mode and sign in as an administrator to load real dashboard data.');
    $('#intelligence-status').textContent = 'Switch off Demo mode and sign in as an administrator to view stored FIR/PDR intelligence or populate demo records.';
    renderAwarenessOperationsUnavailable('Demo mode has no live subscription or delivery data.');
    return;
  }
  try { const data = await apiRequest('/admin/dashboard'); renderAdminDashboard(data); }
  catch (error) { showAdminDashboardError(error.message); logGateway('ERROR', `Dashboard could not load: ${error.message}`); }
  await Promise.all([loadAdminPartners(), loadAdminMonitoring(), loadAdminIntelligence(), loadAwarenessOperations()]);
}

function renderAwarenessOperationsUnavailable(message) {
  $('#awareness-ops-status').textContent = 'Unavailable';
  $('#awareness-ops-status').className = 'pill neutral';
  $('#awareness-ops-next-run').textContent = 'Next run: unavailable';
  $('#awareness-scheduler-note').textContent = message;
  ['awareness-ops-subscribers', 'awareness-ops-checkups', 'awareness-ops-alerts', 'awareness-ops-drafts'].forEach(id => { $(`#${id}`).textContent = '—'; });
  $('#awareness-ops-frequency').textContent = 'No live data';
  $('#awareness-ops-due').textContent = '—';
  $('#awareness-ops-checkups-pending').textContent = 'Pending check-ups: —';
  $('#awareness-ops-deliveries').innerHTML = '<span class="helper">No live delivery data.</span>';
  $('#awareness-ops-last-delivery').textContent = 'Last successful delivery: —';
  $('#awareness-ops-sms-channel').textContent = 'Unknown';
  $('#awareness-ops-voice-channel').textContent = 'Unknown';
  $('#awareness-ops-methods').textContent = '';
}
async function loadAwarenessOperations() {
  if (state.demo) return renderAwarenessOperationsUnavailable('Demo mode has no live subscription or delivery data.');
  try {
    const data = await apiRequest('/admin/awareness/operations');
    const subscriptions = data.subscriptions || {};
    const scheduler = data.scheduler || {};
    const schedulerLabels = { healthy: 'Recurring worker active', stale: 'Worker is stale', failed: 'Last run failed', running: 'Worker running', starting: 'Worker starting', disabled: 'Worker disabled', manual_run: 'Manual run only' };
    $('#awareness-ops-status').textContent = schedulerLabels[scheduler.status] || 'Worker status unknown';
    $('#awareness-ops-status').className = `pill ${scheduler.status === 'healthy' ? 'green' : scheduler.status === 'failed' ? 'red' : 'amber'}`;
    $('#awareness-ops-next-run').textContent = scheduler.next_run_at
      ? `Next run: ${new Date(scheduler.next_run_at).toLocaleString()}`
      : `Checks every ${Number(scheduler.interval_seconds || 300)} seconds`;
    $('#awareness-scheduler-note').textContent = scheduler.detail || 'Scheduler status unavailable.';
    $('#awareness-ops-due').textContent = Number(scheduler.due_subscribers || 0).toLocaleString();
    $('#awareness-ops-checkups-pending').textContent = `Pending check-ups: ${Number(scheduler.pending_checkups || 0).toLocaleString()} · 1-minute tests: ${Number(scheduler.test_schedules || 0).toLocaleString()}`;
    $('#awareness-ops-subscribers').textContent = Number(subscriptions.active || 0).toLocaleString();
    $('#awareness-ops-checkups').textContent = Number(subscriptions.checkups_enabled || 0).toLocaleString();
    $('#awareness-ops-alerts').textContent = Number(subscriptions.fraud_alerts_enabled || 0).toLocaleString();
    $('#awareness-ops-drafts').textContent = Number(data.campaigns?.awaiting_review || 0).toLocaleString();
    const frequencyLabels = { weekly: 'weekly', biweekly: 'biweekly', monthly: 'monthly', custom: 'custom' };
    const frequencies = Object.entries(subscriptions.frequency || {}).map(([key, count]) => `${Number(count).toLocaleString()} ${frequencyLabels[key] || key}`);
    $('#awareness-ops-frequency').textContent = frequencies.length ? frequencies.join(' · ') : 'No active subscriber schedules';
    const deliveries = data.deliveries_24h || {};
    const deliveryMarkup = Object.entries(deliveries).map(([channel, counts]) => {
      const detail = Object.entries(counts).map(([status, count]) => `${Number(count).toLocaleString()} ${status}`).join(' · ');
      return `<span><b>${escapeHtml(channel)}</b> ${escapeHtml(detail || 'no recent deliveries')}</span>`;
    }).join('');
    $('#awareness-ops-deliveries').innerHTML = deliveryMarkup || '<span class="helper">No recorded deliveries in the last 24 hours.</span>';
    $('#awareness-ops-last-delivery').textContent = data.last_delivery_at
      ? `Last successful delivery: ${new Date(data.last_delivery_at).toLocaleString()}`
      : 'Last successful delivery: none recorded';
    const sms = data.channels?.sms || {};
    $('#awareness-ops-sms-channel').textContent = sms.mode === 'http_provider' ? 'HTTP provider configured' : 'Console only · no carrier delivery';
    const voice = data.channels?.voice_call || {};
    $('#awareness-ops-voice-channel').textContent = voice.operational ? 'Connected' : 'Not connected';
    const methods = Object.entries(subscriptions.delivery_method || {}).map(([method, count]) => `${Number(count).toLocaleString()} opted for ${method.replaceAll('_', ' ')}`);
    $('#awareness-ops-methods').textContent = methods.length ? methods.join(' · ') : 'No active delivery preferences';
  } catch (error) {
    renderAwarenessOperationsUnavailable(`Could not load awareness operations: ${error.message}`);
    $('#awareness-ops-status').textContent = 'Load failed';
  }
}
async function runAwarenessSchedulerNow() {
  if (state.demo) return alert('Switch to Live API mode and sign in as a reviewer or administrator to run the scheduler.');
  if (!window.confirm('Ask the awareness agent to prepare or update a draft for due subscribers? No message is delivered until a reviewer approves it. One-minute test subscribers are simulated in SafeGuard Lite after approval.')) return;
  const button = $('#awareness-ops-run');
  button.disabled = true;
  button.textContent = 'Processing…';
  try {
    const result = await apiRequest('/admin/awareness/scheduler/run-now', { method: 'POST' });
    $('#awareness-scheduler-note').textContent = result.detail || `Scheduler checked ${result.due_count} due subscriber(s); ${result.deferred_count} deferred. No message is delivered before approval.`;
    await Promise.all([loadAwarenessOperations(), loadAwarenessCampaigns()]);
  } catch (error) {
    $('#awareness-scheduler-note').textContent = `Could not run scheduler: ${error.message}`;
  } finally {
    button.disabled = false;
    button.textContent = 'Generate due drafts now';
  }
}

function renderAdminIntelligence(data) {
  const fir = data.fir || {}; const pdr = data.pdr || {};
  $('#intelligence-source-summary').innerHTML = [
    ['FIR reports', fir.reports || 0], ['Partners', pdr.partners || 0],
    ['PDR identities', pdr.identities || 0], ['Accounts', pdr.accounts || 0],
    ['Transactions', pdr.transactions || 0],
  ].map(([label, value]) => `<span>${escapeHtml(label)} <b>${Number(value).toLocaleString()}</b></span>`).join('');

  const layers = [
    ['Identity Intelligence', data.identity?.clusters || 0, `${data.identity?.resolved || 0} resolved · ${data.identity?.candidates || 0} candidates`],
    ['Entity Intelligence', data.entities?.profiles || 0, 'enriched entity profiles'],
    ['Fraud Network Graph', data.graph?.nodes || 0, `${data.graph?.edges || 0} relationships`],
    ['Fraud / Risk Intelligence', data.fraud_risk?.high_or_critical || 0, 'high or critical profiles'],
    ['Cross-Institution Intelligence', data.cross_institution?.active_signals || 0, 'active cross-provider signals'],
    ['Multi-layer AI + Graph', data.ai_graph?.profiles || 0, data.ai_graph?.fusion_version || 'fused profiles'],
    ['Liveness Detection', data.liveness?.assessments || 0, `${data.liveness?.by_status?.live || 0} live · ${data.liveness?.by_status?.spoof || 0} spoof attestations`],
    ['Real-time Detection', data.real_time_detection?.active_signals || 0, 'active detection signals'],
    ['Real-time Intelligence Sharing', data.sharing?.pending || 0, `${data.sharing?.acknowledged || 0} alerts acknowledged · pending now`],
  ];
  $('#intelligence-layer-grid').innerHTML = layers.map(([name, value, detail]) => `<article class="intelligence-layer-card"><span class="eyebrow">${escapeHtml(name)}</span><strong>${Number(value).toLocaleString()}</strong><p>${escapeHtml(detail)}</p></article>`).join('');

  const signals = data.recent_signals || [];
  configureAwarenessCampaignStudio();
  renderMonitoringSignals(signals);
  renderMonitoringEntities(data.top_entities || []);
  state.lastIntelligenceDashboard = data.dashboard || {};
  renderIntelligenceAnalytics(state.lastIntelligenceDashboard);
  $('#intelligence-status').textContent = `Updated from the live API · ${new Date().toLocaleTimeString()}.`;
  loadAwarenessCampaigns();
}

const TREND_CHART_HEIGHT_PX = 96;
function intelligenceTrendsMetrics(dashboard) {
  const data = dashboard || {};
  const risks = Array.isArray(data.risk_trends) ? data.risk_trends : [];
  const riskTotal = item => ['low', 'medium', 'high', 'critical'].reduce(
    (sum, level) => sum + Number(item?.[level] || 0), 0,
  );
  return {
    assessments: risks.reduce((sum, day) => sum + riskTotal(day), 0),
    report14: Number(data.reports?.last_14_days || 0),
    signals: Number(data.fraud_signals?.active || 0),
    reportsTotal: Number(data.reports?.total || 0),
  };
}
function intelligenceTrendsFootnote(dashboard) {
  const { assessments, report14, signals } = intelligenceTrendsMetrics(dashboard);
  return `${assessments.toLocaleString()} FIR assessments in the 14-day window · ${report14.toLocaleString()} reports · ${signals.toLocaleString()} active signals`;
}
function renderIntelligenceTrendsSummaryCards(metrics) {
  setIntelligenceAnalyticsText('analytics-summary-assessments', metrics.assessments.toLocaleString());
  setIntelligenceAnalyticsText('analytics-summary-reports', metrics.report14.toLocaleString());
  setIntelligenceAnalyticsText('analytics-summary-signals', metrics.signals.toLocaleString());
  setIntelligenceAnalyticsText('analytics-risk-card-stat', `${metrics.assessments.toLocaleString()} FIR assessments in 14-day window`);
  setIntelligenceAnalyticsText('analytics-report-card-stat', `${metrics.report14.toLocaleString()} received in the last 14 days`);
  setIntelligenceAnalyticsText('analytics-signal-card-stat', `${metrics.signals.toLocaleString()} cross-institution active signals`);
}
function updateIntelligenceTrendsHint(dashboard) {
  const hint = $('#intelligence-trends-hint');
  if (!hint) return;
  const risks = Array.isArray(dashboard?.risk_trends) ? dashboard.risk_trends : [];
  const hasWindowData = risks.some(day => ['low', 'medium', 'high', 'critical'].some(
    level => Number(day?.[level] || 0) > 0,
  ));
  hint.hidden = hasWindowData;
}
function analyticsTrendDayLabel(day) {
  const raw = day?.date ?? day?.day ?? '';
  const text = String(raw);
  return text.length >= 5 ? text.slice(5) : text || '—';
}
function intelligenceAnalyticsEl(id) {
  const panel = $('#intelligence-analytics-panel');
  return panel?.querySelector(`#${id}`) || document.getElementById(id);
}
function setIntelligenceAnalyticsText(id, value) {
  const el = intelligenceAnalyticsEl(id);
  if (el) el.textContent = value;
}
function setIntelligenceAnalyticsHtml(id, html) {
  const el = intelligenceAnalyticsEl(id);
  if (el) el.innerHTML = html;
}
function renderMobileMoneyTactics(summary = {}) {
  const period = $('#analytics-tactic-period')?.value || '90d';
  const tactics = (summary.techniques || []).map(item => ({
    ...item, tally: item.periods?.[period] || { reports: 0 },
  })).filter(item => Number(item.tally.reports || 0) > 0)
    .sort((a, b) => Number(b.tally.reports || 0) - Number(a.tally.reports || 0));
  const target = intelligenceAnalyticsEl('analytics-mobile-money-tactics');
  const note = intelligenceAnalyticsEl('analytics-tactic-note');
  if (!target) return;
  const max = Math.max(1, ...tactics.map(item => Number(item.tally.reports || 0)));
  target.innerHTML = tactics.length ? tactics.slice(0, 8).map(item => {
    const tally = item.tally;
    const count = Number(tally.reports || 0);
    const percent = Math.max(4, Math.round(count / max * 100));
    const reviewed = Number(tally.reviewed_reports || 0);
    const pending = Math.max(0, count - reviewed);
    const sourceCounts = `${Number(tally.explicit_category_reports || 0)} FIR category · ${Number(tally.suggested_reports || 0)} text suggestion(s)`;
    return `<div class="mobile-money-tactic-row"><div class="mobile-money-tactic-heading"><b>${escapeHtml(item.label)}</b><strong>${count.toLocaleString()} <small>reports</small></strong></div><div class="mobile-money-tactic-track" role="img" aria-label="${count} FIR reports" title="${count} FIR reports"><i style="width:${percent}%"></i></div><small>${reviewed.toLocaleString()} reviewed · ${pending.toLocaleString()} not yet reviewed · ${escapeHtml(sourceCounts)}</small></div>`;
  }).join('') : '<p class="helper">No eligible mobile-money FIR reports for this period.</p>';
  if (note) {
    const synthetic = tactics.reduce((sum, item) => sum + Number(item.tally.synthetic_reports || 0), 0);
    const excluded = Number(summary.rejected_reports_excluded || 0);
    note.textContent = `${summary.mobile_money_reports || 0} non-rejected mobile-money report(s) · ${excluded} rejected report(s) excluded · ${synthetic} synthetic training report(s) included. Text-derived tactics are suggestions, not verified findings.`;
  }
}
function renderIntelligenceAnalytics(dashboard) {
  state.lastIntelligenceDashboard = dashboard || {};
  const panel = $('#intelligence-analytics-panel');
  if (!panel) return;
  const data = state.lastIntelligenceDashboard;
  try {
    renderIntelligenceTrendsSummaryCards(intelligenceTrendsMetrics(data));
    const signals = data.fraud_signals || {};
    renderMobileMoneyTactics(data.mobile_money_tactics || {});
    const byRisk = signals.active_by_risk || {};
    const riskCount = level => Number(byRisk[level] ?? byRisk[level.toUpperCase()] ?? 0);
    setIntelligenceAnalyticsText('analytics-signal-total', `${Number(signals.active || 0).toLocaleString()} active`);
    setIntelligenceAnalyticsHtml('analytics-signal-risk', `<span>High ${riskCount('high').toLocaleString()}</span><span>Critical ${riskCount('critical').toLocaleString()}</span>`);
    const signalTypes = Object.entries(signals.by_type || {}).sort((a, b) => b[1] - a[1]);
    setIntelligenceAnalyticsHtml('analytics-signal-types', signalTypes.length
      ? signalTypes.slice(0, 5).map(([type, count]) => `<div class="analytics-row"><span>${escapeHtml(String(type).replaceAll('_', ' '))}</span><b>${Number(count).toLocaleString()}</b></div>`).join('')
      : '<p class="helper">No active fraud signals.</p>');

    const risks = Array.isArray(data.risk_trends) ? data.risk_trends : [];
    const riskTotal = item => ['low', 'medium', 'high', 'critical'].reduce((sum, level) => sum + Number(item?.[level] || 0), 0);
    const maxRisk = Math.max(1, ...risks.map(riskTotal));
    setIntelligenceAnalyticsHtml('analytics-risk-trend', risks.length
      ? `<div class="trend-columns">${risks.map(day => {
        const total = riskTotal(day);
        const barPx = total ? Math.max(14, Math.round(total / maxRisk * TREND_CHART_HEIGHT_PX)) : 5;
        const segments = ['low', 'medium', 'high', 'critical'].map(level => {
          const count = Number(day?.[level] || 0);
          const px = total ? Math.max(count ? 2 : 0, Math.round(count / total * barPx)) : 0;
          return `<i class="bar-${level}" style="height:${px}px"></i>`;
        }).join('');
        const label = analyticsTrendDayLabel(day);
        return `<div class="trend-column" title="${escapeHtml(String(day?.date || label))} · low ${day?.low || 0}, medium ${day?.medium || 0}, high ${day?.high || 0}, critical ${day?.critical || 0}"><div class="trend-column-bar" style="height:${barPx}px">${segments}</div><small>${escapeHtml(label)}</small></div>`;
      }).join('')}</div><div class="trend-axis-note">Daily FIR risk assessments</div>`
      : '<p class="helper">No risk history available.</p>');

    const reports = data.reports || {};
    setIntelligenceAnalyticsText('analytics-report-total', `${Number(reports.total || 0).toLocaleString()} reports`);
    setIntelligenceAnalyticsText('analytics-report-period', `${Number(reports.last_14_days || 0).toLocaleString()} received in the last 14 days`);
    const reportTrend = Array.isArray(reports.trend_14d) ? reports.trend_14d : [];
    const maxReports = Math.max(1, ...reportTrend.map(day => Number(day?.count || 0)));
    setIntelligenceAnalyticsHtml('analytics-report-trend', reportTrend.length
      ? `<div class="report-spark-bars">${reportTrend.map(day => {
        const label = analyticsTrendDayLabel(day);
        const count = Number(day?.count || 0);
        const barPx = count ? Math.max(10, Math.round(count / maxReports * TREND_CHART_HEIGHT_PX)) : 4;
        return `<div title="${escapeHtml(String(day?.date || label))} · ${count} reports"><i style="height:${barPx}px"></i><small>${escapeHtml(label)}</small></div>`;
      }).join('')}</div>`
      : '<p class="helper">No report history available.</p>');
    const reportStatuses = Object.entries(reports.by_status || {});
    setIntelligenceAnalyticsHtml('analytics-report-status', reportStatuses.length
      ? reportStatuses.map(([status, count]) => `<span>${escapeHtml(String(status).replaceAll('_', ' '))} <b>${Number(count).toLocaleString()}</b></span>`).join('')
      : '<span>No status counts</span>');

    const network = data.network || {};
    setIntelligenceAnalyticsText('analytics-network-total', `${Number(network.relationships || 0).toLocaleString()} relationships`);
    setIntelligenceAnalyticsText('analytics-network-nodes', Number(network.nodes || 0).toLocaleString());
    setIntelligenceAnalyticsText('analytics-network-transactions', Number(network.partner_transactions || 0).toLocaleString());
    const nodeTypes = Object.entries(network.nodes_by_type || {}).sort((a, b) => b[1] - a[1]);
    const edgeTypes = Object.entries(network.relationships_by_type || {}).sort((a, b) => b[1] - a[1]);
    const txTypes = Object.entries(network.transactions_by_status || {}).map(([status, count]) => `${status} ${count}`).join(' · ');
    setIntelligenceAnalyticsHtml('analytics-network-types', nodeTypes.length
      ? `<div class="network-type-heading">Nodes</div>${nodeTypes.slice(0, 4).map(([type, count]) => `<div class="analytics-row"><span>${escapeHtml(String(type))}</span><b>${Number(count).toLocaleString()}</b></div>`).join('')}<div class="network-type-heading">Relationships</div>${edgeTypes.slice(0, 4).map(([type, count]) => `<div class="analytics-row"><span>${escapeHtml(String(type).replaceAll('_', ' '))}</span><b>${Number(count).toLocaleString()}</b></div>`).join('')}`
      : '<p class="helper">No graph data available.</p>');
    const volume = network.successful_volume_by_currency || [];
    setIntelligenceAnalyticsHtml('analytics-transaction-volume', `${txTypes ? `<span>${escapeHtml(txTypes)}</span>` : ''}${volume.map(item => `<span>${escapeHtml(item.currency)} ${Number(item.total_amount || 0).toLocaleString(undefined, { maximumFractionDigits: 2 })} successful volume</span>`).join('')}`);
    updateIntelligenceTrendsHint(data);
  } catch (error) {
    logGateway('ERROR', `Intelligence trends could not render: ${error.message}`);
    setIntelligenceAnalyticsHtml('analytics-signal-types', `<p class="helper">${escapeHtml(error.message)}</p>`);
  }
}

function clearIntelligenceAnalytics(message = 'Live intelligence data unavailable.') {
  const setText = (id, value) => { const el = intelligenceAnalyticsEl(id); if (el) el.textContent = value; };
  ['analytics-signal-total', 'analytics-report-total', 'analytics-report-period',
    'analytics-network-total', 'analytics-network-nodes', 'analytics-network-transactions',
    'analytics-summary-assessments', 'analytics-summary-reports', 'analytics-summary-signals',
    'analytics-risk-card-stat', 'analytics-report-card-stat', 'analytics-signal-card-stat']
    .forEach(id => setText(id, '—'));
  if (intelligenceAnalyticsEl('analytics-signal-risk')) intelligenceAnalyticsEl('analytics-signal-risk').innerHTML = '';
  if (intelligenceAnalyticsEl('analytics-signal-types')) intelligenceAnalyticsEl('analytics-signal-types').innerHTML = `<p class="helper">${escapeHtml(message)}</p>`;
  if (intelligenceAnalyticsEl('analytics-risk-trend')) intelligenceAnalyticsEl('analytics-risk-trend').innerHTML = `<p class="helper">${escapeHtml(message)}</p>`;
  if (intelligenceAnalyticsEl('analytics-report-trend')) intelligenceAnalyticsEl('analytics-report-trend').innerHTML = `<p class="helper">${escapeHtml(message)}</p>`;
  if (intelligenceAnalyticsEl('analytics-report-status')) intelligenceAnalyticsEl('analytics-report-status').innerHTML = '';
  if (intelligenceAnalyticsEl('analytics-network-types')) intelligenceAnalyticsEl('analytics-network-types').innerHTML = `<p class="helper">${escapeHtml(message)}</p>`;
  if (intelligenceAnalyticsEl('analytics-transaction-volume')) intelligenceAnalyticsEl('analytics-transaction-volume').innerHTML = '';
  if (intelligenceAnalyticsEl('analytics-mobile-money-tactics')) intelligenceAnalyticsEl('analytics-mobile-money-tactics').innerHTML = `<p class="helper">${escapeHtml(message)}</p>`;
  if (intelligenceAnalyticsEl('analytics-tactic-note')) intelligenceAnalyticsEl('analytics-tactic-note').textContent = '';
}

async function loadAdminIntelligence() {
  if (state.demo) {
    clearIntelligenceAnalytics('Switch to Live API mode and sign in to view stored FIR/PDR data.');
    $('#intelligence-status').textContent = 'Live intelligence requires Live API mode and an administrator session.';
    return;
  }
  try {
    const data = await apiRequest('/admin/intelligence');
    state.lastIntelligencePayload = data;
    state.lastIntelligenceDashboard = data.dashboard || {};
    renderAdminIntelligence(data);
  } catch (error) {
    clearIntelligenceAnalytics(`Could not load live data: ${error.message}`);
    $('#intelligence-status').textContent = `Could not load intelligence: ${error.message}`;
  }
}

async function loadAwarenessPreferences() {
  if (state.demo || !state.token) {
    $('#awareness-preferences-status').textContent = 'Sign in using Live API mode to manage consent.';
    $('#awareness-inbox').innerHTML = '<p class="helper">Sign in to load your awareness inbox.</p>';
    return;
  }
  try {
    const preferences = await apiRequest('/awareness/preferences');
    $('#awareness-memory-consent').checked = preferences.conversation_memory_enabled;
    $('#awareness-education-consent').checked = preferences.proactive_education_enabled;
    $('#awareness-channel-inapp').checked = preferences.channels.includes('in_app');
    $('#awareness-channel-sms').checked = preferences.channels.includes('sms');
    $('#awareness-preferences-status').textContent = preferences.consent_updated_at
      ? `Consent settings updated ${relativeTime(preferences.consent_updated_at)}.`
      : 'No consent is enabled until you save your choices.';
    await loadAwarenessInbox();
  } catch (error) {
    $('#awareness-preferences-status').textContent = error.message;
  }
}

async function saveAwarenessPreferences() {
  if (state.demo || !state.token) {
    $('#awareness-preferences-status').textContent = 'Sign in using Live API mode to manage consent.';
    return;
  }
  const channels = [];
  if ($('#awareness-channel-inapp').checked) channels.push('in_app');
  if ($('#awareness-channel-sms').checked) channels.push('sms');
  if ($('#awareness-education-consent').checked && !channels.length) {
    $('#awareness-preferences-status').textContent = 'Choose at least one delivery channel or turn off proactive education.';
    return;
  }
  try {
    const saved = await apiRequest('/awareness/preferences', { method: 'PUT', body: JSON.stringify({
      conversation_memory_enabled: $('#awareness-memory-consent').checked,
      proactive_education_enabled: $('#awareness-education-consent').checked,
      channels,
    }) });
    $('#awareness-preferences-status').textContent = `Saved. Conversation memory ${saved.conversation_memory_enabled ? 'on' : 'off'}; proactive education ${saved.proactive_education_enabled ? 'on' : 'off'}.`;
    await loadAwarenessInbox();
  } catch (error) {
    $('#awareness-preferences-status').textContent = error.message;
  }
}

async function loadAwarenessInbox() {
  if (state.demo || !state.token) return;
  try {
    const data = await apiRequest('/awareness/inbox');
    const items = data.items || [];
    $('#awareness-inbox').innerHTML = items.length ? items.map(item => `<article class="intelligence-signal"><div><b>${escapeHtml(item.campaign_title)}</b><span class="status ${item.severity === 'high_risk' ? 'pending' : 'review'}">${escapeHtml(item.severity.replaceAll('_', ' '))}</span></div><p>${escapeHtml(item.message)}</p><small>${item.read_at ? 'Read' : 'New'} · ${relativeTime(item.sent_at)}</small>${item.read_at ? '' : `<button class="table-action" data-awareness-read="${escapeHtml(item.id)}">Mark read</button>`}</article>`).join('') : '<p class="helper">No awareness messages yet. You can opt in to receive relevant education.</p>';
  } catch (error) {
    $('#awareness-inbox').innerHTML = `<p class="helper">${escapeHtml(error.message)}</p>`;
  }
}

async function loadAwarenessOutreachStats() {
  if (state.demo || !state.token) return;
  try {
    const stats = await apiRequest('/admin/awareness/outreach-stats');
    $('#awareness-stat-delivered').textContent = Number(stats.interventions_delivered_30d || 0).toLocaleString();
    $('#awareness-stat-read').textContent = Number(stats.awareness_read_30d || 0).toLocaleString();
    $('#awareness-stat-sms').textContent = Number(stats.sms_sent_30d || 0).toLocaleString();
  } catch {
    $('#awareness-stat-delivered').textContent = '—';
    $('#awareness-stat-read').textContent = '—';
    $('#awareness-stat-sms').textContent = '—';
  }
}

async function loadAwarenessDeliveries() {
  if (state.demo || !state.token) return;
  try {
    const items = await apiRequest('/admin/awareness/deliveries?limit=30');
    $('#awareness-delivery-log').innerHTML = items.length
      ? items.map(row => `<article class="intelligence-signal"><div><b>${escapeHtml(row.campaign_title)}</b><span class="status ${row.status === 'sent' ? 'review' : 'pending'}">${escapeHtml(row.channel)} · ${escapeHtml(row.status)}</span></div><small>${escapeHtml(row.severity.replaceAll('_', ' '))} · ${row.delivered_at ? relativeTime(row.delivered_at) : 'pending'}${row.read_at ? ' · read' : ''}</small></article>`).join('')
      : '<p class="helper">No deliveries yet.</p>';
  } catch (error) {
    $('#awareness-delivery-log').innerHTML = `<p class="helper">${escapeHtml(error.message)}</p>`;
  }
}

async function loadAwarenessCampaigns() {
  if (state.demo || !state.token) return;
  try {
    const campaigns = await apiRequest('/admin/awareness/campaigns');
    $('#awareness-campaign-list').innerHTML = campaigns.length ? campaigns.map(campaign => `<article class="intelligence-signal"><div><b>${escapeHtml(campaign.title)}</b><span class="status ${['sent', 'simulated'].includes(campaign.status) ? 'review' : 'pending'}">${escapeHtml(campaign.status)}</span></div><p>${escapeHtml(campaign.message)}</p><small>${escapeHtml(campaign.severity.replaceAll('_', ' '))} · audience ${Number(campaign.audience_count || 0)} · ${relativeTime(campaign.created_at)}${campaign.generated_by_scheduler ? ` · MoMo scam avoidance and defence tip · ${escapeHtml(campaign.generation_context?.copy_source || 'Gradio agent')} · not predictive` : ''}</small>${campaign.generated_by_scheduler ? '<small>Approval sends to live SMS subscribers and creates simulated SMS only for one-minute test subscribers.</small>' : ''}${campaign.status === 'draft' ? `<button class="table-action" data-campaign-send="${escapeHtml(campaign.id)}" data-campaign-scheduled="${campaign.generated_by_scheduler ? 'true' : 'false'}">${campaign.generated_by_scheduler ? 'Approve and deliver' : 'Approve and send'}</button>` : ''}</article>`).join('') : '<p class="helper">No campaign drafts yet.</p>';
    await Promise.all([loadAwarenessOutreachStats(), loadAwarenessDeliveries()]);
  } catch (error) {
    $('#awareness-campaign-list').innerHTML = `<p class="helper">${escapeHtml(error.message)}</p>`;
  }
}

async function sendAwarenessCampaign(campaignId, scheduled = false) {
  const prompt = scheduled
    ? 'Approve this Gradio-generated scheduled message? One-minute test subscribers will see a simulated SMS in SafeGuard Lite; other eligible subscribers may receive a real SMS through the configured provider.'
    : 'Approve and send this campaign to report-linked users who opted in? High-risk alerts require a different reviewer.';
  const confirmSend = window.confirm(prompt);
  if (!confirmSend) return;
  try {
    const result = await apiRequest(`/admin/awareness/campaigns/${encodeURIComponent(campaignId)}/approve-and-send`, { method: 'POST' });
    $('#awareness-campaign-status').textContent = `${result.status === 'simulated' ? 'Approved and simulated' : 'Sent'} for ${result.eligible_users} subscribers; ${result.sms_sent} SMS sent, ${result.simulated_count || 0} simulated in Lite, ${result.sms_failed} failed, ${result.suppressed_by_frequency_limit} suppressed by frequency cap, ${result.suppressed_by_unsupported_preference || 0} held for unavailable language or delivery support.`;
    await Promise.all([loadAwarenessCampaigns(), loadAdminIntelligence(), loadAwarenessOutreachStats(), loadAwarenessDeliveries(), loadAwarenessOperations()]);
  } catch (error) {
    $('#awareness-campaign-status').textContent = error.message;
  }
}

async function markAwarenessRead(deliveryId) {
  try {
    await apiRequest(`/awareness/inbox/${encodeURIComponent(deliveryId)}/read`, { method: 'POST' });
    await loadAwarenessInbox();
  } catch (error) {
    $('#awareness-preferences-status').textContent = error.message;
  }
}

function revealIntelligenceTrendsPanel() {
  const panel = $('#intelligence-analytics-panel');
  const button = $('#toggle-intelligence-trends');
  if (!panel) return;
  panel.removeAttribute('hidden');
  button?.setAttribute('aria-expanded', 'true');
  if (button) button.textContent = 'Hide trends';
  renderIntelligenceAnalytics(state.lastIntelligenceDashboard || state.lastIntelligencePayload?.dashboard || {});
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
async function seedAdminIntelligenceDemo() {
  const button = $('#seed-intelligence-demo');
  if (state.demo) {
    $('#intelligence-status').textContent = 'Switch off Demo mode and sign in as an administrator. Demo seeding is restricted to development/test API environments.';
    return;
  }
  button.disabled = true;
  $('#intelligence-status').textContent = 'Creating demo FIR reports, partner records and cross-provider transactions…';
  try {
    const result = await apiRequest('/admin/intelligence/demo-data', {
      method: 'POST', body: JSON.stringify({}),
    });
    const trend = result.trend_charts || {};
    $('#intelligence-status').textContent = `Demo data loaded: ${result.fir_reports_created} new FIR reports; ${trend.trend_risk_rows || 0} trend risk points across 14 days. Opening trend charts…`;
    await Promise.all([loadAdminDashboard(), loadAdminIntelligence(), loadAdminMonitoring()]);
    await loadAdminPartners();
    revealIntelligenceTrendsPanel();
    const trendNote = (trend.trend_risk_rows || 0) < 1
      ? 'No FIR rows found for trend seed — restart the API, then click Populate demo data again.'
      : intelligenceTrendsFootnote(state.lastIntelligenceDashboard);
    $('#intelligence-status').textContent = `Demo ready · partners ${(result.demo_partner_codes || []).join(', ')} · ${trendNote}`;
  } catch (error) {
    $('#intelligence-status').textContent = `Demo seed failed: ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

async function loadAdminPartners() {
  const table = $('#partners-table');
  if (state.demo) {
    table.innerHTML = '<tr><td colspan="5">Switch to Live API mode and sign in as an admin to manage partners.</td></tr>';
    return;
  }
  try {
    const partners = await apiRequest('/admin/partners');
    table.innerHTML = partners.length ? partners.map(partner => `<tr><td>${escapeHtml(partner.partner_name)}</td><td>${escapeHtml(partner.partner_code)}</td><td>${escapeHtml(partner.partner_type)}</td><td><span class="status ${partner.partner_status === 'active' ? 'review' : 'pending'}">${escapeHtml(partner.partner_status)}</span></td><td><button class="table-action" data-partner-id="${escapeHtml(partner.id)}" data-partner-status="${partner.partner_status === 'active' ? 'inactive' : 'active'}">${partner.partner_status === 'active' ? 'Deactivate' : 'Activate'}</button></td></tr>`).join('') : '<tr><td colspan="5">No partners registered yet.</td></tr>';
  } catch (error) {
    table.innerHTML = `<tr><td colspan="5">${escapeHtml(error.message)}</td></tr>`;
  }
}

async function createAdminPartner() {
  const status = $('#partner-create-status');
  const button = $('#partner-create');
  $('#partner-secret-result').classList.add('hidden');
  if (state.demo) { status.textContent = 'Switch off Demo mode and sign in with an administrator account.'; return; }
  const body = {
    partner_name: $('#partner-name').value.trim(),
    partner_code: $('#partner-id').value.trim().toLowerCase(),
    partner_type: $('#partner-type').value,
  };
  if (!body.partner_name || !body.partner_code) { status.textContent = 'Enter a partner name and partner code.'; return; }
  button.disabled = true;
  status.textContent = 'Registering partner…';
  try {
    const partner = await apiRequest('/partners', { method: 'POST', body: JSON.stringify(body) });
    $('#partner-secret-value').textContent = partner.shared_secret;
    $('#partner-secret-copy').textContent = 'Copy secret';
    $('#partner-secret-result').classList.remove('hidden');
    status.textContent = `${partner.partner_name} is registered. Copy its secret before leaving this page.`;
    $('#partner-name').value = '';
    $('#partner-id').value = '';
    await loadAdminPartners();
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function setPartnerStatus(partnerId, partnerStatus) {
  try {
    await apiRequest(`/admin/partners/${encodeURIComponent(partnerId)}/status`, {
      method: 'PATCH', body: JSON.stringify({ partner_status: partnerStatus }),
    });
    await loadAdminPartners();
  } catch (error) {
    $('#partner-create-status').textContent = error.message;
  }
}

async function loadAdminReports() {
  if (state.demo) {
    openReviewDialog(null, 'Demo report · 024 123 4567 · pending', 'Demo mode has no persisted reviewer record. Switch to Live API mode to review real reports.');
    return;
  }
  try {
    const data = await apiRequest('/reports?status=pending&limit=100');
    renderAdminReportRows(data.items || []);
    $('#admin-reports-section .admin-section-heading')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { logGateway('ERROR', `Reports could not load: ${error.message}`); }
}
async function toggleIntelligenceTrends() {
  const panel = $('#intelligence-analytics-panel');
  const button = $('#toggle-intelligence-trends');
  if (!panel || !button) return;
  const show = panel.hasAttribute('hidden');
  if (show) panel.removeAttribute('hidden');
  else panel.setAttribute('hidden', '');
  button.setAttribute('aria-expanded', String(show));
  button.textContent = show ? 'Hide trends' : 'Show trends';
  if (!show) return;
  if (!state.demo && !state.lastIntelligencePayload) {
    button.disabled = true;
    try { await loadAdminIntelligence(); } finally { button.disabled = false; }
  }
  renderIntelligenceAnalytics(state.lastIntelligenceDashboard || state.lastIntelligencePayload?.dashboard || {});
}

async function openReviewDialog(reportId, title = 'Report', demoBody = '') {
  $('#review-dialog-title').textContent = title;
  $('#review-status').textContent = '';
  $('#review-category-id').value = '';
  $('#review-dialog').dataset.reportId = reportId || '';
  if (state.demo || !reportId) {
    $('#review-dialog-body').innerHTML = `<p>${escapeHtml(demoBody || 'Demo report details are shown here.')}</p>`;
  } else {
    try {
      const report = await apiRequest(`/reports/${reportId}`);
      $('#review-dialog-body').innerHTML = `<p><b>${escapeHtml(report.phone)}</b> · ${escapeHtml(report.report_type)} · ${escapeHtml(report.status)}</p><p>${escapeHtml(report.description || 'No description supplied.')}</p><p class="helper">Case: ${escapeHtml(report.case_id || 'not linked')}</p>`;
    } catch (error) { $('#review-dialog-body').innerHTML = `<p class="danger">${escapeHtml(error.message)}</p>`; }
  }
  $('#review-dialog').showModal();
}

async function submitReviewDecision() {
  const reportId = $('#review-dialog').dataset.reportId;
  if (!reportId || state.demo) { $('#review-status').textContent = 'Demo review preview only.'; return; }
  const body = { decision: $('#review-decision').value, category_id: $('#review-category-id').value.trim() || undefined };
  try {
    await apiRequest(`/reports/${reportId}/review`, { method: 'POST', body: JSON.stringify(body) });
    $('#review-status').textContent = 'Decision saved.';
    setTimeout(() => { $('#review-dialog').close(); loadAdminDashboard(); }, 500);
  } catch (error) { $('#review-status').textContent = error.message; }
}

function logGateway(status, message) { const log = $('#gateway-log'); const row = document.createElement('div'); row.className = 'log-line'; row.innerHTML = `<span>${new Date().toLocaleTimeString()}</span><b>${status}</b><p>${message}</p>`; log.prepend(row); }
function renderLite(screen) { $('#ussd-screen').innerHTML = screen; }
function liteMenu() { endLiteVoiceIO(); state.voiceMessages = []; state.liteStep = 'menu'; $('#lite-input').value = ''; $('#lite-input').disabled = false; $('#lite-send').disabled = false; $('#lite-mic').hidden = true; $('#lite-input').placeholder = 'Type a response'; renderLite('<div class="ussd-brand">SAFEGUARD</div><p>Welcome. Choose an option:</p><button data-ussd="lookup">1. Check a phone number</button><button data-ussd="report">2. Report a scam</button><button data-ussd="shield">3. Report suspicious SMS</button><button data-ussd="advice">4. Safety advice</button><button data-ussd="reports">5. My reports</button><button data-ussd="awareness">6. Continuous Awareness</button><button data-ussd="voice-call">7. Call SafeGuard Voice</button>'); $('#lite-action-title').textContent = 'Lite menu'; }
function renderLiteVoiceCallMemory() {
  state.liteStep = 'voice_call';
  $('#lite-action-title').textContent = 'SafeGuard Voice · simulated';
  $('#lite-input').disabled = true;
  $('#lite-send').disabled = true;
  const memoryStatus = state.voiceMemoryEnabled ? 'Memory is on' : 'Memory is off';
  const memoryAction = state.voiceMemoryEnabled
    ? '<button data-ussd="voice-memory-toggle" data-value="false">Turn memory off and clear saved context</button>'
    : '<button data-ussd="voice-memory-toggle" data-value="true">Allow context memory for future calls</button>';
  renderLite(`<div class="ussd-brand">SAFEGUARD VOICE</div><p><b>Simulated call</b></p><p>The signed gateway uses the caller number to select a SafeGuard profile. This Lite page is a simulation; its configured number does not verify who is calling. ${escapeHtml(memoryStatus)}.</p><p>When enabled, SafeGuard saves a short structured summary for future calls, not call audio or raw transcripts. Microphone audio is processed by browser speech recognition when available, or sent to the configured backend speech provider. SafeGuard does not save the recording. Recognized text and limited context are sent to the backend agent and its configured AI provider. Review the transcript before sending it.</p>${memoryAction}<button data-ussd="voice-start-chat">Start voice conversation</button><button data-ussd="menu">End call · return to Lite menu</button>`);
}
async function startLiteVoiceCall() {
  state.liteStep = 'voice_call';
  $('#lite-action-title').textContent = 'SafeGuard Voice · simulated';
  $('#lite-input').disabled = true;
  $('#lite-send').disabled = true;
  try {
    if (state.demo) {
      state.voiceMemoryEnabled = localStorage.getItem(`safeguard.voiceMemory.${state.gatewayMsisdn}`) === 'true';
    } else {
      const result = await apiRequest(`/gateway/voice/memory?msisdn=${encodeURIComponent(state.gatewayMsisdn)}`, { gateway: true });
      state.voiceMemoryEnabled = Boolean(result.enabled);
    }
    renderLiteVoiceCallMemory();
  } catch (error) {
    renderLite(`<div class="ussd-brand">SAFEGUARD VOICE</div><p>Could not load voice memory preferences: ${escapeHtml(error.message)}</p><button data-ussd="menu">End call · return to Lite menu</button>`);
  }
  logGateway('SIMULATED', 'SafeGuard Voice call screen opened. No external call was placed.');
}
async function setLiteVoiceMemory(enabled) {
  try {
    if (state.demo) {
      state.voiceMemoryEnabled = enabled;
      localStorage.setItem(`safeguard.voiceMemory.${state.gatewayMsisdn}`, String(enabled));
    } else {
      const result = await apiRequest('/gateway/voice/memory', {
        method: 'PUT', gateway: true,
        body: JSON.stringify({ msisdn: state.gatewayMsisdn, enabled }),
      });
      state.voiceMemoryEnabled = Boolean(result.enabled);
    }
    renderLiteVoiceCallMemory();
    logGateway('200 OK', enabled ? 'Voice context memory consent saved.' : 'Voice context memory disabled; saved context cleared.');
  } catch (error) {
    renderLite(`<div class="ussd-brand">SAFEGUARD VOICE</div><p>Could not update voice memory: ${escapeHtml(error.message)}</p><button data-ussd="voice-call">Try again</button><button data-ussd="menu">End call</button>`);
  }
}
function startLiteVoiceChat() {
  state.liteStep = 'voice_chat';
  state.voiceMessages = [{ role: 'assistant', text: 'Welcome to SafeGuard Voice. You can ask me to check a number, report a scam, check a suspicious SMS, get safety advice, or review your reports. You can also check a simulated balance, see simulated money received, or try a simulated send. MoMo actions use test data only; no real money moves. What would you like to do?' }];
  state.voiceStatus = 'Speak or type a message. Check the transcript before sending.';
  $('#lite-action-title').textContent = 'SafeGuard Voice · simulated conversation';
  $('#lite-input').disabled = false;
  $('#lite-send').disabled = false;
  $('#lite-input').placeholder = 'Type what you would say';
  $('#lite-input').maxLength = 3000;
  $('#lite-mic').hidden = !(window.SpeechRecognition || window.webkitSpeechRecognition)
    && (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder);
  renderLiteVoiceChat();
  speakLiteVoiceReply(state.voiceMessages[0].text);
}
function renderLiteVoiceChat() {
  const transcript = state.voiceMessages.map((item, index) => `<p><b>${item.role === 'user' ? 'You' : 'SafeGuard'}:</b> ${escapeHtml(item.text)}${item.role === 'assistant' ? ` <button class="table-action" data-ussd="voice-replay" data-value="${index}">Play reply</button>` : ''}</p>`).join('');
  renderLite(`<div class="ussd-brand">SAFEGUARD VOICE</div><p><b>Simulated voice session</b> · memory ${state.voiceMemoryEnabled ? 'on' : 'off'}</p><p class="helper">${escapeHtml(state.voiceStatus || 'Speak or type a message.')}</p>${transcript}<button data-ussd="menu">End call</button>`);
}
function endLiteVoiceIO() {
  if (state.voiceRecordingTimer) window.clearTimeout(state.voiceRecordingTimer);
  state.voiceRecordingTimer = null;
  if (state.voiceRecorder?.state === 'recording') state.voiceRecorder.stop();
  state.voiceRecorder = null;
  if (state.voiceRecognition) state.voiceRecognition.abort();
  state.voiceRecognition = null;
  if ('speechSynthesis' in window) window.speechSynthesis.cancel();
}
async function toggleLiteVoiceRecording() {
  if (state.voiceRecognition) {
    state.voiceStatus = 'Finishing speech recognition…';
    state.voiceRecognition.stop();
    renderLiteVoiceChat();
    return;
  }
  if (state.voiceRecorder?.state === 'recording') {
    $('#lite-mic').textContent = '🎙 Speak';
    state.voiceStatus = 'Transcribing your recording…';
    renderLiteVoiceChat();
    state.voiceRecorder.stop();
    return;
  }
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (SpeechRecognition) {
    const recognition = new SpeechRecognition();
    recognition.lang = 'en-GH';
    recognition.interimResults = true;
    recognition.continuous = false;
    state.voiceRecognition = recognition;
    recognition.onresult = event => {
      const transcript = [...event.results].map(result => result[0].transcript).join(' ').trim();
      if (transcript) $('#lite-input').value = transcript;
      state.voiceStatus = transcript ? 'Transcript ready. Review or correct it, then tap Send.' : 'Listening…';
      renderLiteVoiceChat();
    };
    recognition.onerror = event => {
      state.voiceStatus = `Speech recognition: ${event.error}. You can type your message instead.`;
      state.voiceRecognition = null;
      $('#lite-mic').textContent = '🎙 Speak';
      renderLiteVoiceChat();
    };
    recognition.onend = () => {
      state.voiceRecognition = null;
      if (state.liteStep !== 'voice_chat') return;
      $('#lite-mic').textContent = '🎙 Speak';
      if (state.voiceStatus === 'Listening…' || state.voiceStatus === 'Finishing speech recognition…') {
        state.voiceStatus = $('#lite-input').value.trim()
          ? 'Transcript ready. Review or correct it, then tap Send.'
          : 'No speech recognized. Try again or type your message.';
      }
      renderLiteVoiceChat();
    };
    try {
      recognition.start();
      $('#lite-mic').textContent = '■ Stop';
      state.voiceStatus = 'Listening… speak now.';
      renderLiteVoiceChat();
    } catch (error) {
      state.voiceRecognition = null;
      state.voiceStatus = `Could not start speech recognition: ${error.message}. You can type your message instead.`;
      renderLiteVoiceChat();
    }
    return;
  }
  let stream;
  try {
    if (state.demo) {
      state.voiceStatus = 'Microphone transcription is unavailable in Demo mode. Switch to Live API or type your message.';
      renderLiteVoiceChat();
      return;
    }
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mimeType = ['audio/webm;codecs=opus', 'audio/webm', 'audio/ogg;codecs=opus']
      .find(type => MediaRecorder.isTypeSupported(type));
    const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
    const chunks = [];
    recorder.ondataavailable = event => { if (event.data?.size) chunks.push(event.data); };
    recorder.onstop = async () => {
      stream.getTracks().forEach(track => track.stop());
      if (state.voiceRecordingTimer) window.clearTimeout(state.voiceRecordingTimer);
      state.voiceRecordingTimer = null;
      state.voiceRecorder = null;
      $('#lite-mic').textContent = '🎙 Speak';
      if (state.liteStep !== 'voice_chat') return;
      const blob = new Blob(chunks, { type: recorder.mimeType || mimeType || 'audio/webm' });
      if (!blob.size) {
        state.voiceStatus = 'No audio was captured. Try again or type your message.';
        renderLiteVoiceChat();
        return;
      }
      try {
        const result = await apiRequest(`/gateway/voice/transcribe?msisdn=${encodeURIComponent(state.gatewayMsisdn)}`, {
          method: 'POST', gateway: true, body: blob,
          headers: { 'Content-Type': blob.type.split(';')[0] || 'audio/webm' },
        });
        $('#lite-input').value = result.transcript || '';
        state.voiceStatus = result.transcript
          ? 'Transcript ready. Review or correct it, then tap Send.'
          : 'I could not hear that clearly. Try again or type your message.';
      } catch (error) {
        state.voiceStatus = `${error.message} You can type your message instead.`;
        logGateway('ERROR', `Voice transcription: ${error.message}`);
      }
      renderLiteVoiceChat();
    };
    state.voiceRecorder = recorder;
    recorder.start();
    $('#lite-mic').textContent = '■ Stop';
    state.voiceStatus = 'Listening… speak now. Recording stops after 15 seconds.';
    renderLiteVoiceChat();
    state.voiceRecordingTimer = window.setTimeout(() => {
      if (state.voiceRecorder?.state === 'recording') {
        state.voiceStatus = 'Transcribing your recording…';
        $('#lite-mic').textContent = '🎙 Speak';
        state.voiceRecorder.stop();
        renderLiteVoiceChat();
      }
    }, 15000);
  } catch (error) {
    stream?.getTracks().forEach(track => track.stop());
    state.voiceStatus = `Microphone unavailable: ${error.message}. You can type your message instead.`;
    renderLiteVoiceChat();
  }
}
function speakLiteVoiceReply(text) {
  if (!text) return;
  if (!('speechSynthesis' in window) || !window.SpeechSynthesisUtterance) {
    state.voiceStatus = 'Spoken playback is unavailable in this browser; the reply is shown above.';
    renderLiteVoiceChat();
    return;
  }
  window.speechSynthesis.cancel();
  const utterance = new window.SpeechSynthesisUtterance(text);
  utterance.lang = 'en-GH';
  utterance.rate = 0.92;
  const voices = window.speechSynthesis.getVoices();
  utterance.voice = voices.find(voice => /^en-GH$/i.test(voice.lang))
    || voices.find(voice => /^en-(GB|NG|US)/i.test(voice.lang)) || null;
  state.voiceStatus = 'SafeGuard is speaking…';
  renderLiteVoiceChat();
  utterance.onend = () => { state.voiceStatus = 'Your turn. Speak or type a reply.'; renderLiteVoiceChat(); };
  utterance.onerror = () => { state.voiceStatus = 'Could not play speech. The reply is still shown above.'; renderLiteVoiceChat(); };
  try { window.speechSynthesis.speak(utterance); }
  catch {
    state.voiceStatus = 'Could not play speech. The reply is still shown above.';
    renderLiteVoiceChat();
  }
}
function renderAwarenessChoices(title, prompt, choices) {
  state.liteStep = 'awareness_choice'; $('#lite-action-title').textContent = title;
  renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>${escapeHtml(prompt)}</p>${choices.map(([label, action, value]) => `<button data-ussd="${action}" data-value="${escapeHtml(value)}">${escapeHtml(label)}</button>`).join('')}<button data-ussd="menu">0. Cancel / main menu</button>`);
}
function showUssdAwarenessFrequency() {
  renderAwarenessChoices('Awareness schedule', 'How often should we send routine awareness?', [
    ['1. Weekly', 'awareness-frequency', 'weekly'], ['2. Every two weeks', 'awareness-frequency', 'biweekly'],
    ['3. Monthly', 'awareness-frequency', 'monthly'], ['4. Custom interval', 'awareness-frequency', 'custom'],
  ]);
}
function showUssdAwarenessDelivery() {
  renderAwarenessChoices('Preferred delivery', 'Choose how you would like to receive awareness.', [
    ['1. SMS', 'awareness-delivery', 'sms'], ['2. Voice call', 'awareness-delivery', 'voice_call'], ['3. SMS and voice call', 'awareness-delivery', 'both'],
  ]);
}
function showUssdAwarenessLanguage() {
  renderAwarenessChoices('Language', 'Choose your preferred language. Other languages are saved as a preference when supported.', [
    ['1. English', 'awareness-language', 'english'], ['2. Twi', 'awareness-language', 'twi'], ['3. Other supported language', 'awareness-language', 'other'],
  ]);
}
function showUssdAwarenessTime() {
  renderAwarenessChoices('Preferred time', 'Choose a delivery period.', [
    ['1. Morning', 'awareness-time', 'morning'], ['2. Afternoon', 'awareness-time', 'afternoon'], ['3. Evening', 'awareness-time', 'evening'],
  ]);
}
function showUssdAwarenessCheckupPreference() {
  renderAwarenessChoices('Personal check-ups', 'Would you like occasional safety check-up questions?', [
    ['1. Enable check-ups', 'awareness-checkup', 'true'], ['2. Keep check-ups off', 'awareness-checkup', 'false'],
  ]);
}
function showUssdAwarenessAlerts() {
  renderAwarenessChoices('Fraud alerts', 'Would you like extra alerts about reviewed, emerging fraud tactics?', [
    ['1. Enable fraud alerts', 'awareness-alerts', 'true'], ['2. Keep extra alerts off', 'awareness-alerts', 'false'],
  ]);
}
function showUssdAwarenessSummary() {
  const draft = state.ussdAwarenessDraft || {};
  const interval = draft.schedule_frequency === 'custom' ? `Every ${draft.custom_interval_days} days` : draft.schedule_frequency;
  const language = draft.language?.startsWith('other:') ? draft.language.slice(6) : draft.language;
  state.liteStep = 'awareness_confirm'; $('#lite-action-title').textContent = 'Confirm awareness subscription';
  renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>Review your choices:</p><p>Frequency: ${escapeHtml(interval)}<br>Delivery: ${escapeHtml(draft.delivery_method)}<br>Language: ${escapeHtml(language)}<br>Preferred time: ${escapeHtml(draft.preferred_time)}<br>Check-ups: ${draft.checkup_enabled ? 'On' : 'Off'}<br>Fraud alerts: ${draft.fraud_alerts_enabled ? 'On' : 'Off'}${draft.test_schedule_enabled ? '<br>Test schedule: every minute (simulated only)' : ''}</p>${draft.test_schedule_available ? `<button data-ussd="awareness-test-draft" data-value="${draft.test_schedule_enabled ? 'false' : 'true'}">${draft.test_schedule_enabled ? 'Disable' : 'Enable'} 1-minute test schedule</button>` : ''}<p>By choosing Confirm, you agree to this awareness subscription. You can update or unsubscribe through this menu.</p><button data-ussd="awareness-confirm">1. Confirm subscription</button><button data-ussd="awareness-update">2. Change choices</button><button data-ussd="menu">0. Cancel</button>`);
}
function startUssdAwarenessTestPolling(enabled) {
  if (state.ussdAwarenessPollTimer) window.clearInterval(state.ussdAwarenessPollTimer);
  state.ussdAwarenessPollTimer = null;
  if (state.demo || !enabled) return;
  state.ussdAwarenessPollTimer = window.setInterval(async () => {
    if (state.liteStep !== 'awareness_home' || state.ussdAwarenessRefreshing) return;
    state.ussdAwarenessRefreshing = true;
    try { await loadUssdAwareness({ quiet: true }); }
    finally { state.ussdAwarenessRefreshing = false; }
  }, 10000);
}
async function loadUssdAwareness({ quiet = false } = {}) {
  $('#lite-action-title').textContent = 'Continuous Awareness'; state.liteStep = 'awareness_home';
  try {
    const url = `/gateway/awareness/preferences?msisdn=${encodeURIComponent(state.gatewayMsisdn)}`;
    const prefs = state.demo
      ? JSON.parse(localStorage.getItem(`safeguard.ussdAwareness.${state.gatewayMsisdn}`) || '{"subscription_active":false}')
      : await apiRequest(url, { gateway: true });
    state.ussdAwarenessDraft = { ...prefs, msisdn: state.gatewayMsisdn };
    startUssdAwarenessTestPolling(Boolean(prefs.subscription_active && prefs.test_schedule_enabled));
    let checkup = { available: false };
    if (!state.demo && prefs.subscription_active && prefs.checkup_enabled) {
      checkup = await apiRequest(`/gateway/awareness/checkup?msisdn=${encodeURIComponent(state.gatewayMsisdn)}`, { gateway: true });
    }
    state.ussdAwarenessCheckup = checkup.available ? checkup : null;
    if (prefs.subscription_active) {
      const interval = prefs.schedule_frequency === 'custom' ? `Every ${prefs.custom_interval_days} days` : prefs.schedule_frequency;
      const testPreview = prefs.latest_test_interaction?.message
        ? `<p><b>Latest simulated reminder:</b><br>${escapeHtml(prefs.latest_test_interaction.message)}</p>` : '';
      const testToggle = prefs.test_schedule_available
        ? `<button data-ussd="awareness-test-toggle" data-value="${prefs.test_schedule_enabled ? 'false' : 'true'}">${prefs.test_schedule_enabled ? 'Disable' : 'Enable'} 1-minute test schedule</button>` : '';
      renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>Continuous Awareness: SUBSCRIBED</p><p>${escapeHtml(prefs.test_schedule_enabled ? 'TEST MODE · every minute · no SMS sent' : interval)} · ${escapeHtml(prefs.delivery_method)} · ${escapeHtml(prefs.language)} · ${escapeHtml(prefs.preferred_time)}<br>Check-ups ${prefs.checkup_enabled ? 'on' : 'off'} · fraud alerts ${prefs.fraud_alerts_enabled ? 'on' : 'off'}</p>${testPreview}<button data-ussd="awareness-messages">Messages</button>${checkup.available ? '<button data-ussd="awareness-checkup-start">Continue waiting check-up</button>' : ''}${testToggle}<button data-ussd="awareness-update">Update preferences</button><button data-ussd="awareness-unsubscribe">Unsubscribe</button><button data-ussd="menu">0. Main menu</button>`);
    } else {
      renderLite('<div class="ussd-brand">SAFEGUARD</div><p>Get optional fraud-prevention reminders and check-ups. You control how often we contact you.</p><button data-ussd="awareness-update">1. Subscribe / set preferences</button><button data-ussd="menu">0. Main menu</button>');
    }
    if (!quiet) logGateway('200 OK', prefs.subscription_active ? 'Continuous Awareness preferences loaded.' : 'No Continuous Awareness subscription is active.');
  } catch (error) {
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>Could not load awareness preferences: ${escapeHtml(error.message)}</p><button data-ussd="menu">0. Main menu</button>`);
    logGateway('ERROR', error.message);
  }
}
async function loadUssdAwarenessMessages() {
  state.liteStep = 'awareness_messages';
  $('#lite-action-title').textContent = 'Awareness messages';
  try {
    const data = state.demo ? { items: [] } : await apiRequest(
      `/gateway/awareness/messages?msisdn=${encodeURIComponent(state.gatewayMsisdn)}`,
      { gateway: true },
    );
    const items = data.items || [];
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>Unread Continuous Awareness messages</p>${items.length ? items.map(item => `<article class="intelligence-signal"><b>${escapeHtml(item.topic)}</b><p>${escapeHtml(item.message)}</p><small>${relativeTime(item.sent_at)}</small><button data-ussd="awareness-message-read" data-value="${escapeHtml(item.id)}">Mark as read</button></article>`).join('') : '<p>No unread messages.</p>'}<button data-ussd="awareness">Back to Continuous Awareness</button><button data-ussd="menu">0. Main menu</button>`);
    logGateway('200 OK', `${items.length} unread awareness message(s) loaded.`);
  } catch (error) {
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>Could not load messages: ${escapeHtml(error.message)}</p><button data-ussd="awareness">Try again</button><button data-ussd="menu">0. Main menu</button>`);
    logGateway('ERROR', error.message);
  }
}
async function markUssdAwarenessMessageRead(interactionId) {
  try {
    await apiRequest(`/gateway/awareness/messages/${encodeURIComponent(interactionId)}/read?msisdn=${encodeURIComponent(state.gatewayMsisdn)}`, {
      method: 'POST', gateway: true,
    });
    logGateway('200 OK', 'Awareness message marked read and removed from the unread list.');
    await loadUssdAwarenessMessages();
  } catch (error) {
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>Could not mark this message as read: ${escapeHtml(error.message)}</p><button data-ussd="awareness-messages">Try again</button><button data-ussd="menu">0. Main menu</button>`);
    logGateway('ERROR', error.message);
  }
}
function showUssdAwarenessPendingCheckup() {
  const item = state.ussdAwarenessCheckup;
  if (!item?.available) return loadUssdAwareness();
  state.liteStep = 'awareness_checkup';
  $('#lite-action-title').textContent = 'Safety check-up';
  renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>${escapeHtml(item.question)}</p><button data-ussd="awareness-checkup-answer" data-value="yes">1. I know what to do</button><button data-ussd="awareness-checkup-answer" data-value="unsure">2. I'm not sure</button><button data-ussd="awareness-checkup-answer" data-value="no">3. I would share it</button><button data-ussd="awareness">0. Back</button>`);
}
async function answerUssdAwarenessCheckup(answer) {
  const item = state.ussdAwarenessCheckup;
  if (!item?.interaction_id) return loadUssdAwareness();
  try {
    const result = await apiRequest('/gateway/awareness/checkup/respond', {
      method: 'POST', gateway: true,
      body: JSON.stringify({ msisdn: state.gatewayMsisdn, interaction_id: item.interaction_id, answer }),
    });
    state.ussdAwarenessCheckup = null;
    $('#lite-action-title').textContent = 'Check-up complete';
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>${escapeHtml(result.message || 'Your check-up response was saved.')}</p><button data-ussd="awareness">0. Continuous Awareness</button><button data-ussd="menu">Main menu</button>`);
    logGateway('200 OK', 'Awareness check-up response saved.');
  } catch (error) {
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>Could not save your response: ${escapeHtml(error.message)}</p><button data-ussd="awareness">Try again</button>`);
    logGateway('ERROR', error.message);
  }
}
async function saveUssdAwarenessSubscription(active) {
  const draft = state.ussdAwarenessDraft || {};
  const body = { msisdn: state.gatewayMsisdn, subscription_active: active,
    schedule_frequency: draft.schedule_frequency || 'monthly',
    custom_interval_days: draft.schedule_frequency === 'custom' ? Number(draft.custom_interval_days) : null,
    delivery_method: draft.delivery_method || 'sms', language: draft.language || 'english',
    preferred_time: draft.preferred_time || 'morning', checkup_enabled: Boolean(draft.checkup_enabled),
    fraud_alerts_enabled: Boolean(draft.fraud_alerts_enabled),
    test_schedule_enabled: Boolean(active && draft.test_schedule_enabled) };
  try {
    let result;
    if (state.demo) {
      result = { ...body, subscription_active: active, message: 'Demo only: saved in this browser. No real subscription or contact was created.' };
      localStorage.setItem(`safeguard.ussdAwareness.${state.gatewayMsisdn}`, JSON.stringify(result));
    } else result = await apiRequest('/gateway/awareness/preferences', { method: 'PUT', body: JSON.stringify(body), gateway: true });
    state.ussdAwarenessDraft = { ...result, msisdn: state.gatewayMsisdn };
    startUssdAwarenessTestPolling(Boolean(active && result.test_schedule_enabled));
    state.liteStep = 'awareness_home';
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>${escapeHtml(result.message || 'Your preferences are saved.')}</p><p>${active ? 'You can change or cancel your subscription at any time from Continuous Awareness.' : ''}</p><button data-ussd="awareness">0. Return to Continuous Awareness</button><button data-ussd="menu">Main menu</button>`);
    logGateway('200 OK', result.message || 'Awareness preferences saved.');
  } catch (error) {
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>Could not save preferences: ${escapeHtml(error.message)}</p><button data-ussd="menu">0. Main menu</button>`);
    logGateway('ERROR', error.message);
  }
}
async function liteAction(action, value = '') {
  if (action === 'voice-call') { await startLiteVoiceCall(); return; }
  if (action === 'voice-memory-toggle') { await setLiteVoiceMemory(value === 'true'); return; }
  if (action === 'voice-start-chat') { startLiteVoiceChat(); return; }
  if (action === 'voice-replay') { speakLiteVoiceReply(state.voiceMessages[Number(value)]?.text); return; }
  if (action === 'awareness') { await loadUssdAwareness(); return; }
  if (action === 'awareness-messages') { await loadUssdAwarenessMessages(); return; }
  if (action === 'awareness-message-read') { await markUssdAwarenessMessageRead(value); return; }
  if (action === 'awareness-checkup-start') { showUssdAwarenessPendingCheckup(); return; }
  if (action === 'awareness-checkup-answer') { await answerUssdAwarenessCheckup(value); return; }
  if (action === 'awareness-test-draft') {
    state.ussdAwarenessDraft.test_schedule_enabled = value === 'true';
    showUssdAwarenessSummary(); return;
  }
  if (action === 'awareness-test-toggle') {
    state.ussdAwarenessDraft.test_schedule_enabled = value === 'true';
    await saveUssdAwarenessSubscription(true); return;
  }
  if (action === 'awareness-update') {
    const existing = state.ussdAwarenessDraft || {};
    state.ussdAwarenessDraft = { schedule_frequency: existing.schedule_frequency || 'monthly',
      custom_interval_days: existing.custom_interval_days ?? null, delivery_method: existing.delivery_method || 'sms',
      language: existing.language || 'english', preferred_time: existing.preferred_time || 'morning',
      checkup_enabled: Boolean(existing.checkup_enabled), fraud_alerts_enabled: Boolean(existing.fraud_alerts_enabled),
      test_schedule_enabled: Boolean(existing.test_schedule_enabled), test_schedule_available: Boolean(existing.test_schedule_available),
      subscription_active: true, msisdn: state.gatewayMsisdn };
    showUssdAwarenessFrequency(); return;
  }
  if (action === 'awareness-frequency') {
    const draft = state.ussdAwarenessDraft; draft.schedule_frequency = value; draft.custom_interval_days = null;
    if (value === 'custom') { state.liteStep = 'awareness_custom_interval'; $('#lite-action-title').textContent = 'Custom interval'; $('#lite-input').placeholder = 'Enter days, from 1 to 365'; renderLite('<div class="ussd-brand">SAFEGUARD</div><p>How many days between routine reminders? Enter a number from 1 to 365, then press Send.</p><button data-ussd="awareness">Cancel</button>'); return; }
    showUssdAwarenessDelivery(); return;
  }
  if (action === 'awareness-delivery') { state.ussdAwarenessDraft.delivery_method = value; showUssdAwarenessLanguage(); return; }
  if (action === 'awareness-language') {
    if (value === 'other') { state.liteStep = 'awareness_other_language'; $('#lite-action-title').textContent = 'Other language'; $('#lite-input').placeholder = 'Type a supported language name'; renderLite('<div class="ussd-brand">SAFEGUARD</div><p>Enter another language name. It will be used only when approved content is available in that language.</p><button data-ussd="menu">0. Cancel</button>'); return; }
    state.ussdAwarenessDraft.language = value; showUssdAwarenessTime(); return;
  }
  if (action === 'awareness-time') { state.ussdAwarenessDraft.preferred_time = value; showUssdAwarenessCheckupPreference(); return; }
  if (action === 'awareness-checkup') { state.ussdAwarenessDraft.checkup_enabled = value === 'true'; showUssdAwarenessAlerts(); return; }
  if (action === 'awareness-alerts') { state.ussdAwarenessDraft.fraud_alerts_enabled = value === 'true'; showUssdAwarenessSummary(); return; }
  if (action === 'awareness-confirm') { await saveUssdAwarenessSubscription(true); return; }
  if (action === 'awareness-unsubscribe') {
    state.liteStep = 'awareness_unsubscribe_confirm'; $('#lite-action-title').textContent = 'Confirm unsubscribe';
    renderLite('<div class="ussd-brand">SAFEGUARD</div><p>Stop Continuous Awareness reminders, calls, check-ups and fraud alerts?</p><button data-ussd="awareness-confirm-unsubscribe">1. Yes, unsubscribe</button><button data-ussd="awareness">0. Keep my subscription</button>'); return;
  }
  if (action === 'awareness-confirm-unsubscribe') { await saveUssdAwarenessSubscription(false); return; }
  if (action === 'advice') { state.liteStep = 'advice'; $('#lite-action-title').textContent = 'Safety advice'; renderLite('<div class="ussd-brand">SAFEGUARD</div><p>Never share your PIN or OTP. Stop when pressured. Verify callers through official channels.</p><button data-ussd="menu">0. Back to menu</button>'); logGateway('200 OK', 'Safety advice displayed.'); return; }
  if (action === 'reports') {
    state.liteStep = 'reports'; $('#lite-action-title').textContent = 'My reports';
    try {
      const data = state.demo ? [{ report_type: 'call', status: 'pending', created_at: new Date().toISOString(), phone: '+233 24 123 4567' }] : await apiRequest(`/gateway/reports?msisdn=${encodeURIComponent(state.gatewayMsisdn)}`, { gateway: true });
      const items = Array.isArray(data) ? data : (data.items || []);
      renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>${items.length ? items.map(item => `${escapeHtml(item.title || 'Scam report')} · ${escapeHtml(item.status.replaceAll('_', ' '))} · ${relativeTime(item.created_at)}`).join('<br />') : 'No reports found for this account.'}</p><button data-ussd="menu">0. Back to menu</button>`);
      logGateway('200 OK', `${items.length} report(s) loaded.`);
    } catch (error) { renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>Could not load reports: ${escapeHtml(error.message)}</p><button data-ussd="menu">0. Back to menu</button>`); logGateway('ERROR', error.message); }
    return;
  }
  $('#lite-action-title').textContent = action === 'lookup' ? 'Number lookup' : action === 'shield' ? 'Report suspicious SMS' : 'Report a scam';
  renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>${action === 'lookup' ? 'Enter the phone number to check:' : action === 'shield' ? 'Paste the suspicious SMS below:' : 'Enter the scam report message:'}</p><p class="helper">Then press Send.</p>`);
  $('#lite-input').placeholder = action === 'shield' ? 'Paste SMS text' : action === 'report' ? 'Type scam report message' : '+233...';
  if (action === 'report') $('#lite-input').maxLength = 500; else $('#lite-input').removeAttribute('maxlength');
  state.liteStep = action; logGateway('READY', `${action} flow opened on simulated USSD gateway.`);
}
async function liteSend() {
  const value = $('#lite-input').value.trim();
  if (state.liteStep === 'voice_chat') {
    if (!value) return;
    $('#lite-input').value = '';
    state.voiceMessages.push({ role: 'user', text: value });
    if (state.demo) {
      state.voiceMessages.push({ role: 'assistant', text: 'Demo mode does not contact the SafeGuard conversation service or save caller memory. Switch to Live API mode to try this turn.' });
      renderLiteVoiceChat();
      return;
    }
    $('#lite-send').disabled = true;
    let replyToSpeak = '';
    try {
      const result = await apiRequest('/gateway/voice/turn', {
        method: 'POST', gateway: true,
        body: JSON.stringify({
          msisdn: state.gatewayMsisdn,
          message: value,
          history: state.voiceMessages.slice(0, -1).slice(-10).map(item => ({ role: item.role, text: item.text.slice(-1000) })),
        }),
      });
      state.voiceMemoryEnabled = Boolean(result.memory_enabled);
      replyToSpeak = result.reply || 'I could not prepare a reply. Please try again.';
      state.voiceMessages.push({ role: 'assistant', text: replyToSpeak });
      logGateway('200 OK', result.privacy_notice || 'Voice turn analyzed.');
    } catch (error) {
      replyToSpeak = `I could not reach the conversation service: ${error.message}`;
      state.voiceMessages.push({ role: 'assistant', text: replyToSpeak });
      logGateway('ERROR', error.message);
    } finally {
      $('#lite-send').disabled = false;
      renderLiteVoiceChat();
    }
    if (replyToSpeak) speakLiteVoiceReply(replyToSpeak);
    return;
  }
  if (state.liteStep === 'awareness_custom_interval') {
    const days = Number(value);
    if (!Number.isInteger(days) || days < 1 || days > 365) { renderLite('<div class="ussd-brand">SAFEGUARD</div><p>Enter a whole number of days from 1 to 365, then press Send.</p><button data-ussd="menu">0. Cancel</button>'); return; }
    state.ussdAwarenessDraft.custom_interval_days = days; $('#lite-input').value = ''; showUssdAwarenessDelivery(); return;
  }
  if (state.liteStep === 'awareness_other_language') {
    if (value.length < 2 || value.length > 32 || !/^[a-zA-Z][a-zA-Z -]*$/.test(value)) { renderLite('<div class="ussd-brand">SAFEGUARD</div><p>Enter a language name using letters, spaces or hyphens, then press Send.</p><button data-ussd="menu">0. Cancel</button>'); return; }
    state.ussdAwarenessDraft.language = value; $('#lite-input').value = ''; showUssdAwarenessTime(); return;
  }
  if (!value || ['menu', 'advice', 'reports'].includes(state.liteStep)) return;
  try {
    let message = '';
    if (state.liteStep === 'shield') {
      if (state.demo) {
        const data = mockShield(value);
        message = `${data.risk_level.toUpperCase()}: ${data.explanation}`;
      } else {
        const data = await conversationAdapterTurn(value, 'sms');
        const risk = String(data.intelligence?.risk_level || 'unknown').toUpperCase();
        const advice = String(data.short_reply || data.intervention?.short_message || data.reply || 'Please verify through an official channel.');
        const cleanAdvice = advice.replace(/^SafeGuard(?:\s+(?:LOW|MEDIUM|HIGH|CRITICAL))?:\s*/i, '');
        message = `${risk}: ${cleanAdvice}`;
      }
    } else if (state.liteStep === 'report') {
      if (value.length < 10) throw new Error('Please describe what happened in at least 10 characters.');
      const body = { msisdn: state.gatewayMsisdn, description: value, report_type: 'other', case_id: state.gatewayCaseId || undefined };
      const data = state.demo ? { message: 'Your scam report was received for review.' } : await apiRequest('/gateway/reports', { method: 'POST', body: JSON.stringify(body), gateway: true });
      rememberGatewayCase(data.case_id);
      message = data.message;
    } else {
      const body = { msisdn: state.gatewayMsisdn, number: value, case_id: state.gatewayCaseId || undefined };
      const data = state.demo ? { risk_level: 'low', short_message: `No reports for ${value}. Stay careful.` } : await apiRequest('/gateway/lookup', { method: 'POST', body: JSON.stringify(body), gateway: true });
      rememberGatewayCase(data.case_id);
      message = data.short_message;
    }
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>${escapeHtml(message)}</p><button data-ussd="menu">0. Back to menu</button>`);
    logGateway('200 OK', message);
  } catch (error) {
    renderLite(`<div class="ussd-brand">SAFEGUARD</div><p>${escapeHtml(error.message)}</p><button data-ussd="menu">0. Back to menu</button>`);
    logGateway('ERROR', error.message);
  }
}

function openSettings() { $('#api-url').value = state.apiUrl; $('#api-token').value = state.token; $('#auth-phone').value = state.authPhone; $('#gateway-id').value = state.gatewayId; $('#gateway-secret').value = state.gatewaySecret; $('#gateway-msisdn').value = state.gatewayMsisdn; $('#demo-mode').checked = state.demo; $('#settings-dialog').showModal(); }
function saveSettings() { state.apiUrl = $('#api-url').value.trim(); state.token = $('#api-token').value.trim(); state.authPhone = $('#auth-phone').value.trim(); state.gatewayId = $('#gateway-id').value; state.gatewaySecret = $('#gateway-secret').value; state.gatewayMsisdn = $('#gateway-msisdn').value.trim(); state.demo = $('#demo-mode').checked; localStorage.setItem('safeguard.apiUrl', state.apiUrl); localStorage.removeItem('safeguard.gradioUrl'); localStorage.setItem('safeguard.token', state.token); localStorage.setItem('safeguard.authPhone', state.authPhone); localStorage.setItem('safeguard.gatewayId', state.gatewayId); localStorage.setItem('safeguard.gatewaySecret', state.gatewaySecret); localStorage.setItem('safeguard.gatewayMsisdn', state.gatewayMsisdn); localStorage.setItem('safeguard.demo', String(state.demo)); setModeLabel(); loadIntelligenceCapabilities(); loadAwarenessPreferences(); if ($('#view-admin').classList.contains('active')) loadAdminDashboard(); }
function switchView(view, options = {}) {
  document.body.classList.toggle('admin-view-active', view === 'admin');
  $$('.nav-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.view === view || (['nexus', 'atlas'].includes(view) && tab.dataset.view === 'admin')));
  $$('.view').forEach(item => item.classList.toggle('active', item.id === `view-${view}`));
  const names = { smart: ['SafeGuard Smart', 'Your personal safety layer'], lite: ['SafeGuard Lite', 'Feature-phone safety, simulated'], admin: ['Administration', 'Trust & safety overview'], nexus: ['NEXUS', 'Fraud intelligence investigation'], atlas: ['ATLAS', 'Network World Map'] };
  $('#section-kicker').textContent = names[view][0];
  $('#section-title').textContent = names[view][1];
  if (view === 'admin') loadAdminDashboard();
  if (view === 'atlas' && !options.skipAtlasLoad) loadAtlas();
  if (view === 'nexus') { loadNexusTab('reports'); restoreNexusActiveCase(); }
  if (view === 'smart') { loadAwarenessPreferences(); loadSmartReports(); }
}

let atlasGraph = null;
const atlasView = { scale: 1, x: 0, y: 0 };
let atlasPointer = null;
let atlasSuppressClick = false;
let atlasCatalog = null;
let atlasOpenNodeDetails = null;
const ATLAS_VIEWBOX = { width: 1000, height: 620 };

function atlasNodeMatchesQuery(node, query) {
  if (!query) return false;
  const q = query.toLowerCase();
  if (String(node.id || '').toLowerCase() === q) return true;
  if (String(node.record_id || '').toLowerCase() === q) return true;
  if (String(node.label || '').toLowerCase().includes(q)) return true;
  if (String(node.id || '').toLowerCase().includes(q)) return true;
  if (String(node.record_id || '').toLowerCase().includes(q)) return true;
  return Object.values(node.details || {}).some(value => String(value).toLowerCase().includes(q));
}

function pickAtlasSearchTarget(query, nodes, nodeIdMatch) {
  const q = query.toLowerCase();
  const matches = (nodes || [])
    .filter(node => node.search_match || atlasNodeMatchesQuery(node, query))
    .sort((a, b) => {
      const priority = Number(a.search_match_priority ?? 1) - Number(b.search_match_priority ?? 1);
      if (priority !== 0) return priority;
      const aLabel = String(a.label || '').toLowerCase();
      const bLabel = String(b.label || '').toLowerCase();
      const rank = label => (label === q ? 0 : label.startsWith(q) ? 1 : 2);
      return rank(aLabel) - rank(bLabel);
    });
  if (!matches.length) return null;
  if (nodeIdMatch) {
    const byFullId = matches.find(node => String(node.id || '').toLowerCase() === q);
    if (byFullId) return byFullId;
    const byRecord = matches.find(node => String(node.record_id || '') === nodeIdMatch[3]);
    if (byRecord) return byRecord;
  }
  const exactLabel = matches.find(node => String(node.label || '').toLowerCase() === q);
  if (exactLabel) return exactLabel;
  const exactRecord = matches.find(node => String(node.record_id || '').toLowerCase() === q);
  if (exactRecord) return exactRecord;
  return matches[0];
}

function atlasGraphNodeElement(nodeId) {
  const graph = $('#atlas-graph');
  if (!graph) return null;
  return [...graph.querySelectorAll('[data-atlas-node]')].find(
    element => element.dataset.atlasNode === nodeId,
  ) || null;
}

async function loadAtlas() {
  const status = $('#atlas-status');
  $('#atlas-details-panel').hidden = true;
  $('#atlas-detail-title').textContent = '';
  $('#atlas-detail-body').innerHTML = '';
  if (state.demo) { status.textContent = 'Switch to Live API mode and sign in as a reviewer or administrator to view FIR/PDR data.'; return; }
  status.textContent = 'Loading mapped FIR and PDR source records…';
  try {
    if (!atlasCatalog) atlasCatalog = await apiRequest('/intelligence/layers/atlas/catalog');
    const params = new URLSearchParams({ limit: '15000', offset: '0', table: 'all', source: 'all', coverage: 'ecosystem' });
    const query = $('#atlas-search').value.trim();
    const nodeIdMatch = query.match(/^(fir|pdr|shared)\.([a-z_]+):(.+)$/i);
    const searchQuery = nodeIdMatch ? nodeIdMatch[3] : query;
    if (searchQuery) params.set('query', searchQuery);
    atlasGraph = await apiRequest(`/intelligence/layers/atlas?${params}`);
    renderAtlasGraph(atlasGraph);
    const summary = atlasGraph.summary || {};
    const sourceRecords = summary.scoped_record_total ?? atlasCatalog.record_count ?? 0;
    const loaded = summary.nodes_loaded ?? summary.node_count ?? 0;
    status.textContent = `${loaded.toLocaleString()} graph nodes · ${(summary.edge_count || 0).toLocaleString()} links · ${sourceRecords.toLocaleString()} scoped source rows${summary.ecosystem_complete ? ' · full ecosystem loaded' : summary.truncated ? ' · graph capacity reached; some source rows are not shown' : ''}.`;
    if (query) {
      const searchMatches = (atlasGraph.nodes || []).filter(
        node => node.search_match || atlasNodeMatchesQuery(node, query),
      );
      const target = pickAtlasSearchTarget(query, atlasGraph.nodes || [], nodeIdMatch);
      if (target) {
        jumpAtlasRecord(target.id);
        if (searchMatches.length > 1) {
          status.textContent += ` Search found ${searchMatches.length.toLocaleString()} records; opened the best match. Refine the query to narrow it.`;
        }
      } else {
        status.textContent += ' No records matched that search.';
      }
    }
  } catch (error) {
    status.textContent = `Could not load Atlas: ${error.message}`;
    $('#atlas-graph').innerHTML = `<div class="nexus-empty"><span>◈</span><b>Atlas data unavailable</b><p>${escapeHtml(error.message)}</p></div>`;
  }
}
function jumpAtlasRecord(nodeId) {
  const point = atlasGraph?.nodesPosition?.get(nodeId);
  const graph = $('#atlas-graph');
  if (!graph) return;
  graph.querySelectorAll('.atlas-search-focus').forEach(element => element.classList.remove('atlas-search-focus'));
  requestAnimationFrame(() => {
    if (point) {
      atlasView.scale = 2.25;
      atlasView.x = ATLAS_VIEWBOX.width / 2 - point.x * atlasView.scale;
      atlasView.y = ATLAS_VIEWBOX.height / 2 - point.y * atlasView.scale;
      updateAtlasView();
    }
    const element = atlasGraphNodeElement(nodeId);
    if (element) {
      element.classList.add('atlas-search-focus');
      element.focus({ preventScroll: true });
    }
    atlasOpenNodeDetails?.(nodeId);
  });
}
function renderAtlasGraph(data) {
  const graph = $('#atlas-graph'); const nodes = data.nodes || []; const edges = data.edges || [];
  if (atlasGraph) atlasGraph.edges = edges;
  const summary = data.summary || {};
  $('#atlas-summary').innerHTML = `<span>Records <b>${summary.node_count ?? nodes.length}</b></span><span>Links <b>${summary.edge_count ?? edges.length}</b></span><span>FIR <b>${summary.by_source?.fir ?? 0}</b></span><span>PDR <b>${summary.by_source?.pdr ?? 0}</b></span><span>Shared <b>${summary.by_source?.shared ?? 0}</b></span>`;
  if (!nodes.length) {
    atlasOpenNodeDetails = null;
    graph.innerHTML = '<div class="nexus-empty"><span>◈</span><b>No matching records</b><p>Adjust the search or filters, or choose another record type.</p></div>';
    return;
  }
  const width = 1000, height = 620;
  const positions = computeAtlasLayout(nodes, edges, width, height);
  atlasGraph.nodesPosition = positions;
  const edgeMarkup = edges.map((edge, index) => {
    if (!edge) return '';
    const a = positions.get(edge.source), b = positions.get(edge.target); if (!a || !b) return '';
    return `<line class="atlas-edge" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" data-edge-index="${index}" data-edge-label="${escapeHtml(edge.relationship)}"${edge.directed ? ' marker-end="url(#atlas-arrow)"' : ''}/>`;
  }).join('');
  const nodeMarkup = nodes.map(node => {
    const p = positions.get(node.id), radius = positions.nodeRadius || 10;
    return `<g class="atlas-node atlas-${escapeHtml(node.type)} atlas-source-${escapeHtml(node.source)}" data-atlas-node="${escapeHtml(node.id)}" tabindex="0" role="button" aria-label="${escapeHtml(node.type)}: ${escapeHtml(node.label)}"><circle cx="${p.x}" cy="${p.y}" r="${radius}"/><text x="${p.x + radius + 4}" y="${p.y + 4}">${escapeHtml(node.label.slice(0, 24))}</text></g>`;
  }).join('');
  graph.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Unified FIR and PDR force-directed relationship network"><defs><marker id="atlas-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#526a7b"/></marker></defs><g id="atlas-scene">${edgeMarkup}${nodeMarkup}</g></svg>`;
  atlasView.scale = 1; atlasView.x = 0; atlasView.y = 0; updateAtlasView();
  const inspectNode = (element, { force = false } = {}) => {
    const node = nodes.find(item => item.id === element.dataset.atlasNode);
    if (!node) return;
    const inspect = () => {
      if (!force && atlasSuppressClick) { atlasSuppressClick = false; return; }
      $('#atlas-details-panel').hidden = false;
      const connections = edges.filter(edge => edge.source === node.id || edge.target === node.id);
      $('#atlas-detail-title').textContent = node.label;
      const rows = [['Type', node.type], ['Repository', (node.source || 'shared').toUpperCase()], ['Origin', (node.origin_repository || node.source || 'shared').toUpperCase()], ['Source table', node.table || '—'], ['Source record ID', node.record_id || '—'], ['Verification', node.verification_status || '—'], ['Connections', connections.length], ...Object.entries(node.details || {}).filter(([, value]) => value !== null && value !== '').map(([key, value]) => [key.replaceAll('_', ' '), value])];
      $('#atlas-detail-body').innerHTML = rows.map(([key, value]) => `<div class="nexus-detail-row"><span>${escapeHtml(key)}</span><b>${escapeHtml(value)}</b></div>`).join('') || '<p class="helper">No additional details.</p>';
      graph.querySelectorAll('.atlas-node').forEach(item => {
        const isSelected = item === element;
        const isNeighbor = connections.some(edge => edge.source === item.dataset.atlasNode || edge.target === item.dataset.atlasNode);
        item.classList.toggle('selected', isSelected);
        item.classList.toggle('atlas-dimmed', !isSelected && !isNeighbor);
      });
      graph.querySelectorAll('.atlas-edge').forEach(line => {
        const edge = edges[Number(line.dataset.edgeIndex)];
        line.classList.toggle('atlas-edge-active', edge?.source === node.id || edge?.target === node.id);
        line.classList.toggle('atlas-edge-dimmed', edge?.source !== node.id && edge?.target !== node.id);
      });
    };
    inspect();
  };
  atlasOpenNodeDetails = nodeId => {
    const element = atlasGraphNodeElement(nodeId);
    if (!element) return;
    inspectNode(element, { force: true });
  };
  const inspectEdge = line => {
    const edge = edges[Number(line.dataset.edgeIndex)];
    if (!edge) return false;
    $('#atlas-details-panel').hidden = false;
    const source = nodes.find(node => node.id === edge.source), target = nodes.find(node => node.id === edge.target);
    $('#atlas-detail-title').textContent = edge.relationship;
    $('#atlas-detail-body').innerHTML = [
      ['Relationship', edge.relationship], ['From', source?.label || edge.source], ['To', target?.label || edge.target],
      ['Direction', edge.directed ? 'Arrow shows source → target' : 'Relationship link'],
      ['Confidence', edge.confidence == null ? 'Not scored' : `${Math.round(Number(edge.confidence) * 100)}%`],
      ['Repository', (edge.repository || 'fir').toUpperCase()], ['Source table', edge.source_table || '—'],
      ['Source record ID', edge.source_record_id || '—'], ['Verification', edge.verification_status || '—'],
    ].map(([key, value]) => `<div class="nexus-detail-row"><span>${escapeHtml(key)}</span><b>${escapeHtml(value)}</b></div>`).join('');
    return true;
  };
  graph.onclick = event => {
    const edge = event.target.closest('.atlas-edge');
    if (edge && inspectEdge(edge)) return;
    const node = event.target.closest('[data-atlas-node]');
    if (node) inspectNode(node);
  };
  graph.onkeydown = event => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const node = event.target.closest('[data-atlas-node]');
    if (!node) return;
    event.preventDefault();
    inspectNode(node);
  };
}

function atlasBuildForceQuad(points, left, top, size, depth = 0) {
  let centerX = 0, centerY = 0;
  for (const point of points) { centerX += point.x; centerY += point.y; }
  centerX /= points.length || 1; centerY /= points.length || 1;
  if (points.length <= 4 || depth >= 24 || size < 0.01) {
    return { left, top, size, centerX, centerY, mass: points.length, points, children: null };
  }
  const half = size / 2, groups = [[], [], [], []];
  for (const point of points) {
    const index = (point.x >= left + half ? 1 : 0) + (point.y >= top + half ? 2 : 0);
    groups[index].push(point);
  }
  const children = [];
  groups.forEach((group, index) => {
    if (!group.length) return;
    children.push(atlasBuildForceQuad(group, left + (index % 2) * half,
      top + (index >= 2 ? half : 0), half, depth + 1));
  });
  return { left, top, size, centerX, centerY, mass: points.length, points: null, children };
}

function atlasApplyForceRepulsion(points, strength, theta = 0.72) {
  if (points.length < 2) return;
  const minX = Math.min(...points.map(point => point.x));
  const minY = Math.min(...points.map(point => point.y));
  const maxX = Math.max(...points.map(point => point.x));
  const maxY = Math.max(...points.map(point => point.y));
  const size = Math.max(maxX - minX, maxY - minY, 1) + 0.01;
  const root = atlasBuildForceQuad(points, minX, minY, size);
  for (const point of points) {
    const visit = cell => {
      let dx = point.x - cell.centerX, dy = point.y - cell.centerY;
      let distance2 = dx * dx + dy * dy;
      const containsPoint = point.x >= cell.left && point.x <= cell.left + cell.size
        && point.y >= cell.top && point.y <= cell.top + cell.size;
      if (cell.points) {
        for (const other of cell.points) {
          if (other === point) continue;
          dx = point.x - other.x; dy = point.y - other.y;
          distance2 = Math.max(25, dx * dx + dy * dy);
          const force = strength / distance2;
          point.fx += dx * force; point.fy += dy * force;
        }
      } else if (!containsPoint && distance2 > 0 && cell.size / Math.sqrt(distance2) < theta) {
        distance2 = Math.max(25, distance2);
        const force = strength * cell.mass / distance2;
        point.fx += dx * force; point.fy += dy * force;
      } else {
        for (const child of cell.children || []) visit(child);
      }
    };
    visit(root);
  }
}

function atlasResolveNodeSpacing(points, minimum, width, height) {
  const cellSize = minimum;
  for (let pass = 0; pass < 36; pass++) {
    const grid = new Map();
    points.forEach((point, index) => {
      const key = `${Math.floor(point.x / cellSize)}:${Math.floor(point.y / cellSize)}`;
      if (!grid.has(key)) grid.set(key, []);
      grid.get(key).push(index);
    });
    let collisions = 0;
    for (let index = 0; index < points.length; index++) {
      const point = points[index];
      const cellX = Math.floor(point.x / cellSize), cellY = Math.floor(point.y / cellSize);
      for (let y = cellY - 1; y <= cellY + 1; y++) for (let x = cellX - 1; x <= cellX + 1; x++) {
        for (const otherIndex of grid.get(`${x}:${y}`) || []) {
          if (otherIndex <= index) continue;
          const other = points[otherIndex];
          let dx = other.x - point.x, dy = other.y - point.y;
          let distance = Math.hypot(dx, dy);
          if (distance >= minimum) continue;
          if (distance < .001) {
            const angle = ((index * 31 + otherIndex * 17) % 360) * Math.PI / 180;
            dx = Math.cos(angle); dy = Math.sin(angle); distance = 1;
          }
          const separation = (minimum - distance) * .51;
          const ux = dx / distance, uy = dy / distance;
          point.x -= ux * separation; point.y -= uy * separation;
          other.x += ux * separation; other.y += uy * separation;
          collisions++;
        }
      }
    }
    for (const point of points) {
      point.x = Math.max(minimum / 2, Math.min(width - minimum / 2, point.x));
      point.y = Math.max(minimum / 2, Math.min(height - minimum / 2, point.y));
    }
    if (!collisions) break;
  }
}

function computeAtlasLayout(nodes, edges, width, height) {
  const count = nodes.length, centerX = width / 2, centerY = height / 2;
  if (!count) return new Map();
  const indexById = new Map(nodes.map((node, index) => [node.id, index]));
  const links = edges.map(edge => [indexById.get(edge.source), indexById.get(edge.target)])
    .filter(([a, b]) => a !== undefined && b !== undefined && a !== b);
  // Seed records across the canvas. The image-B style uses one open network
  // space rather than pulling each detected community into its own cluster.
  const points = nodes.map((node, index) => {
    let seed = 2166136261;
    for (const char of node.id) seed = Math.imul(seed ^ char.charCodeAt(0), 16777619);
    const x = 48 + ((seed >>> 0) % 100000) / 100000 * (width - 96);
    const y = 48 + ((seed >>> 10) % 100000) / 100000 * (height - 96);
    return { x, y, vx: 0, vy: 0, fx: 0, fy: 0, index };
  });
  const ideal = Math.max(26, Math.min(72, Math.sqrt(width * height / count) * .78));
  const charge = ideal * ideal * 1.1;
  const iterations = count > 350 ? 55 : 95;
  for (let step = 0; step < iterations; step++) {
    const cooling = 1 - step / iterations;
    for (const point of points) {
      point.fx = (centerX - point.x) * .00018;
      point.fy = (centerY - point.y) * .00018;
    }
    atlasApplyForceRepulsion(points, charge);
    for (const [sourceIndex, targetIndex] of links) {
      const source = points[sourceIndex], target = points[targetIndex];
      const dx = target.x - source.x, dy = target.y - source.y;
      const distance = Math.sqrt(dx * dx + dy * dy) || .01;
      const force = (distance - ideal) * .009;
      const fx = dx / distance * force, fy = dy / distance * force;
      source.fx += fx; source.fy += fy; target.fx -= fx; target.fy -= fy;
    }
    const maxStep = 8 * cooling + .15;
    for (const point of points) {
      point.vx = (point.vx + point.fx) * .76;
      point.vy = (point.vy + point.fy) * .76;
      const speed = Math.sqrt(point.vx * point.vx + point.vy * point.vy) || 1;
      const scale = Math.min(1, maxStep / speed);
      point.x += point.vx * scale;
      point.y += point.vy * scale;
    }
  }
  const minX = Math.min(...points.map(point => point.x)), maxX = Math.max(...points.map(point => point.x));
  const minY = Math.min(...points.map(point => point.y)), maxY = Math.max(...points.map(point => point.y));
  const fitScale = Math.min((width - 80) / Math.max(1, maxX - minX), (height - 80) / Math.max(1, maxY - minY));
  const spacedPoints = points.map(point => ({
    x: centerX + (point.x - (minX + maxX) / 2) * fitScale,
    y: centerY + (point.y - (minY + maxY) / 2) * fitScale,
  }));
  const minimumSpacing = Math.min(28, Math.max(10, 25 * fitScale));
  atlasResolveNodeSpacing(spacedPoints, minimumSpacing, width, height);
  const positions = new Map(nodes.map((node, index) => [node.id, {
    x: spacedPoints[index].x,
    y: spacedPoints[index].y,
  }]));
  positions.nodeRadius = Math.min(10, Math.max(3.5, minimumSpacing * .42));
  return positions;
}

function updateAtlasView() {
  const scene = $('#atlas-scene');
  if (scene) scene.setAttribute('transform', `translate(${atlasView.x} ${atlasView.y}) scale(${atlasView.scale})`);
  const level = $('#atlas-zoom-level'); if (level) level.textContent = `${Math.round(atlasView.scale * 100)}%`;
}
function zoomAtlas(factor) {
  atlasView.scale = Math.max(.35, Math.min(4, atlasView.scale * factor));
  updateAtlasView();
}
function moveAtlasNode(element, dx, dy) {
  const id = element.dataset.atlasNode;
  const svg = $('#atlas-graph svg'); const rect = svg.getBoundingClientRect();
  const sx = 1000 / rect.width, sy = 620 / rect.height;
  const circle = element.querySelector('circle'), label = element.querySelector('text');
  const screenX = dx * sx / atlasView.scale, screenY = dy * sy / atlasView.scale;
  const x = Number(circle.getAttribute('cx')) + screenX;
  const y = Number(circle.getAttribute('cy')) + screenY;
  circle.setAttribute('cx', x); circle.setAttribute('cy', y); label.setAttribute('x', x + Number(circle.getAttribute('r')) + 4); label.setAttribute('y', y + 4);
  atlasGraph.nodesPosition?.set(id, { x, y });
  $('#atlas-graph').querySelectorAll('.atlas-edge').forEach(line => {
    const edge = atlasGraph.edges[Number(line.dataset.edgeIndex)];
    if (!edge || (edge.source !== id && edge.target !== id)) return;
    const otherId = edge.source === id ? edge.target : edge.source;
    const otherElement = [...$('#atlas-graph').querySelectorAll('[data-atlas-node]')].find(node => node.dataset.atlasNode === otherId);
    const other = otherElement?.querySelector('circle');
    if (!other) return;
    const point = { x: Number(other.getAttribute('cx')), y: Number(other.getAttribute('cy')) };
    if (edge.source === id) { line.setAttribute('x1', x); line.setAttribute('y1', y); line.setAttribute('x2', point.x); line.setAttribute('y2', point.y); }
    else { line.setAttribute('x1', point.x); line.setAttribute('y1', point.y); line.setAttribute('x2', x); line.setAttribute('y2', y); }
  });
}

function navigateAdmin(target) {
  $$('.admin-nav-link').forEach(button => button.classList.toggle('active', button.dataset.adminTarget === target));
  if (target === 'settings') { openSettings(); return; }
  if (target === 'nexus' || target === 'investigations') {
    switchView('nexus');
    if (target === 'investigations') setTimeout(() => loadNexusTab('investigations'), 0);
    return;
  }
  document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function setNexusStatus(message) { $('#nexus-status').textContent = message; }
function nexusEmpty(title, message) {
  $('#nexus-graph').innerHTML = `<div class="nexus-empty"><span>◈</span><b>${escapeHtml(title)}</b><p>${escapeHtml(message)}</p></div>`;
}
function renderNexusDetails(title, rows = [], actions = []) {
  $('#nexus-detail-title').textContent = title || 'No selection';
  const fields = rows.length ? rows.map(([label, value]) => `<div class="nexus-detail-row"><span>${escapeHtml(label)}</span><b>${escapeHtml(String(value ?? '—'))}</b></div>`).join('') : '<p class="helper">Select an entity or relationship in the graph to inspect its intelligence.</p>';
  const buttons = actions.map(action => `<button class="secondary-button nexus-detail-action" data-nexus-open-entity="${escapeHtml(action.entityId)}">${escapeHtml(action.label)}</button>`).join('');
  $('#nexus-detail-body').innerHTML = fields + buttons;
  $('#nexus-detail-body').querySelectorAll('[data-nexus-open-entity]').forEach(button => button.addEventListener('click', () => openNexusEntity(button.dataset.nexusOpenEntity, 'Expanded graph')));
}
function nexusInferSourceTable(node) {
  if (node.source_table) return node.source_table;
  const nodeId = String(node.id || '');
  const type = String(node.type || '').toLowerCase();
  const prefixTables = {
    'fir-report:': 'fir_reports',
    'fir-incident:': 'fraud_incidents',
    'fir-case:': 'fraud_cases',
    'fir-reporter:': 'users',
    'fir-entity:': 'community_entities',
    'pdr-identity:': 'partner_identities',
    'pdr-account:': 'partner_accounts',
  };
  for (const [prefix, table] of Object.entries(prefixTables)) {
    if (nodeId.startsWith(prefix)) return table;
  }
  if (type === 'transaction') return 'partner_transactions';
  if (/^[0-9a-f-]{36}$/i.test(nodeId)) return 'community_entities';
  return null;
}
function nexusNodeSourceMeta(node) {
  const nodeId = String(node.id || '');
  const source = String(node.source || (nodeId.startsWith('pdr') ? 'pdr' : 'fir')).toLowerCase();
  const recordId = node.source_record_id
    || (nodeId.includes(':') ? nodeId.split(':').slice(1).join(':') : (/^[0-9a-f-]{36}$/i.test(nodeId) ? nodeId : null));
  return { source, recordId, table: nexusInferSourceTable(node) };
}
function nexusBaseDetailRows(node) {
  const { source, recordId, table } = nexusNodeSourceMeta(node);
  const details = node.details || {};
  const skipDetailKeys = new Set(['source_text']);
  return [
    ['Record type', node.type || '—'],
    ['Repository', source.toUpperCase()],
    ['Source table', table || '—'],
    ['Source record ID', recordId || '—'],
    ['Verification / evidence status', node.verification_status || 'Not specified'],
    ...Object.entries(details).filter(([key]) => !skipDetailKeys.has(key)).map(([key, value]) => [
      key.replaceAll('_', ' '),
      typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—'),
    ]),
  ];
}
function nexusDetailRowsFromRecord(record, baseRows = []) {
  const repo = String(record.origin_repository || record.source || 'fir').toUpperCase();
  const merged = new Map(baseRows.map(([label, value]) => [label, value]));
  merged.set('Repository', repo);
  merged.set('Source table', record.table || merged.get('Source table'));
  merged.set('Source record ID', record.record_id || merged.get('Source record ID'));
  merged.set('Verification / evidence status', record.verification_status || merged.get('Verification / evidence status'));
  Object.entries(record.details || {}).forEach(([key, value]) => {
    const label = key.replaceAll('_', ' ');
    if (label === 'description' && String(value).length > 320) {
      merged.set(label, `${String(value).slice(0, 317)}…`);
      return;
    }
    merged.set(label, typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—'));
  });
  return [...merged.entries()];
}
function nexusEvidenceForGraphNode(node) {
  const { source, recordId } = nexusNodeSourceMeta(node);
  const evidenceType = node.type === 'transaction' ? 'transaction' : node.type === 'report' ? 'report' : 'other';
  return {
    evidence_type: evidenceType,
    source: `nexus_${source}`,
    value: recordId,
    details: {
      source_system: source,
      source_table: node.source_table || null,
      source_record_id: recordId,
      verification_status: node.verification_status,
      node_type: node.type,
      entity_id: nexusEntityIdFromNode(node),
    },
  };
}
function nexusProfileDetailRows(profile) {
  const meta = profile.entity?.metadata || {};
  const metaRows = Object.entries(meta)
    .filter(([key]) => !/protected|reference_protected/i.test(key))
    .slice(0, 12)
    .map(([key, value]) => [key.replaceAll('_', ' '), typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')]);
  return [
    ['Entity type', profile.entity?.type || '—'],
    ['Display value', profile.entity?.display_value || '—'],
    ['Risk level', profile.profile?.risk_level || 'Not assessed'],
    ['Risk score', profile.profile?.risk_score == null ? '—' : `${Math.round(Number(profile.profile.risk_score) * 100)}%`],
    ['Confidence', profile.profile?.risk_confidence == null ? '—' : `${Math.round(Number(profile.profile.risk_confidence) * 100)}%`],
    ['Linked entities', profile.profile?.linked_entity_count ?? '—'],
    ['Reports (FIR)', profile.profile?.report_count ?? '—'],
    ['Transactions (PDR)', profile.profile?.transaction_count ?? '—'],
    ['Activity', profile.profile?.activity_summary || 'No activity summary available'],
    ['Risk reasons', (profile.profile?.risk_reasons || []).join('; ') || 'None recorded'],
    ...metaRows,
  ];
}
async function showNexusGraphNodeDetails(node, actions = []) {
  const requestId = ++state.nexusDetailRequestId;
  const title = node.display_value || node.type || 'Selected item';
  const baseRows = [['Trust tier', nexusFormatTrustTier(nexusTrustTierFromNode(node))], ...nexusBaseDetailRows(node)];
  const { source, recordId, table } = nexusNodeSourceMeta(node);
  const entityId = nexusEntityIdFromNode(node);
  renderNexusDetails(title, baseRows, actions);
  state.nexusIntakeContext = {
    source_system: source,
    source_record_id: recordId,
    entity_id: entityId || undefined,
    intake_type: nexusIntakeType(node.type),
    label: node.display_value,
    summary: `${source.toUpperCase()} ${node.type || 'record'}`,
  };
  setNexusSelectedEvidence(nexusEvidenceForGraphNode(node));
  if (state.demo) return;
  $('#nexus-detail-title').textContent = `${title} · loading…`;
  const tasks = [];
  if (table && recordId) {
    tasks.push(apiRequest(
      `/intelligence/layers/records/detail?source_table=${encodeURIComponent(table)}&source_record_id=${encodeURIComponent(recordId)}`,
    ).then(record => ({ kind: 'record', record })).catch(() => ({ kind: 'record', record: null })));
  }
  if (entityId) {
    tasks.push(apiRequest(`/intelligence/layers/entities/${encodeURIComponent(entityId)}`)
      .then(profile => ({ kind: 'profile', profile }))
      .catch(() => ({ kind: 'profile', profile: null })));
  }
  if (!tasks.length) return;
  const outcomes = await Promise.all(tasks);
  if (requestId !== state.nexusDetailRequestId) return;
  let rows = [...baseRows];
  let panelTitle = title;
  for (const outcome of outcomes) {
    if (outcome.kind === 'record' && outcome.record) {
      panelTitle = outcome.record.label || panelTitle;
      rows = nexusDetailRowsFromRecord(outcome.record, rows);
      if (outcome.record.table === 'fir_reports') {
        state.nexusIntakeContext = {
          source_system: 'fir',
          source_record_id: outcome.record.record_id || recordId,
          intake_type: 'report',
          label: outcome.record.label || title,
          summary: outcome.record.details?.description || 'FIR report record',
        };
      }
    }
    if (outcome.kind === 'profile' && outcome.profile) {
      rows = [...rows, ...nexusProfileDetailRows(outcome.profile)];
    }
  }
  if (outcomes.every(outcome => (outcome.kind === 'record' && !outcome.record)
      || (outcome.kind === 'profile' && !outcome.profile))) {
    rows.push(['Source record', 'Could not load FIR/PDR details for this node.']);
  }
  renderNexusDetails(panelTitle, rows, actions);
  if (entityId && outcomes.some(outcome => outcome.kind === 'profile' && outcome.profile)) {
    await loadNexusCollection(entityId);
  }
}
function setNexusSelectedEvidence(evidence) {
  state.nexusSelectedEvidence = evidence;
  const button = $('#nexus-add-to-case');
  if (button) button.disabled = !state.nexusActiveCase || !evidence || state.nexusActiveCase.status === 'closed' || isNexusEvidenceAttached(evidence);
  if (button) button.textContent = evidence && isNexusEvidenceAttached(evidence) ? 'Already attached' : 'Add selected item to case';
}
function isNexusEvidenceAttached(evidence) {
  const details = evidence?.details || {};
  return Boolean(state.nexusActiveCase?.evidence?.some(item => {
    const existing = item.details || {};
    return (details.entity_id && existing.entity_id === details.entity_id)
      || (details.source_record_id && existing.source_record_id === details.source_record_id)
      || (details.target_entity_id && existing.source_entity_id === details.source_entity_id
        && existing.target_entity_id === details.target_entity_id
        && existing.relationship_type === details.relationship_type);
  }));
}
function renderNexusActiveCase() {
  const panel = $('#nexus-active-case');
  if (!panel) return;
  const active = state.nexusActiveCase;
  panel.hidden = !active;
  if (active) {
    $('#nexus-active-case-title').textContent = active.title || `Investigation ${active.id.slice(0, 8)}`;
    $('#nexus-active-case-status').textContent = `${active.status || 'open'} · ${active.evidence_count ?? 0} evidence item(s)`;
    $('#nexus-add-to-case').disabled = !state.nexusSelectedEvidence || active.status === 'closed' || isNexusEvidenceAttached(state.nexusSelectedEvidence);
    $('#nexus-add-to-case').textContent = state.nexusSelectedEvidence && isNexusEvidenceAttached(state.nexusSelectedEvidence)
      ? 'Already attached' : 'Add selected item to case';
  }
}
async function activateNexusCase(id, data = null) {
  const detail = data || await apiRequest(`/cases/${encodeURIComponent(id)}`);
  state.nexusActiveCase = { id: detail.id, title: detail.title, status: detail.status,
    evidence_count: detail.evidence?.length ?? detail.evidence_count ?? 0, evidence: detail.evidence || [] };
  localStorage.setItem('safeguard.nexusActiveCaseId', detail.id);
  renderNexusActiveCase();
  return detail;
}
function clearNexusActiveCase() {
  state.nexusActiveCase = null;
  localStorage.removeItem('safeguard.nexusActiveCaseId');
  renderNexusActiveCase();
}
async function restoreNexusActiveCase() {
  const id = localStorage.getItem('safeguard.nexusActiveCaseId');
  if (!id || state.demo || state.nexusActiveCase?.id === id) return;
  try { await activateNexusCase(id); }
  catch (error) { clearNexusActiveCase(); setNexusStatus(`The saved active investigation could not be reopened: ${error.message}`); }
}
function evidenceForEntity(node, relationship = null) {
  const kind = nexusIntakeType(node.type);
  const evidenceType = { phone: 'phone_number', transaction: 'transaction', report: 'report',
    identity: 'identity', person: 'identity', business: 'identity', agent: 'identity' }[kind] || 'other';
  return { evidence_type: evidenceType, source: 'nexus_graph', value: node.id || null,
    details: { entity_id: node.id || null, entity_type: node.type || 'entity', ...(relationship || {}) } };
}
async function addSelectedNexusEvidence() {
  const active = state.nexusActiveCase;
  const selected = state.nexusSelectedEvidence;
  if (!active || !selected) return;
  if (isNexusEvidenceAttached(selected)) return setNexusStatus('This entity or source record is already attached to the active investigation.');
  if (active.status === 'closed') return setNexusStatus('This investigation is closed and cannot receive more evidence.');
  const button = $('#nexus-add-to-case');
  button.disabled = true;
  setNexusStatus('Attaching selected intelligence to the investigation…');
  try {
    await apiRequest(`/cases/${encodeURIComponent(active.id)}/evidence`, {
      method: 'POST', body: JSON.stringify(selected),
    });
    const detail = await activateNexusCase(active.id);
    setNexusStatus(`Intelligence added to ${detail.title}. ${detail.evidence.length} evidence item(s) are attached.`);
  } catch (error) {
    setNexusStatus(`Could not add intelligence to this investigation: ${error.message}`);
  } finally {
    renderNexusActiveCase();
  }
}
function clearNexusCollection(message = 'Select an entity to load connected FIR/PDR records.') {
  state.nexusCollection = null;
  $('#nexus-referral-save').disabled = true;
  $('#nexus-referral-target-label').value = '';
  $('#nexus-collection-title').textContent = 'Collected intelligence';
  $('#nexus-collection-status').textContent = message;
  $('#nexus-collection-summary').innerHTML = '<span>Reports <b>—</b></span><span>Incidents <b>—</b></span><span>Transactions <b>—</b></span><span>Evidence <b>—</b></span><span>Identity links <b>—</b></span><span>Findings <b>—</b></span><span>Cases <b>—</b></span>';
  $('#nexus-collection-content').innerHTML = `<p class="helper">${escapeHtml(message)}</p>`;
}
function collectionCard(title, subtitle, entries = []) {
  const details = entries.length ? entries.map(([label, value]) => `<div class="nexus-collection-field"><span>${escapeHtml(label)}</span><b>${escapeHtml(Array.isArray(value) ? value.join(' · ') : value ?? '—')}</b></div>`).join('') : '<p class="helper">No related records.</p>';
  return `<details class="nexus-collection-card"><summary><b>${escapeHtml(title)}</b><span>${escapeHtml(subtitle || '')}</span></summary><div class="nexus-collection-card-body">${details}</div></details>`;
}
function renderNexusCollectionTab(tab = state.nexusCollectionTab) {
  state.nexusCollectionTab = tab;
  $$('.nexus-collection-tabs button').forEach(button => button.classList.toggle('active', button.dataset.collectionTab === tab));
  const data = state.nexusCollection;
  if (!data) return;
  const arr = data[tab] || [];
  if (tab === 'overview') {
    const sections = [
      {
        title: 'Reports', rows: data.reports || [],
        render: row => collectionCard(row.subject,
          `${row.report_type} · ${row.status} · ${row.created_at?.slice(0, 10)}`,
          [['Category', row.category], ['Channel', row.channel], ['Source', row.source],
            ['Summary', row.description], ['Extracted entities', (row.extracted_entities || [])
              .map(entity => `${entity.entity_type}: ${entity.display_value}`)] ]),
      },
      {
        title: 'Incidents', rows: data.incidents || [],
        render: row => collectionCard(row.title, `${row.risk_level} · ${row.status}`,
          [['Category', row.category], ['Outcome', row.outcome], ['Reports', (row.report_ids || []).length],
            ['Entities', (row.entities || []).map(entity => `${entity.role}: ${entity.display_value}`)]]),
      },
      {
        title: 'Transactions', rows: data.transactions || [],
        render: row => collectionCard(`${row.amount} ${row.currency}`,
          `${row.sender_partner} → ${row.receiver_partner} · ${row.status}`,
          [['Timestamp', row.timestamp], ['Sender graph entity', row.sender_entity_id],
            ['Receiver graph entity', row.receiver_entity_id]]),
      },
    ];
    const content = sections.map(section => `<section class="nexus-collection-group"><h4>${section.title} <span>${section.rows.length}</span></h4>${section.rows.slice(0, 3).map(section.render).join('') || '<p class="helper">No connected records.</p>'}</section>`).join('');
    $('#nexus-collection-content').innerHTML = content || '<p class="helper">No connected intelligence has been collected for this entity.</p>';
    return;
  }
  if (tab === 'relationships') {
    const analysis = data.relationship_analysis || {};
    const graphNodes = new Map((data.graph?.nodes || []).map(node => [node.id, node]));
    const entityLabel = id => {
      const node = graphNodes.get(id);
      if (!node) return id ? `Entity ${String(id).slice(0, 8)}` : 'Unresolved account';
      if (node.metadata?.source === 'pdr') return `${node.metadata.partner_code || 'Partner'} · ${node.type}`;
      return node.display_value || `${node.type} entity`;
    };
    const sections = [
      { title: 'Analysis summary', rows: [analysis.summary || {}], render: row => collectionCard(
        'Collected relationship indicators', 'Descriptive findings · reviewer assessment required',
        Object.entries(row).map(([key, value]) => [key.replaceAll('_', ' '), value])) },
      { title: 'Identifiers reported more than once', rows: analysis.shared_identifiers || [], render: row => collectionCard(
        row.display_value, `${row.report_count} linked reports`, [['Entity type', row.entity_type], ['Reports', row.report_ids]]) },
      { title: 'Repeated transaction counterparties', rows: analysis.repeated_counterparties || [], render: row => collectionCard(
        `${entityLabel(row.sender_entity_id)} → ${entityLabel(row.receiver_entity_id)}`,
        `${row.transaction_count} observed transactions`, [['Partner routes', row.partner_routes], ['Statuses', row.statuses], ['Transaction IDs', row.transaction_ids]]) },
      { title: 'Cross-institution transactions', rows: analysis.cross_institution_transactions || [], render: row => collectionCard(
        `${row.sender_partner} → ${row.receiver_partner}`, `${row.amount} ${row.currency} · ${row.status}`,
        [['Timestamp', row.timestamp], ['Transaction ID', row.id], ['From entity', entityLabel(row.sender_entity_id)], ['To entity', entityLabel(row.receiver_entity_id)]]) },
      { title: 'Cross-provider identity clusters', rows: analysis.cross_provider_identity_clusters || [], render: row => collectionCard(
        `${row.match_type.replaceAll('_', ' ')} cluster`, `${row.partner_count} providers · ${row.status}`,
        [['Confidence', `${Math.round(Number(row.confidence || 0) * 100)}%`], ['Members', (row.members || []).map(member => `${member.partner} · ${member.verification_status}`)]]) },
      { title: 'Transaction paths', rows: analysis.transaction_paths || [], render: row => collectionCard(
        `${entityLabel(row.start_entity_id)} → ${entityLabel(row.end_entity_id)}`,
        `${row.hop_count} transaction hop(s)`, [['Entity path', row.entity_ids.map(entityLabel)], ['Partner routes', row.partner_routes], ['Statuses', row.statuses], ['Transaction IDs', row.transaction_ids]]) },
      { title: 'Observed graph relationship types', rows: Object.entries(analysis.relationship_type_counts || {}).map(([type, count]) => ({ type, count })), render: row => collectionCard(
        row.type.replaceAll('_', ' '), `${row.count} collected relationship(s)`, []) },
    ];
    const content = `<p class="helper nexus-analysis-note">${escapeHtml(analysis.method || 'Descriptive links from collected records; not a fraud determination.')}</p>` +
      sections.map(section => `<section class="nexus-collection-group"><h4>${section.title} <span>${section.rows.length}</span></h4>${section.rows.slice(0, 20).map(section.render).join('') || '<p class="helper">No matching relationship signals in the collected records.</p>'}</section>`).join('');
    $('#nexus-collection-content').innerHTML = content;
    return;
  }
  let cards = [];
  if (tab === 'reports') cards = arr.map(row => collectionCard(row.subject, `${row.report_type} · ${row.status} · ${row.created_at?.slice(0, 10)}`, [['Report ID', row.id], ['Category', row.category], ['Channel', row.channel], ['Source', row.source], ['Description', row.description], ['Extracted entities', (row.extracted_entities || []).map(entity => `${entity.entity_type}: ${entity.display_value} (${Math.round(entity.confidence * 100)}%)`)], ['Linked case', row.case_id]]));
  if (tab === 'incidents') cards = arr.map(row => collectionCard(row.title, `${row.risk_level} risk · ${row.status} · ${Math.round(Number(row.confidence || 0) * 100)}% confidence`, [['Description', row.description], ['Category', row.category], ['Outcome', row.outcome], ['Incident date', row.incident_at], ['Location', row.location], ['Reports', row.report_ids], ['Entities', (row.entities || []).map(entity => `${entity.role}: ${entity.display_value} (${entity.verification_status})`)]]));
  if (tab === 'transactions') cards = arr.map(row => collectionCard(`${row.amount} ${row.currency}`, `${row.sender_partner} → ${row.receiver_partner} · ${row.status}`, [['Transaction record', row.id], ['Timestamp', row.timestamp], ['Sender entity', row.sender_entity_id], ['Receiver entity', row.receiver_entity_id]]));
  if (tab === 'identity_clusters') cards = arr.map(row => collectionCard(`${row.match_type.replaceAll('_', ' ')} identity cluster`, `${row.status} · ${Math.round(Number(row.confidence || 0) * 100)}% confidence`, [['Partners', row.partner_count], ['Identities', row.identity_count], ['Members', (row.members || []).map(member => `${member.partner} · ${member.verification_status}${member.verified_ownership ? ' · ownership verified' : ''}`)]]));
  if (tab === 'evidence') cards = arr.map(row => collectionCard(row.kind, `${row.source} · ${row.created_at?.slice(0, 10)}`, [['Reference', row.reference], ['Content hash', row.content_hash], ['Case', row.case_id], ['Metadata', JSON.stringify(row.metadata || {})]]));
  if (tab === 'findings') cards = arr.map(row => collectionCard(row.title, `${row.type} · ${Math.round(Number(row.confidence || 0) * 100)}% · ${row.source}`, [['Description', row.description], ['Taxonomy', row.taxonomy_id], ['Model', row.model_version], ['Report', row.report_id], ['Evidence', JSON.stringify(row.evidence || {})]]));
  if (tab === 'risk_assessments') cards = arr.map(row => collectionCard(`${row.level} risk · ${Math.round(Number(row.score || 0) * 100)}%`, `${Math.round(Number(row.confidence || 0) * 100)}% confidence · ${row.created_at?.slice(0, 10)}`, [['Reasons', row.reasons], ['Source', row.source], ['Model', row.model_version], ['Report', row.report_id], ['Incident', row.incident_id]]));
  if (tab === 'investigations') cards = arr.map(row => collectionCard(row.title, `${row.status} · updated ${row.updated_at?.slice(0, 10)}`, [['Case ID', row.id], ['Summary', row.summary], ['Assigned investigator', row.assigned_investigator_id], ['Evidence count', row.evidence_count]]));
  if (tab === 'activities') cards = arr.map(row => collectionCard(row.action_type.replaceAll('_', ' '), row.created_at?.slice(0, 10), [['Summary', row.summary], ['Incident', row.incident_id], ['Details', JSON.stringify(row.details || {})]]));
  if (tab === 'signals') cards = arr.map(row => collectionCard(row.type.replaceAll('_', ' '), `${row.risk_level} · ${Math.round(Number(row.score || 0) * 100)}% · ${row.last_seen_at?.slice(0, 10)}`, [['Confidence', `${Math.round(Number(row.confidence || 0) * 100)}%`], ['Partners', row.partner_codes], ['Reasons', row.reasons], ['Evidence', JSON.stringify(row.evidence || {})]]));
  $('#nexus-collection-content').innerHTML = cards.length ? cards.join('') : '<p class="helper">No related records in this section.</p>';
}
async function loadNexusCollection(entityId) {
  $('#nexus-collection-status').textContent = 'Collecting linked records…';
  try {
    const data = await apiRequest(`/intelligence/layers/entities/${encodeURIComponent(entityId)}/collection`);
    state.nexusCollection = data;
    const counts = data.counts || {};
    $('#nexus-collection-title').textContent = `Intelligence collected for ${data.entity?.display_value || data.entity?.type || 'entity'}`;
    $('#nexus-collection-status').textContent = data.collection_scope?.truncated ? 'Live · 400 entity cap' : 'Live FIR + PDR';
    $('#nexus-collection-summary').innerHTML = [
      ['Reports', counts.reports], ['Incidents', counts.incidents], ['Transactions', counts.transactions],
      ['Evidence', counts.evidence], ['Identity links', counts.identity_clusters],
      ['Findings', counts.findings], ['Cases', counts.investigations],
    ].map(([label, value]) => `<span>${escapeHtml(label)} <b>${Number(value || 0).toLocaleString()}</b></span>`).join('');
    renderNexusCollectionTab('overview');
    $('#nexus-referral-target-label').value = data.entity?.display_value || data.entity?.type || '';
    $('#nexus-referral-save').disabled = false;
    await loadNexusPartnerReferrals();
  } catch (error) {
    clearNexusCollection(`Could not collect related intelligence: ${error.message}`);
  }
}

function nexusReferralStatus(message) { $('#nexus-referral-status').textContent = message; }
async function loadNexusPartnerReferrals() {
  if (state.demo) {
    $('#nexus-referral-partner').innerHTML = '<option value="">Switch to Live API to select a partner</option>';
    $('#nexus-referral-items').innerHTML = '<p class="helper">Partner referrals are available in Live API mode.</p>';
    nexusReferralStatus('Connect to the live API to prepare an auditable partner referral.');
    return;
  }
  try {
    const [partners, referrals] = await Promise.all([
      apiRequest('/intelligence/layers/partner-referrals/partners'),
      apiRequest('/intelligence/layers/partner-referrals'),
    ]);
    state.nexusReferralPartners = partners;
    state.nexusReferrals = referrals;
    const select = $('#nexus-referral-partner');
    const selected = select.value;
    select.innerHTML = '<option value="">Select responsible partner</option>' + partners.map(partner =>
      `<option value="${escapeHtml(partner.id)}">${escapeHtml(partner.partner_name)} · ${escapeHtml(partner.partner_type)}</option>`).join('');
    if (partners.some(partner => partner.id === selected)) select.value = selected;
    if (!partners.length) select.innerHTML = '<option value="">No active partners registered</option>';
    renderNexusReferrals();
    nexusReferralStatus(partners.length ? 'Drafts are saved for review. An approved PDF can be sent through your approved partner channel.' : 'Register an active partner before creating a referral.');
  } catch (error) {
    $('#nexus-referral-items').innerHTML = `<p class="helper">Could not load referrals: ${escapeHtml(error.message)}</p>`;
    nexusReferralStatus(error.message);
  }
}
function referralActionLabel(action) {
  return ({ review_account: 'Review account or transaction', preserve_records: 'Preserve relevant records',
    assess_restriction: 'Assess temporary restriction', assess_recall_recovery: 'Assess recall or recovery', other: 'Other review' })[action] || action;
}
function renderNexusReferrals() {
  const items = state.nexusReferrals || [];
  if (!items.length) { $('#nexus-referral-items').innerHTML = '<p class="helper">No partner referrals yet.</p>'; return; }
  const claims = (() => { try { const part = state.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'); return JSON.parse(atob(part.padEnd(Math.ceil(part.length / 4) * 4, '='))); } catch { return {}; } })();
  const role = claims.role || '';
  $('#nexus-referral-items').innerHTML = items.map(item => `<article class="nexus-referral-item">
    <div><b>${escapeHtml(item.target_label)}</b><span class="pill neutral">${escapeHtml(item.status.replaceAll('_', ' '))}</span><p>${escapeHtml(item.partner_name)} · ${escapeHtml(referralActionLabel(item.requested_action))}</p><small>${escapeHtml(item.target_reference)} · ${escapeHtml(String(item.created_at || '').slice(0, 16).replace('T', ' '))}</small></div>
    <div class="nexus-referral-actions"><button class="text-button" data-referral-pdf="${escapeHtml(item.id)}">Print / Save PDF</button>
      ${item.status === 'draft' ? `<button class="text-button" data-referral-submit="${escapeHtml(item.id)}">Submit for review</button>` : ''}
      ${item.status === 'pending_review' && ['reviewer', 'admin'].includes(role) && claims.sub !== item.created_by ? `<button class="text-button" data-referral-review="approved" data-referral-id="${escapeHtml(item.id)}">Approve</button><button class="text-button" data-referral-review="declined" data-referral-id="${escapeHtml(item.id)}">Decline</button>` : ''}
      ${item.status === 'approved' ? `<button class="text-button" data-referral-sent="${escapeHtml(item.id)}">Mark sent</button>` : ''}
      ${item.status === 'sent' ? `<button class="text-button" data-referral-response="${escapeHtml(item.id)}">Record partner response</button>` : ''}
      ${item.review_note ? `<small>Review: ${escapeHtml(item.review_note)}</small>` : ''}${item.partner_response ? `<small>Partner response: ${escapeHtml(item.partner_response)}</small>` : ''}
    </div></article>`).join('');
}
function buildNexusReferralSnapshot() {
  const data = state.nexusCollection || {};
  const nodes = (data.graph?.nodes || []).slice(0, 80).map(node => ({
    id: node.id, type: node.type, label: node.display_value || node.type,
    source: node.metadata?.source || 'FIR/shared', source_table: node.metadata?.source_table || null,
    source_record_id: node.metadata?.source_record_id || node.id,
    verification_status: node.metadata?.verification_status || node.metadata?.trust_status || 'unverified',
  }));
  const nodeIds = new Set(nodes.map(node => String(node.id)));
  const edges = (data.graph?.edges || []).filter(edge => nodeIds.has(String(edge.source_entity_id)) && nodeIds.has(String(edge.target_entity_id))).slice(0, 160).map(edge => ({
    source: edge.source_entity_id, target: edge.target_entity_id, relationship: edge.relationship_type,
    confidence: edge.confidence, verification_status: edge.metadata?.verification_status || edge.metadata?.trust_status || 'relationship recorded; investigator review required',
  }));
  return {
    captured_at: new Date().toISOString(), entity: data.entity, profile: data.profile,
    collection_scope: data.collection_scope, graph: { nodes, edges, total_nodes: data.graph?.nodes?.length || 0, total_edges: data.graph?.edges?.length || 0 },
    reports: (data.reports || []).slice(0, 50).map(row => ({ id: row.id, subject: row.subject, status: row.status, created_at: row.created_at, source: row.source })),
    transactions: (data.transactions || []).slice(0, 100).map(row => ({ id: row.id, amount: row.amount, currency: row.currency, sender_partner: row.sender_partner, receiver_partner: row.receiver_partner, status: row.status, timestamp: row.timestamp, transaction_reference: row.transaction_reference })),
    relationship_analysis: data.relationship_analysis?.summary || {},
    evidence_status_note: 'Graph links retain source references. Allegations, observed records, candidate matches and investigator-confirmed links must be assessed separately.',
  };
}
async function createNexusReferral(event) {
  event.preventDefault();
  if (state.demo || !state.nexusCollection) return nexusReferralStatus('Load a live NEXUS entity before creating a referral.');
  const button = $('#nexus-referral-save'); button.disabled = true;
  nexusReferralStatus('Saving referral draft…');
  try {
    const body = {
      partner_id: $('#nexus-referral-partner').value,
      requested_action: $('#nexus-referral-action').value,
      target_label: $('#nexus-referral-target-label').value.trim(),
      target_reference: $('#nexus-referral-target-reference').value.trim(),
      rationale: $('#nexus-referral-rationale').value.trim(),
      case_id: state.nexusActiveCase?.id || undefined,
      evidence_snapshot: buildNexusReferralSnapshot(),
    };
    const referral = await apiRequest('/intelligence/layers/partner-referrals', { method: 'POST', body: JSON.stringify(body) });
    $('#nexus-referral-form').reset();
    $('#nexus-referral-target-label').value = state.nexusCollection.entity?.display_value || state.nexusCollection.entity?.type || '';
    await loadNexusPartnerReferrals();
    nexusReferralStatus(`Draft ${String(referral.id).slice(0, 8)} saved. Submit it for a separate reviewer decision.`);
  } catch (error) { nexusReferralStatus(`Could not save referral: ${error.message}`); }
  finally { button.disabled = false; }
}
function makeReferralSvg(snapshot) {
  const graph = snapshot?.graph || {}; const nodes = (graph.nodes || []).slice(0, 50); const edges = graph.edges || [];
  if (!nodes.length) return '<p>No graph nodes were captured for this referral.</p>';
  const root = String(snapshot.entity?.id || nodes[0].id);
  const byId = new Map(nodes.map(node => [String(node.id), node])); const depths = new Map([[root, 0]]); const queue = [root];
  for (let i = 0; i < queue.length; i++) {
    const current = queue[i];
    for (const edge of edges) {
      const a = String(edge.source); const b = String(edge.target); const next = a === current ? b : b === current ? a : null;
      if (next && byId.has(next) && !depths.has(next)) { depths.set(next, Math.min(4, (depths.get(current) || 0) + 1)); queue.push(next); }
    }
  }
  nodes.forEach(node => { if (!depths.has(String(node.id))) depths.set(String(node.id), 1); });
  const columns = Array.from({ length: 5 }, (_, depth) => nodes.filter(node => (depths.get(String(node.id)) || 0) === depth));
  const positions = new Map(); let height = 180;
  columns.forEach((column, depth) => { height = Math.max(height, 70 + column.length * 82); column.forEach((node, index) => positions.set(String(node.id), { x: 95 + depth * 190, y: 45 + index * 82 })); });
  const lineMarkup = edges.slice(0, 80).map(edge => { const a = positions.get(String(edge.source)); const b = positions.get(String(edge.target)); if (!a || !b) return ''; return `<g><line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/><text x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2-4}">${escapeHtml(String(edge.relationship || 'linked').slice(0, 22))}</text></g>`; }).join('');
  const nodeMarkup = nodes.map(node => { const p = positions.get(String(node.id)); const label = String(node.label || node.type || 'Record'); return `<g><circle class="${node.source === 'pdr' ? 'pdr' : 'fir'}" cx="${p.x}" cy="${p.y}" r="22"/><text class="type" x="${p.x}" y="${p.y-3}">${escapeHtml(String(node.type || 'record').slice(0, 13))}</text><text class="label" x="${p.x}" y="${p.y+38}">${escapeHtml(label.slice(0, 28))}</text></g>`; }).join('');
  return `<svg class="referral-graph" viewBox="0 0 900 ${height}" role="img" aria-label="NEXUS relationship graph">${lineMarkup}${nodeMarkup}</svg><p class="helper">Showing ${nodes.length} captured nodes and up to 80 links. The referral snapshot records ${graph.total_nodes || nodes.length} nodes and ${graph.total_edges || edges.length} links in scope.</p>`;
}
function printNexusReferral(referralId) {
  const item = state.nexusReferrals.find(row => row.id === referralId); if (!item) return;
  const popup = window.open('', '_blank'); if (!popup) return nexusReferralStatus('Allow pop-ups for this page to print the partner referral PDF.');
  const data = item.evidence_snapshot || {};
  const reports = (data.reports || []).map(row => `<li><b>${escapeHtml(row.subject || 'FIR report')}</b> · ${escapeHtml(row.status)} · ${escapeHtml(row.id)}</li>`).join('') || '<li>No FIR reports in the captured scope.</li>';
  const transactions = (data.transactions || []).map(row => `<li>${escapeHtml(row.amount)} ${escapeHtml(row.currency)} · ${escapeHtml(row.sender_partner)} → ${escapeHtml(row.receiver_partner)} · ${escapeHtml(row.status)} · ${escapeHtml(row.timestamp)} · ${escapeHtml(row.id)}</li>`).join('') || '<li>No transactions in the captured scope.</li>';
  const sourceRows = (data.graph?.nodes || []).slice(0, 80).map(node => `<li>${escapeHtml(node.label || node.type)} · ${escapeHtml(node.source || 'FIR/shared')} · ${escapeHtml(node.source_table || 'source table unavailable')} · record ${escapeHtml(node.source_record_id || node.id)} · ${escapeHtml(node.verification_status || 'unverified')}</li>`).join('') || '<li>No source records captured.</li>';
  popup.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>NEXUS Partner Referral ${escapeHtml(item.id)}</title><style>body{font:14px Arial,sans-serif;color:#17251f;margin:28px}h1{font-size:22px}h2{font-size:16px;margin-top:24px}.meta{display:grid;grid-template-columns:170px 1fr;gap:8px}.meta b{color:#52645b}.disclaimer{border:1px solid #cc8f42;padding:12px;background:#fff9ef;margin:18px 0}.referral-graph{width:100%;height:auto;max-height:650px;border:1px solid #ddd}.referral-graph line{stroke:#86948c;stroke-width:1.6}.referral-graph circle{stroke:#fff;stroke-width:2}.referral-graph .fir{fill:#318567}.referral-graph .pdr{fill:#6655cb}.referral-graph text{text-anchor:middle;font-size:9px;fill:#64736b}.referral-graph .type{font-size:7px;font-weight:bold;fill:white}.referral-graph .label{font-size:8px}.helper{color:#68766f;font-size:11px}li{margin:7px 0;overflow-wrap:anywhere}@media print{body{margin:12mm}.no-print{display:none}}</style></head><body><div class="no-print"><button onclick="window.print()">Print / Save as PDF</button></div><h1>SafeGuard · NEXUS Partner Referral</h1><p>Referral ${escapeHtml(item.id)} · Status: ${escapeHtml(item.status)} · Created ${escapeHtml(item.created_at)}</p><div class="disclaimer"><b>Partner review requested</b><br>This report is investigative context, not an instruction to freeze, debit, or reverse funds. The partner makes its own decision under its procedures and authority.</div><div class="meta"><b>Partner</b><span>${escapeHtml(item.partner_name)}</span><b>Requested action</b><span>${escapeHtml(referralActionLabel(item.requested_action))}</span><b>Entity / account</b><span>${escapeHtml(item.target_label)} · ${escapeHtml(item.target_reference)}</span><b>Investigator rationale</b><span>${escapeHtml(item.rationale)}</span><b>Investigation case</b><span>${escapeHtml(item.case_id || 'Not linked')}</span></div><h2>NEXUS relationship graph</h2>${makeReferralSvg(data)}<h2>Graph source records and verification status</h2><ul>${sourceRows}</ul><h2>Related FIR reports</h2><ul>${reports}</ul><h2>Observed PDR transactions</h2><ul>${transactions}</ul><p class="helper">${escapeHtml(data.evidence_status_note || '')} Snapshot captured ${escapeHtml(data.captured_at || '')}. Protect and transmit this document only through an approved secure partner channel.</p></body></html>`);
  popup.document.close();
}
async function handleReferralAction(event) {
  const submit = event.target.closest('[data-referral-submit]'); const review = event.target.closest('[data-referral-review]');
  const markSent = event.target.closest('[data-referral-sent]'); const recordResponse = event.target.closest('[data-referral-response]');
  const print = event.target.closest('[data-referral-pdf]');
  try {
    if (print) return printNexusReferral(print.dataset.referralPdf);
    if (submit) await apiRequest(`/intelligence/layers/partner-referrals/${encodeURIComponent(submit.dataset.referralSubmit)}/submit`, { method: 'POST' });
    if (review) {
      const note = window.prompt(`${review.dataset.referralReview === 'approved' ? 'Approval' : 'Decline'} note (required):`);
      if (!note) return;
      await apiRequest(`/intelligence/layers/partner-referrals/${encodeURIComponent(review.dataset.referralId)}/review`, { method: 'POST', body: JSON.stringify({ decision: review.dataset.referralReview, note }) });
    }
    if (markSent) {
      if (!window.confirm('Confirm this approved referral and its PDF were sent through the approved partner channel?')) return;
      await apiRequest(`/intelligence/layers/partner-referrals/${encodeURIComponent(markSent.dataset.referralSent)}/mark-sent`, { method: 'POST' });
    }
    if (recordResponse) {
      const response = window.prompt('Enter the partner response for the audit record:'); if (!response) return;
      await apiRequest(`/intelligence/layers/partner-referrals/${encodeURIComponent(recordResponse.dataset.referralResponse)}/response`, { method: 'POST', body: JSON.stringify({ response }) });
    }
    await loadNexusPartnerReferrals();
  } catch (error) { nexusReferralStatus(`Referral action failed: ${error.message}`); }
}
function nexusIntakeType(type) {
  const map = { phone: 'phone', account: 'account', wallet: 'wallet', transaction: 'transaction',
    person: 'person', organization: 'business', business: 'business', agent: 'agent',
    identity: 'identity', email: 'identity', link: 'identity', message: 'identity' };
  return map[String(type || '').toLowerCase()] || 'identity';
}
function openNexusIntake(context = null) {
  state.nexusIntakeContext = context;
  const fromRecord = Boolean(context?.source_record_id || context?.entity_id);
  $('#nexus-intake-type').value = context?.intake_type || 'phone';
  $('#nexus-intake-type').disabled = fromRecord;
  $('#nexus-intake-identifier').value = context?.identifier || '';
  $('#nexus-intake-identifier').disabled = fromRecord;
  $('#nexus-intake-source').textContent = context?.label
    ? `Starting from ${context.label}. The linked source will be attached to the case.`
    : 'Enter an indicator to start an investigation. You can also start from a selected report, PDR record, or graph entity.';
  $('#nexus-intake-title').value = (context?.title || (context?.label ? `Investigation · ${context.label}` : '')).slice(0, 160);
  $('#nexus-intake-summary').value = context?.summary || '';
  $('#nexus-intake-status').textContent = context?.source_record_id
    ? 'The source record ID will be attached as typed case evidence.'
    : 'Manual identifiers are stored as protected references, not raw case evidence.';
  $('#nexus-intake-dialog').showModal();
}
async function createNexusInvestigation(event) {
  event.preventDefault();
  if (state.demo) {
    $('#nexus-intake-status').textContent = 'Switch to Live API mode and sign in as a reviewer or administrator to create an investigation.';
    return;
  }
  const context = state.nexusIntakeContext;
  const identifier = $('#nexus-intake-identifier').value.trim();
  const body = {
    title: $('#nexus-intake-title').value.trim(),
    summary: $('#nexus-intake-summary').value.trim() || undefined,
    intake_type: $('#nexus-intake-type').value,
    source_system: context?.source_system || 'manual',
    source_record_id: context?.source_record_id || undefined,
    entity_id: context?.entity_id || undefined,
    identifier: context?.identifier || identifier || undefined,
  };
  if (body.source_system === 'manual' && !body.identifier) {
    $('#nexus-intake-status').textContent = 'Enter a starting identifier first.';
    return;
  }
  $('#nexus-intake-submit').disabled = true;
  $('#nexus-intake-status').textContent = 'Creating case and attaching its intake evidence…';
  try {
    const created = await apiRequest('/cases/intake', { method: 'POST', body: JSON.stringify(body) });
    state.caseId = created.id;
    localStorage.setItem('safeguard.caseId', state.caseId);
    state.nexusSelectedEvidence = null;
    await activateNexusCase(created.id, { ...created, evidence: [{ details: {
      entity_id: body.entity_id || null, source_record_id: body.source_record_id || null,
    } }] });
    $('#nexus-intake-dialog').close();
    setNexusStatus(`Investigation ${created.id.slice(0, 8)} created and set as active. Its starting evidence is attached.`);
    state.nexusIntakeContext = null;
    await loadNexusTab('reports');
  } catch (error) {
    $('#nexus-intake-status').textContent = error.message;
  } finally {
    $('#nexus-intake-submit').disabled = false;
  }
}
async function extractAndMatchNexusReport() {
  if (state.demo) return setNexusStatus('Switch to Live API mode and sign in as a reviewer or administrator to extract and match a FIR report.');
  if (!state.nexusReportId) return setNexusStatus('Select a FIR report first.');
  const button = $('#nexus-extract-match');
  button.disabled = true;
  setNexusStatus('Extracting identifiers and matching FIR/PDR records…');
  try {
    const result = await apiRequest(`/intelligence/layers/reports/${encodeURIComponent(state.nexusReportId)}/extract-match`, { method: 'POST' });
    if (result.nexus_graph?.nodes?.length) {
      renderNexusGraph(result.nexus_graph, { display_value: 'FIR investigation network', type: 'report' });
      const summary = result.nexus_graph.summary || {};
      $('#nexus-workspace-kicker').textContent = 'FIR + PDR investigation graph';
      $('#nexus-workspace-title').textContent = `${summary.node_count || result.nexus_graph.nodes.length} connected records`;
    }
    const items = result.items || [];
    $('#nexus-workspace-kicker').textContent = 'Automatic extraction & matching';
    $('#nexus-workspace-title').textContent = `${result.extracted_count} identifier(s) extracted`;
    $('#nexus-list').innerHTML = [
      ...items.map((item, index) => `<button class="nexus-result" data-extracted-index="${index}"><b>${escapeHtml(item.kind.replaceAll('_', ' '))} · ${escapeHtml(item.value)}</b><span>${Math.round(Number(item.confidence) * 100)}% extraction confidence · ${item.pdr_matches.length} PDR match(es)</span></button>`),
      ...(result.possible_duplicate_reports || []).map((report, index) => `<button class="nexus-result nexus-duplicate-result" data-duplicate-report="${index}"><b>Possible duplicate · ${escapeHtml(report.subject)}</b><span>${escapeHtml(report.status)} · ${report.shared_entity_ids.length} shared entity match(es)</span></button>`),
    ].join('') || '<p class="helper">No supported identifiers were found in the report text.</p>';
    $('#nexus-list').querySelectorAll('[data-extracted-index]').forEach(row => row.addEventListener('click', async () => {
      const item = items[Number(row.dataset.extractedIndex)];
      const preferredPdrKind = item.kind === 'account' || item.kind === 'wallet' ? 'account' :
        item.kind === 'transaction' ? 'transaction' : 'identity';
      const pdrMatch = item.pdr_matches?.find(match => match.kind === preferredPdrKind) || item.pdr_matches?.[0];
      state.nexusIntakeContext = pdrMatch?.record_id
        ? { source_system: 'pdr', source_record_id: pdrMatch.record_id, entity_id: pdrMatch.entity_id || item.entity_id || undefined,
            intake_type: pdrMatch.kind === 'transaction' ? 'transaction' : pdrMatch.kind === 'account'
              ? (/momo|wallet/i.test(pdrMatch.account_type || pdrMatch.title) ? 'wallet' : 'account') : 'identity',
            label: pdrMatch.title, summary: pdrMatch.summary }
        : item.entity_id
          ? { source_system: 'graph', entity_id: item.entity_id, intake_type: nexusIntakeType(item.kind), label: item.value }
          : { source_system: 'manual', identifier: item.value, intake_type: nexusIntakeType(item.kind), label: item.value };
      if (item.entity_id) await openNexusEntity(item.entity_id, item.value);
      else if (pdrMatch?.entity_id) await openNexusEntity(pdrMatch.entity_id, pdrMatch.title);
      else { nexusEmpty('No connected graph match', 'The identifier was extracted and attached to FIR, but no existing graph entity matched it.'); clearNexusCollection('No connected graph entity was found for this identifier.'); }
      const duplicateCount = result.possible_duplicate_reports?.length || 0;
      renderNexusDetails(item.value, [['Extracted type', item.kind], ['Confidence', `${Math.round(Number(item.confidence) * 100)}%`], ['FIR entity', item.entity_id ? 'Linked' : 'No graph entity type for this identifier'], ['PDR matches', item.pdr_matches?.map(match => `${match.title} (${match.matched_field})`).join('; ') || 'No exact PDR match'], ['Possible duplicate reports', duplicateCount], ['Evidence status', item.entity_id ? 'Saved to FIR as unverified NEXUS extraction' : 'Extracted from FIR text; not stored as a graph entity']]);
      setNexusStatus(`Identifier extracted and matched. ${duplicateCount} possible duplicate report(s) share extracted entities.`);
    }));
    $('#nexus-list').querySelectorAll('[data-duplicate-report]').forEach(row => row.addEventListener('click', () => {
      const report = result.possible_duplicate_reports[Number(row.dataset.duplicateReport)];
      state.nexusIntakeContext = { source_system: 'fir', source_record_id: report.report_id,
        intake_type: 'report', label: report.subject, summary: `Possible duplicate of FIR report ${report.report_id}.` };
      state.nexusReportId = report.report_id;
      renderNexusDetails(report.subject, [['Report ID', report.report_id], ['Status', report.status], ['Shared entities', report.shared_entity_ids.length], ['Match type', 'Exact shared extracted identifier']]);
      setNexusStatus('Possible duplicate report selected. Start an investigation or run extraction on it.');
      nexusEmpty('Possible duplicate report', 'This report shares an extracted entity with the selected source report.');
    }));
    renderNexusDetails('Extraction complete', [['Extracted identifiers', result.extracted_count], ['Linked into FIR', result.linked_to_fir], ['Possible duplicate reports', result.possible_duplicate_reports?.length || 0], ['Graph entities refreshed', result.layers_refreshed?.graph_entities || 0]]);
    if (result.nexus_graph?.nodes?.length) {
      const summary = result.nexus_graph.summary || {};
      $('#nexus-workspace-kicker').textContent = 'FIR + PDR investigation graph';
      $('#nexus-workspace-title').textContent = `${summary.node_count || result.nexus_graph.nodes.length} connected records`;
      setNexusStatus(`${summary.pdr_identity_count || 0} PDR identities · ${summary.pdr_account_count || 0} accounts · ${summary.transaction_count || 0} transactions · ${summary.candidate_transaction_count || 0} unconfirmed transaction candidate(s).`);
      await loadNexusTrace(state.nexusReportId);
    } else setNexusStatus(`${result.extracted_count} identifier(s) extracted, but no connected graph records were found yet.`);
    if (!result.nexus_graph?.nodes?.length) nexusEmpty(items.length ? 'Select an extracted identifier' : 'No identifiers extracted', items.length ? 'Choose a candidate to inspect exact FIR/PDR matches and shared reports.' : 'The report has no extracted records available to graph yet.');
  } catch (error) {
    setNexusStatus(`Extraction failed: ${error.message}`);
    nexusEmpty('Could not extract and match report', error.message);
  } finally { button.disabled = false; }
}
function nexusFormatTrustTier(tier) {
  return {
    allegation: 'Allegation',
    observed: 'Observed transfer',
    candidate: 'Candidate match',
    investigator_confirmed: 'Investigator confirmed',
  }[tier] || tier || 'Allegation';
}
function nexusTrustTierFromNode(node) {
  const status = String(node?.verification_status || '');
  const source = String(node?.source || '').toLowerCase();
  if (/investigator|reviewer_verified|confirmed/i.test(status) && !/unconfirmed|not/i.test(status)) return 'investigator_confirmed';
  if (source === 'pdr' || /pdr_|transaction_record/i.test(status)) return 'observed';
  if (/candidate|alleged|allegation|phone_reference|unverified/i.test(status)) return 'candidate';
  return 'allegation';
}
function clearNexusTrace() {
  state.nexusTraceBundle = null;
  const panel = $('#nexus-trace-panel');
  if (panel) panel.hidden = true;
  if ($('#nexus-trace-steps')) $('#nexus-trace-steps').innerHTML = '';
  if ($('#nexus-pattern-candidates')) $('#nexus-pattern-candidates').innerHTML = '';
  if ($('#nexus-exposure-sentence')) $('#nexus-exposure-sentence').textContent = '';
}
async function submitNexusTraceDecision(targetId, decision, role = null) {
  if (!state.nexusReportId || state.demo) return;
  try {
    const body = { target_type: 'entity', target_id: targetId, decision, role: role || undefined };
    const result = await apiRequest(
      `/intelligence/layers/reports/${encodeURIComponent(state.nexusReportId)}/nexus-trace/decisions`,
      { method: 'POST', body: JSON.stringify(body) },
    );
    state.nexusTraceBundle = result.trace;
    renderNexusTrace(result.trace);
    if (result.trace?.exposure?.sentence) setNexusStatus(`Exposure updated · ${result.trace.exposure.sentence}`);
  } catch (error) {
    setNexusStatus(`Could not save investigator decision: ${error.message}`);
  }
}
function renderNexusTrace(bundle) {
  const panel = $('#nexus-trace-panel');
  if (!panel || !bundle) return;
  panel.hidden = false;
  const exp = bundle.exposure;
  $('#nexus-exposure-sentence').textContent = exp?.sentence
    || 'Exposure appears when PDR inflows exist and an investigator confirms collection/suspect wallets.';
  const confirmed = new Set((bundle.investigator_decisions?.confirmed_entity_ids || []).map(String));
  const steps = bundle.steps || [];
  $('#nexus-trace-steps').innerHTML = steps.length ? steps.map(step => {
    const nodeId = String(step.node_id || '');
    const bareId = nodeId.startsWith('fir-entity:') ? nodeId.split(':').slice(1).join(':') : nodeId;
    const isConfirmed = confirmed.has(bareId);
    const canDecide = step.kind !== 'report' && (nodeId.startsWith('fir-entity:') || bareId.length === 36);
    const actions = canDecide && !isConfirmed
      ? `<div class="nexus-trace-actions"><button type="button" class="text-button" data-trace-confirm="${escapeHtml(nodeId)}" data-trace-role="${step.kind === 'wallet_or_account' || step.kind === 'ledger_wallet' || step.kind === 'cash_out' ? 'collection_wallet' : 'suspect'}">Confirm</button><button type="button" class="text-button" data-trace-reject="${escapeHtml(nodeId)}">Reject</button></div>`
      : (isConfirmed ? '<span class="pill green">Investigator confirmed</span>' : '');
    return `<li class="nexus-trace-step"><header><b>${step.step}. ${escapeHtml(step.label)}</b><span class="nexus-trust-tier ${escapeHtml(step.trust_tier)}">${escapeHtml(nexusFormatTrustTier(step.trust_tier))}</span></header><span class="helper">${escapeHtml(step.source)} · ${escapeHtml(String(step.kind).replaceAll('_', ' '))}</span>${actions}</li>`;
  }).join('') : '<li class="helper">Run extract &amp; match to build the FIR→PDR trace.</li>';
  $('#nexus-trace-steps').querySelectorAll('[data-trace-confirm]').forEach(button => {
    button.addEventListener('click', () => submitNexusTraceDecision(button.dataset.traceConfirm, 'confirm', button.dataset.traceRole));
  });
  $('#nexus-trace-steps').querySelectorAll('[data-trace-reject]').forEach(button => {
    button.addEventListener('click', () => submitNexusTraceDecision(button.dataset.traceReject, 'reject'));
  });
  const patterns = bundle.pattern_candidates || [];
  $('#nexus-pattern-candidates').innerHTML = patterns.length
    ? patterns.map(row => `<div class="nexus-pattern-card"><b>${escapeHtml(row.pattern.replaceAll('_', ' '))}</b> · review candidate<p class="helper">${escapeHtml(row.summary)}</p></div>`).join('')
    : '';
}
async function loadNexusTrace(reportId = state.nexusReportId) {
  if (!reportId || state.demo) return clearNexusTrace();
  try {
    const bundle = await apiRequest(`/intelligence/layers/reports/${encodeURIComponent(reportId)}/nexus-trace`);
    state.nexusTraceBundle = bundle;
    renderNexusTrace(bundle);
  } catch {
    clearNexusTrace();
  }
}
async function loadNexusReportGraph() {
  if (!state.nexusReportId) return setNexusStatus('Select a FIR report first.');
  if (state.demo) return setNexusStatus('Switch to Live API mode to load the auto-built investigation graph.');
  setNexusStatus('Loading auto-built NEXUS investigation graph…');
  try {
    const result = await apiRequest(`/intelligence/layers/reports/${encodeURIComponent(state.nexusReportId)}/nexus-graph`);
    if (result.nexus_graph?.nodes?.length) {
      renderNexusGraph(result.nexus_graph, { display_value: 'FIR investigation network', type: 'report' });
      const summary = result.nexus_graph.summary || {};
      $('#nexus-workspace-kicker').textContent = result.nexus_meta?.auto ? 'Auto-built FIR + PDR graph' : 'FIR + PDR investigation graph';
      $('#nexus-workspace-title').textContent = `${summary.node_count || result.nexus_graph.nodes.length} connected records`;
      const cash = result.nexus_meta?.cash_out_hints?.length || 0;
      setNexusStatus(`${summary.pdr_account_count || 0} PDR accounts · ${summary.transaction_count || 0} transfers · ${cash} potential cash-out node(s). Re-run extract & match to refresh.`);
      renderNexusDetails('Investigation graph', [['Processed at', result.nexus_meta?.processed_at || '—'], ['Ledger hops', summary.network_scope || '—'], ['Cash-out hints', cash]]);
      await loadNexusTrace(state.nexusReportId);
    } else {
      nexusEmpty('Graph not ready yet', 'No PDR-linked wallets were found. Seed partner data or run extract & match.');
      setNexusStatus('Report is indexed in FIR; no PDR money graph yet.');
      clearNexusTrace();
    }
  } catch (error) {
    setNexusStatus(error.message);
    nexusEmpty('Could not load investigation graph', error.message);
    clearNexusTrace();
  }
}
async function selectNexusReport(reportId, title = 'FIR report') {
  state.nexusReportId = reportId;
  state.nexusGraphHistory = [];
  state.nexusNodePositions = null;
  $('#nexus-extract-match').hidden = false;
  state.nexusIntakeContext = { source_system: 'fir', source_record_id: reportId,
    intake_type: 'report', label: title, summary: `Investigation opened from FIR report ${reportId}.` };
  setNexusSelectedEvidence({ evidence_type: 'report', source: 'nexus_fir', value: reportId,
    details: { source_system: 'fir', source_record_id: reportId, intake_type: 'report' } });
  $('#nexus-workspace-kicker').textContent = 'FIR report intake';
  $('#nexus-workspace-title').textContent = title;
  await loadNexusReportGraph();
}
function renderNexusGraph(graph, root = {}) {
  state.nexusGraphData = { graph, root };
  if (graph.nodes?.length && graph.nodes.some(node => node.source || node.source_record_id) && graph.edges?.some(edge => edge.source && edge.target)) {
    renderNexusNetworkGraph(graph, root);
    return;
  }
  const rootNode = graph.nodes?.[0] || { id: root.entity_id, type: root.entity_type || 'entity', display_value: root.entity_value || root.display_value || 'Selected entity' };
  const edges = graph.edges || [];
  state.nexusVisibleTreeEdgeIndexes = new Set(edges.map((_, index) => index));
  const width = 760; const height = 500; const center = { x: width / 2, y: height / 2 };
  const nodes = [rootNode, ...edges.map(edge => edge.node)];
  const treeHeight = Math.max(height, 120 + Math.max(1, edges.length) * 92);
  const treeCenter = { x: 100, y: treeHeight / 2 };
  const positions = nodes.map((node, index) => index === 0 ? treeCenter : {
    x: 390,
    y: 60 + ((index - 1) * (treeHeight - 120)) / Math.max(edges.length - 1, 1),
  });
  const links = edges.map((edge, index) => {
    const point = positions[index + 1];
    return `<g class="nexus-link" data-nexus-edge="${index}" tabindex="0" role="button" aria-label="Inspect ${escapeHtml((edge.relationship_type || 'linked').replaceAll('_', ' '))} relationship"><line x1="${center.x}" y1="${center.y}" x2="${point.x}" y2="${point.y}"/><text x="${(center.x + point.x) / 2}" y="${(center.y + point.y) / 2 - 7}">${escapeHtml((edge.relationship_type || 'linked').replaceAll('_', ' '))}</text></g>`;
  }).join('');
  const circles = nodes.map((node, index) => {
    const point = positions[index]; const label = String(node.display_value || node.type || 'Entity');
    return `<g class="nexus-node ${index === 0 ? 'root' : ''}" data-nexus-node="${index}" tabindex="0" role="button"><circle cx="${point.x}" cy="${point.y}" r="${index === 0 ? 39 : 30}"/><text class="node-type" x="${point.x}" y="${point.y - 4}">${escapeHtml(String(node.type || 'entity').slice(0, 13))}</text><text class="node-label" x="${point.x}" y="${point.y + 11}">${escapeHtml(label.slice(0, 20))}</text></g>`;
  }).join('');
  state.nexusGraphView = { scale: 1, x: 0, y: 0 };
  $('#nexus-graph').classList.add('nexus-graph-tree');
  $('#nexus-graph').innerHTML = `<svg viewBox="0 0 ${width} ${treeHeight}" style="width:${width}px;height:${treeHeight}px" role="img" aria-label="Investigation relationship tree"><g class="nexus-scene">${links}${circles}</g></svg>`;
  applyNexusGraphView();
  $('#nexus-workspace-title').textContent = rootNode.display_value || rootNode.type || 'Entity graph';
  const nodeData = nodes.map((node, index) => ({ ...node, relationship: index ? edges[index - 1]?.relationship_type : 'investigation starting point', confidence: index ? edges[index - 1]?.confidence : root.confidence }));
  $('#nexus-graph').querySelectorAll('[data-nexus-node]').forEach(button => button.addEventListener('click', async () => {
    if (nexusSuppressClick) { nexusSuppressClick = false; return; }
    const index = Number(button.dataset.nexusNode);
    const node = nodeData[index];
    const graphNode = {
      ...node,
      display_value: node.display_value || node.type,
      source: node.source || 'shared',
      source_table: node.source_table || 'community_entities',
      source_record_id: node.source_record_id || node.id,
      verification_status: node.verification_status,
      details: { ...(node.metadata || {}), relationship: node.relationship, confidence: node.confidence },
    };
    const expandActions = index ? [{ entityId: node.id, label: 'Expand graph from this entity' }] : [];
    await showNexusGraphNodeDetails(graphNode, expandActions);
    setNexusSelectedEvidence(evidenceForEntity(node, {
      relationship_type: node.relationship || null,
      relationship_confidence: node.confidence ?? null,
    }));
    if (index) {
      const body = $('#nexus-detail-body');
      const rel = `<div class="nexus-detail-row"><span>Relationship</span><b>${escapeHtml(String(node.relationship || '—').replaceAll('_', ' '))}</b></div>`;
      const conf = `<div class="nexus-detail-row"><span>Confidence</span><b>${escapeHtml(node.confidence == null ? '—' : `${Math.round(Number(node.confidence) * 100)}%`)}</b></div>`;
      body.insertAdjacentHTML('afterbegin', rel + conf);
    }
  }));
  $('#nexus-graph').querySelectorAll('[data-nexus-node]').forEach(button => button.addEventListener('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    }
  }));
  $('#nexus-graph').querySelectorAll('[data-nexus-edge]').forEach(element => {
    const inspect = () => {
      const edge = edges[Number(element.dataset.nexusEdge)];
      const linkedNode = edge?.node;
      const sourceId = rootNode.id || root.entity_id;
      setNexusSelectedEvidence({ evidence_type: 'other', source: 'nexus_graph',
        value: sourceId && linkedNode?.id ? `${sourceId}:${linkedNode.id}:${edge?.relationship_type || 'linked'}` : null,
        details: { evidence_kind: 'graph_relationship', source_entity_id: sourceId || null,
          target_entity_id: linkedNode?.id || null, relationship_type: edge?.relationship_type || 'linked',
          direction: edge?.direction || 'connected', confidence: edge?.confidence ?? null } });
      renderNexusDetails('Relationship', [
        ['Type', String(edge?.relationship_type || 'linked').replaceAll('_', ' ')],
        ['Direction', edge?.direction || 'connected'],
        ['Confidence', edge?.confidence == null ? '—' : `${Math.round(Number(edge.confidence) * 100)}%`],
        ['Evidence / metadata', JSON.stringify(edge?.metadata || {})],
        ['From', rootNode.display_value || rootNode.type],
        ['To', linkedNode?.display_value || linkedNode?.type],
      ], [
        ...(sourceId ? [{ entityId: sourceId, label: 'Open source entity graph' }] : []),
        ...(linkedNode?.id ? [{ entityId: linkedNode.id, label: 'Expand linked entity' }] : []),
      ]);
      setNexusStatus('Relationship selected · open either connected entity to continue exploring.');
    };
    element.addEventListener('click', inspect);
    element.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); inspect(); } });
  });
  setNexusStatus(`${nodes.length} graph node(s) · ${edges.length} relationship(s) · live API`);
}
function nexusIsMoneyEdge(edge) {
  return edge.ledger_relationship === 'pdr_transfer' || edge.verification_status === 'PDR_transaction_record';
}
function nexusIsAllegationEdge(edge) {
  const status = String(edge.verification_status || '');
  return /allegation|candidate|not_identity|possible_transfer/i.test(status)
    || /possible_transfer|exact_transaction/i.test(String(edge.relationship_type || ''));
}
function nexusCollisionRadius(node, rootKey) {
  const isRoot = node?.id === rootKey;
  const kind = String(node?.type || '').toLowerCase();
  const isWallet = kind === 'wallet' || kind === 'account';
  const core = isRoot ? 28 : isWallet ? 22 : 19;
  return core + 30;
}
function nexusResolveCollisions(positions, nodes, width, height, rootKey) {
  const padX = 52, padY = 48;
  for (let step = 0; step < 120; step++) {
    let moved = false;
    for (let a = 0; a < nodes.length; a++) {
      for (let b = a + 1; b < nodes.length; b++) {
        let dx = positions[b].x - positions[a].x;
        let dy = positions[b].y - positions[a].y;
        let d = Math.hypot(dx, dy);
        const minD = nexusCollisionRadius(nodes[a], rootKey) + nexusCollisionRadius(nodes[b], rootKey);
        if (d < 1e-3) {
          const angle = ((a * 17 + b * 31) % 360) * (Math.PI / 180);
          dx = Math.cos(angle);
          dy = Math.sin(angle);
          d = 1;
        }
        if (d < minD) {
          const overlap = (minD - d) / 2;
          const ux = dx / d, uy = dy / d;
          const aRoot = nodes[a].id === rootKey;
          const bRoot = nodes[b].id === rootKey;
          const aW = aRoot ? 0.2 : 1;
          const bW = bRoot ? 0.2 : 1;
          const wSum = aW + bW || 1;
          positions[a].x -= ux * overlap * (2 * aW / wSum);
          positions[a].y -= uy * overlap * (2 * aW / wSum);
          positions[b].x += ux * overlap * (2 * bW / wSum);
          positions[b].y += uy * overlap * (2 * bW / wSum);
          moved = true;
        }
      }
    }
    positions.forEach((p, i) => {
      if (nodes[i].id === rootKey) return;
      p.x = Math.max(padX, Math.min(width - padX, p.x));
      p.y = Math.max(padY, Math.min(height - padY, p.y));
    });
    if (!moved && step > 16) break;
  }
}
function nexusTreeLayout(nodes, edges, rootId) {
  const byId = new Map(nodes.map((node, index) => [node.id, index]));
  const adjacency = new Map(nodes.map(node => [node.id, []]));
  edges.forEach((edge, edgeIndex) => {
    if (edge.source === edge.target || !adjacency.has(edge.source) || !adjacency.has(edge.target)) return;
    adjacency.get(edge.source).push({ other: edge.target, edgeIndex });
    adjacency.get(edge.target).push({ other: edge.source, edgeIndex });
  });
  const edgePriority = edge => {
    const relationship = String(edge.relationship_type || '').toLowerCase();
    if (relationship === 'exact_transaction_reference') return 0;
    if (relationship === 'mentions' || relationship === 'describes_incident') return 1;
    if (relationship.includes('phone_reference')) return 2;
    if (relationship === 'registered_account' || relationship === 'owns') return 3;
    if (nexusIsMoneyEdge(edge)) return 4;
    return 5;
  };
  adjacency.forEach(links => links.sort((a, b) =>
    edgePriority(edges[a.edgeIndex]) - edgePriority(edges[b.edgeIndex])
  ));
  const preferredRoot = rootId || nodes.find(node => node.type === 'report')?.id || nodes[0]?.id;
  const rootOrder = [preferredRoot, ...nodes.map(node => node.id).filter(id => id !== preferredRoot)];
  const visited = new Set();
  const components = [];
  const treeEdges = [];
  const children = new Map(nodes.map(node => [node.id, []]));
  const depth = new Map();

  rootOrder.forEach(componentRoot => {
    if (!componentRoot || visited.has(componentRoot) || !byId.has(componentRoot)) return;
    components.push(componentRoot);
    visited.add(componentRoot);
    depth.set(componentRoot, 0);
    const queue = [componentRoot];
    for (let cursor = 0; cursor < queue.length; cursor++) {
      const parent = queue[cursor];
      for (const link of adjacency.get(parent) || []) {
        if (visited.has(link.other)) continue;
        visited.add(link.other);
        depth.set(link.other, depth.get(parent) + 1);
        children.get(parent).push(link.other);
        treeEdges.push({ edge: edges[link.edgeIndex], originalIndex: link.edgeIndex });
        queue.push(link.other);
      }
    }
  });

  const positions = nodes.map(() => ({ x: 100, y: 80 }));
  let yCursor = 80;
  let maxDepth = 0;
  const horizontalGap = 250;
  const verticalGap = 118;
  const placeSubtree = id => {
    const nodeDepth = depth.get(id) || 0;
    maxDepth = Math.max(maxDepth, nodeDepth);
    const childYs = (children.get(id) || []).map(placeSubtree);
    const y = childYs.length
      ? childYs.reduce((sum, value) => sum + value, 0) / childYs.length
      : (yCursor += verticalGap) - verticalGap;
    positions[byId.get(id)] = { x: 100 + nodeDepth * horizontalGap, y };
    return y;
  };
  components.forEach((componentRoot, index) => {
    if (index) yCursor += 86;
    placeSubtree(componentRoot);
  });

  const width = Math.max(920, 250 + maxDepth * horizontalGap);
  const height = Math.max(620, yCursor + 80);
  return {
    positions, width, height, treeEdges,
    componentCount: components.length,
    hiddenEdgeCount: Math.max(0, edges.length - treeEdges.length),
  };
}
function nexusCurvePath(p, q, bundleIndex, bundleSize) {
  const dx = q.x - p.x, dy = q.y - p.y, dist = Math.hypot(dx, dy) || 1;
  const nx = -dy / dist, ny = dx / dist;
  const spread = bundleSize > 1 ? (bundleIndex - (bundleSize - 1) / 2) * 14 : 0;
  const midx = (p.x + q.x) / 2 + nx * (28 + spread);
  const midy = (p.y + q.y) / 2 + ny * (28 + spread) - Math.min(35, dist * 0.08);
  const endX = q.x - (dx / dist) * 22, endY = q.y - (dy / dist) * 22;
  const startX = p.x + (dx / dist) * 22, startY = p.y + (dy / dist) * 22;
  return `M ${startX} ${startY} Q ${midx} ${midy} ${endX} ${endY}`;
}
function nexusWalletGlyph(x, y, r) {
  const w = r * 0.9, h = r * 0.55;
  return `<rect x="${x - w / 2}" y="${y - h / 2}" width="${w}" height="${h}" rx="${h * 0.2}" class="nexus-wallet-body"/>
    <circle cx="${x + w * 0.28}" cy="${y}" r="${h * 0.14}" class="nexus-wallet-dot"/>`;
}
function nexusViewBoxSize() {
  const svg = $('#nexus-graph svg');
  if (svg?.viewBox?.baseVal?.width) {
    return { width: svg.viewBox.baseVal.width, height: svg.viewBox.baseVal.height };
  }
  return state.nexusGraphSize || { width: 920, height: 520 };
}
function nexusEntityIdFromNode(node) {
  if (!node) return null;
  if (node.entity_id) return node.entity_id;
  const nodeId = String(node.id || '');
  const graphEntity = nodeId.match(/^fir-entity:([0-9a-f-]{36})$/i);
  if (graphEntity) return graphEntity[1];
  const kind = String(node.type || '').toLowerCase();
  if (kind === 'report' || kind === 'case' || kind === 'person') return null;
  if (/^[0-9a-f-]{36}$/i.test(nodeId)) return nodeId;
  return null;
}
function nexusClearGraphHighlight() {
  $('#nexus-graph')?.querySelectorAll('.nexus-node.is-dimmed,.nexus-node.is-neighbor,.nexus-link.is-dimmed,.nexus-link.is-active')
    .forEach(el => el.classList.remove('is-dimmed', 'is-neighbor', 'is-active'));
}
function nexusApplyGraphHighlight(nodeId) {
  const graph = state.nexusGraphData?.graph;
  if (!graph?.edges || !nodeId) { nexusClearGraphHighlight(); return; }
  const neighborIds = new Set([nodeId]);
  graph.edges.forEach((edge, index) => {
    if (state.nexusVisibleTreeEdgeIndexes && !state.nexusVisibleTreeEdgeIndexes.has(index)) return;
    if (edge.source === nodeId) neighborIds.add(edge.target);
    if (edge.target === nodeId) neighborIds.add(edge.source);
  });
  $('#nexus-graph').querySelectorAll('.nexus-node[data-node-id]').forEach(el => {
    const id = el.dataset.nodeId;
    el.classList.toggle('is-dimmed', id !== nodeId && !neighborIds.has(id));
    el.classList.toggle('is-neighbor', id !== nodeId && neighborIds.has(id));
  });
  $('#nexus-graph').querySelectorAll('[data-network-edge]').forEach(el => {
    const index = Number(el.dataset.networkEdge);
    const edge = state.nexusVisibleTreeEdgeIndexes?.has(index) ? graph.edges[index] : null;
    const active = edge && (edge.source === nodeId || edge.target === nodeId);
    el.classList.toggle('is-active', Boolean(active));
    el.classList.toggle('is-dimmed', !active);
  });
}
function nexusSetNodeCoords(element, x, y, r) {
  element.querySelectorAll('.nexus-node-halo,.nexus-node-core').forEach(circle => {
    circle.setAttribute('cx', x); circle.setAttribute('cy', y);
  });
  const label = element.querySelector('.node-label');
  if (label) { label.setAttribute('x', x); label.setAttribute('y', y + r + 16); }
  const body = element.querySelector('.nexus-wallet-body');
  if (body) {
    const wr = r * 0.72, ww = wr * 0.9, wh = wr * 0.55;
    body.setAttribute('x', x - ww / 2); body.setAttribute('y', y - wh / 2);
    body.setAttribute('width', ww); body.setAttribute('height', wh);
    const dot = element.querySelector('.nexus-wallet-dot');
    if (dot) {
      dot.setAttribute('cx', x + ww * 0.28); dot.setAttribute('cy', y); dot.setAttribute('r', wh * 0.14);
    }
  }
  const hub = element.querySelector('.nexus-hub-badge');
  if (hub) hub.setAttribute('transform', `translate(${x + r + 2},${y - r - 22})`);
}
function nexusUpdateConnectedEdges(nodeId) {
  const graph = state.nexusGraphData?.graph;
  const positions = state.nexusNodePositions;
  if (!graph?.edges || !positions) return;
  $('#nexus-graph').querySelectorAll('[data-network-edge]').forEach(el => {
    const edge = graph.edges[Number(el.dataset.networkEdge)];
    if (!edge || (edge.source !== nodeId && edge.target !== nodeId)) return;
    const p = positions[edge.source], q = positions[edge.target];
    if (!p || !q) return;
    const bundleIndex = Number(el.dataset.bundleIndex) || 0;
    const bundleSize = Number(el.dataset.bundleSize) || 1;
    const pathEl = el.querySelector('path');
    if (pathEl) pathEl.setAttribute('d', nexusCurvePath(p, q, bundleIndex, bundleSize));
    const mid = bundleIndex - (bundleSize - 1) / 2;
    const label = el.querySelector('.nexus-edge-label');
    if (label) {
      label.setAttribute('x', (p.x + q.x) / 2 + mid * 8);
      label.setAttribute('y', (p.y + q.y) / 2 - 12 - Math.abs(mid) * 4);
    }
  });
}
function nexusMoveLegacyNode(element, dx, dy) {
  const nodes = state.nexusGraphData?.graph?.nodes;
  const index = Number(element.dataset.nexusNode);
  if (!nodes?.[index]) return;
  const { width, height } = nexusViewBoxSize();
  const svg = $('#nexus-graph svg');
  const rect = svg.getBoundingClientRect();
  const scale = state.nexusGraphView.scale || 1;
  const sx = width / rect.width / scale, sy = height / rect.height / scale;
  const circle = element.querySelector('circle');
  const x = Number(circle.getAttribute('cx')) + dx * sx;
  const y = Number(circle.getAttribute('cy')) + dy * sy;
  circle.setAttribute('cx', x); circle.setAttribute('cy', y);
  element.querySelectorAll('text').forEach(text => {
    if (text.classList.contains('node-type')) { text.setAttribute('x', x); text.setAttribute('y', y - 4); }
    else if (text.classList.contains('node-label')) { text.setAttribute('x', x); text.setAttribute('y', y + 11); }
  });
  $('#nexus-graph').querySelectorAll('[data-nexus-edge]').forEach(link => {
    const edgeIndex = Number(link.dataset.nexusEdge);
    const line = link.querySelector('line');
    if (!line) return;
    if (index === 0) line.setAttribute('x1', x), line.setAttribute('y1', y);
    else if (edgeIndex === index - 1) line.setAttribute('x2', x), line.setAttribute('y2', y);
    const x1 = Number(line.getAttribute('x1')), y1 = Number(line.getAttribute('y1'));
    const x2 = Number(line.getAttribute('x2')), y2 = Number(line.getAttribute('y2'));
    const label = link.querySelector('text');
    if (label) { label.setAttribute('x', (x1 + x2) / 2); label.setAttribute('y', (y1 + y2) / 2 - 7); }
  });
}
function nexusMoveNode(element, dx, dy) {
  if (element.dataset.nexusNode != null) {
    nexusMoveLegacyNode(element, dx, dy);
    return;
  }
  const nodeId = element.dataset.nodeId;
  const r = Number(element.dataset.nodeR) || 22;
  if (!nodeId) return;
  const { width, height } = nexusViewBoxSize();
  const svg = $('#nexus-graph svg');
  const rect = svg.getBoundingClientRect();
  const scale = state.nexusGraphView.scale || 1;
  const sx = width / rect.width / scale, sy = height / rect.height / scale;
  const core = element.querySelector('.nexus-node-core');
  const pos = {
    x: Number(core?.getAttribute('cx') || state.nexusNodePositions?.[nodeId]?.x || 0),
    y: Number(core?.getAttribute('cy') || state.nexusNodePositions?.[nodeId]?.y || 0),
  };
  pos.x += dx * sx; pos.y += dy * sy;
  if (!state.nexusNodePositions) state.nexusNodePositions = {};
  state.nexusNodePositions[nodeId] = pos;
  nexusSetNodeCoords(element, pos.x, pos.y, r);
  nexusUpdateConnectedEdges(nodeId);
}
async function nexusExpandSelectedNode(node) {
  const entityId = nexusEntityIdFromNode(node);
  if (!entityId) {
    setNexusStatus('This record has no expandable graph entity — select a FIR-linked wallet or person.');
    return;
  }
  if (state.demo) {
    setNexusStatus('Switch to Live API mode to expand the graph from this node.');
    return;
  }
  await openNexusEntity(entityId, node.display_value || node.type || 'Expanded graph');
}
function renderNexusNetworkGraph(graph, root = {}) {
  const nodes = graph.nodes || [], edges = graph.edges || [];
  const byId = new Map(nodes.map((node, index) => [node.id, index]));
  const rootIndex = Math.max(0, nodes.findIndex(node => node.id === graph.root_id));
  const rootKey = graph.root_id || nodes[rootIndex]?.id;
  const layout = nexusTreeLayout(nodes, edges, graph.root_id);
  let { positions, width, height, treeEdges, componentCount, hiddenEdgeCount } = layout;
  state.nexusVisibleTreeEdgeIndexes = new Set(treeEdges.map(item => item.originalIndex));
  state.nexusGraphSize = { width, height };
  const prior = state.nexusNodePositions || {};
  const priorIds = new Set(Object.keys(prior));
  const sameNodeSet = nodes.length === priorIds.size && nodes.every(node => priorIds.has(node.id));
  if (sameNodeSet) {
    positions = positions.map((point, index) => (prior[nodes[index].id] ? { ...prior[nodes[index].id] } : point));
    nexusResolveCollisions(positions, nodes, width, height, rootKey);
  }
  state.nexusNodePositions = Object.fromEntries(nodes.map((node, index) => [node.id, { ...positions[index] }]));
  const edgeBundles = new Map();
  treeEdges.forEach(({ edge, originalIndex }) => {
    const key = `${edge.source}\0${edge.target}`;
    const bucket = edgeBundles.get(key) || [];
    bucket.push(originalIndex);
    edgeBundles.set(key, bucket);
  });
  const edgeMarkup = treeEdges.map(({ edge, originalIndex }) => {
    const a = byId.get(edge.source), b = byId.get(edge.target);
    if (a == null || b == null) return '';
    const p = positions[a], q = positions[b];
    const bundleKey = `${edge.source}\0${edge.target}`;
    const bundle = edgeBundles.get(bundleKey) || [originalIndex];
    const bundleIndex = bundle.indexOf(originalIndex);
    const path = nexusCurvePath(p, q, bundleIndex, bundle.length);
    const ledger = nexusIsMoneyEdge(edge);
    const allegation = nexusIsAllegationEdge(edge);
    const label = ledger
      ? String(edge.relationship_type || edge.metadata?.amount || 'transfer').slice(0, 22)
      : String(edge.relationship_type || 'link').replaceAll('_', ' ').slice(0, 20);
    const mid = bundleIndex - (bundle.length - 1) / 2;
    const lx = (p.x + q.x) / 2 + mid * 8, ly = (p.y + q.y) / 2 - 12 - Math.abs(mid) * 4;
    const marker = ledger ? 'nexus-arrow-ledger' : allegation ? 'nexus-arrow-fir' : 'nexus-arrow-meta';
    return `<g class="nexus-link ${ledger ? 'is-ledger' : ''} ${allegation ? 'is-allegation' : ''}" data-network-edge="${originalIndex}" data-bundle-index="${bundleIndex}" data-bundle-size="${bundle.length}" tabindex="0" role="button">
      <path d="${path}" marker-end="url(#${marker})"/>
      <text class="nexus-edge-label" x="${lx}" y="${ly}">${escapeHtml(label)}</text>
    </g>`;
  }).join('');
  const hubCounts = new Map();
  edges.filter(nexusIsMoneyEdge).forEach(edge => {
    hubCounts.set(edge.target, (hubCounts.get(edge.target) || 0) + 1);
    hubCounts.set(edge.source, (hubCounts.get(edge.source) || 0) + 1);
  });
  const nodeMarkup = nodes.map((node, index) => {
    const p = positions[index];
    const label = String(node.display_value || node.type || 'Record');
    const kind = String(node.type || 'record').replace(/[^a-z0-9_-]/gi, '-');
    const isRoot = index === rootIndex;
    const isWallet = kind === 'wallet' || kind === 'account';
    const degree = hubCounts.get(node.id) || 0;
    const isHub = isWallet && degree >= 3;
    const r = isRoot ? 28 : isHub ? 26 : isWallet ? 22 : 19;
    const inner = isWallet ? nexusWalletGlyph(p.x, p.y, r * 0.72) : '';
    const hubBadge = isHub
      ? `<g class="nexus-hub-badge" transform="translate(${p.x + r + 2},${p.y - r - 22})" data-hub-node="${index}" role="button" tabindex="0">
        <rect x="0" y="0" width="72" height="28" rx="8"/>
        <text class="nexus-hub-count" x="36" y="12">${degree}</text>
        <text class="nexus-hub-hint" x="36" y="23">flows · dbl-click expand</text>
      </g>` : '';
    const tooltip = `${label} · ${node.type || 'record'} · ${String(node.source || 'graph').toUpperCase()}`;
    return `<g class="nexus-node nexus-kind-${escapeHtml(kind)} ${isRoot ? 'root is-focus' : ''}" data-network-node="${index}" data-node-id="${escapeHtml(node.id)}" data-node-r="${r}" tabindex="0" role="button" aria-label="${escapeHtml(tooltip)}">
      <title>${escapeHtml(tooltip)}</title>
      <circle class="nexus-node-halo" cx="${p.x}" cy="${p.y}" r="${r + 7}"/>
      <circle class="nexus-node-core" cx="${p.x}" cy="${p.y}" r="${r}"/>
      ${inner}
      <text class="node-label" x="${p.x}" y="${p.y + r + 16}">${escapeHtml(label.slice(0, 28))}</text>
      ${hubBadge}
    </g>`;
  }).join('');
  state.nexusGraphView = { scale: 1, x: 0, y: 0 };
  state.nexusSelectedNodeId = graph.root_id || nodes[rootIndex]?.id || null;
  $('#nexus-graph').classList.add('nexus-graph-canvas');
  $('#nexus-graph').innerHTML = `<svg viewBox="0 0 ${width} ${height}" style="width:${width}px;height:${height}px" class="nexus-flow-svg" role="img" aria-label="Money flow investigation graph">
    <defs>
      <marker id="nexus-arrow-ledger" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" class="nexus-marker-ledger"/></marker>
      <marker id="nexus-arrow-fir" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" class="nexus-marker-fir"/></marker>
      <marker id="nexus-arrow-meta" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" class="nexus-marker-meta"/></marker>
    </defs>
    <g class="nexus-scene">${edgeMarkup}${nodeMarkup}</g>
  </svg>`;
  applyNexusGraphView();
  $('#nexus-workspace-title').textContent = root.display_value || 'FIR investigation network';
  $('#nexus-graph').querySelectorAll('[data-network-node]').forEach(element => {
    const node = nodes[Number(element.dataset.networkNode)];
    const select = async () => {
      if (nexusSuppressClick) { nexusSuppressClick = false; return; }
      $('#nexus-graph').querySelectorAll('.nexus-node.is-focus').forEach(n => n.classList.remove('is-focus'));
      element.classList.add('is-focus');
      state.nexusSelectedNodeId = node.id;
      nexusApplyGraphHighlight(node.id);
      const expandId = nexusEntityIdFromNode(node);
      const detailActions = expandId ? [{ entityId: expandId, label: 'Expand graph from this node' }] : [];
      await showNexusGraphNodeDetails(node, detailActions);
      const { source } = nexusNodeSourceMeta(node);
      setNexusStatus(`${source.toUpperCase()} ${node.type} selected · drag to reposition · double-click connected FIR entity to expand.`);
    };
    element.addEventListener('click', select);
    element.addEventListener('dblclick', event => { event.preventDefault(); nexusExpandSelectedNode(node); });
    element.addEventListener('mouseenter', () => { if (!nexusPointer) nexusApplyGraphHighlight(node.id); });
    element.addEventListener('mouseleave', () => { if (!nexusPointer) nexusApplyGraphHighlight(state.nexusSelectedNodeId); });
    element.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); } });
  });
  $('#nexus-graph').querySelectorAll('.nexus-hub-badge').forEach(badge => {
    const index = Number(badge.dataset.hubNode);
    const nodeEl = $('#nexus-graph').querySelector(`[data-network-node="${index}"]`);
    const focusHub = event => {
      event.stopPropagation();
      nodeEl?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    };
    badge.addEventListener('click', focusHub);
    badge.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); focusHub(event); }
    });
  });
  $('#nexus-graph').querySelectorAll('[data-network-edge]').forEach(element => {
    const edge = edges[Number(element.dataset.networkEdge)];
    const inspect = async () => {
      nexusApplyGraphHighlight(edge.source);
      setNexusSelectedEvidence({ evidence_type: 'other', source: 'nexus_graph', value: edge.source_record_id || null,
        details: { source_record_id: edge.source_record_id || null, source_table: edge.source_table || null,
          relationship_type: edge.relationship_type, verification_status: edge.verification_status,
          source_system: edge.source_repository || null, confidence: edge.confidence } });
      const edgeTitle = String(edge.relationship_type || 'Relationship').replaceAll('_', ' ');
      const edgeRows = [
        ['From', nodes[byId.get(edge.source)]?.display_value], ['To', nodes[byId.get(edge.target)]?.display_value],
        ['Evidence status', edge.verification_status], ['Source repository', edge.source_repository], ['Source table', edge.source_table],
        ['Source record ID', edge.source_record_id], ['Confidence', edge.confidence == null ? '—' : `${Math.round(edge.confidence * 100)}%`],
        ['Metadata', JSON.stringify(edge.metadata || {})],
      ];
      renderNexusDetails(edgeTitle, edgeRows);
      if (state.demo || !edge.source_table || !edge.source_record_id) return;
      try {
        const record = await apiRequest(
          `/intelligence/layers/records/detail?source_table=${encodeURIComponent(edge.source_table)}&source_record_id=${encodeURIComponent(edge.source_record_id)}`,
        );
        renderNexusDetails(`${edgeTitle} · ${record.origin_repository || record.source || ''}`.toUpperCase(),
          [...edgeRows, ['— linkage —', record.label || '—'], ...nexusDetailRowsFromRecord(record, [])]);
      } catch { /* keep relationship rows only */ }
    };
    element.addEventListener('click', inspect);
    element.addEventListener('mouseenter', () => { if (!nexusPointer) nexusApplyGraphHighlight(edge.source); });
    element.addEventListener('mouseleave', () => { if (!nexusPointer) nexusApplyGraphHighlight(state.nexusSelectedNodeId); });
    element.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); inspect(); } });
  });
  nexusApplyGraphHighlight(state.nexusSelectedNodeId);
  const rootNode = nodes[rootIndex];
  if (rootNode) {
    const expandId = nexusEntityIdFromNode(rootNode);
    const detailActions = expandId ? [{ entityId: expandId, label: 'Expand graph from this node' }] : [];
    void showNexusGraphNodeDetails(rootNode, detailActions);
    $('#nexus-graph').querySelector(`[data-network-node="${rootIndex}"]`)?.classList.add('is-focus');
  }
  setNexusStatus(`${nodes.length} records · ${treeEdges.length} tree links shown · ${hiddenEdgeCount} additional links retained but hidden to keep this view acyclic · ${componentCount} connected component(s).`);
}
async function openNexusEntity(entityId, title = 'Selected entity', options = {}) {
  if (!entityId) return setNexusStatus('This record is not linked to a graph entity yet.');
  if (!options.fromHistory) state.nexusNodePositions = null;
  if (!options.fromHistory && state.nexusGraphHistory.at(-1) !== entityId) state.nexusGraphHistory.push(entityId);
  $('#nexus-back-entity').disabled = state.nexusGraphHistory.length < 2;
  state.nexusEntityId = entityId;
  $('#nexus-workspace-kicker').textContent = 'Investigation graph';
  setNexusStatus('Loading entity profile and relationships…');
  try {
    const profile = await apiRequest(`/intelligence/layers/entities/${encodeURIComponent(entityId)}`);
    const ledgerTypes = new Set(['wallet', 'account', 'organization']);
    const entityType = String(profile.entity?.type || '').toLowerCase();
    const graph = ledgerTypes.has(entityType)
      ? await apiRequest(`/intelligence/layers/entities/${encodeURIComponent(entityId)}/ledger?depth=2&limit=250`)
      : await apiRequest(`/intelligence/layers/entities/${encodeURIComponent(entityId)}/graph`);
    if (!state.nexusIntakeContext || state.nexusIntakeContext.entity_id !== entityId) {
      state.nexusIntakeContext = { source_system: 'graph', entity_id: entityId,
        intake_type: nexusIntakeType(profile.entity?.type), label: title || profile.entity?.display_value || profile.entity?.type };
    }
    renderNexusGraph(graph, { ...profile.entity, ...profile.profile, entity_id: entityId });
    setNexusSelectedEvidence(evidenceForEntity({ id: entityId,
      type: profile.entity?.type, display_value: profile.entity?.display_value }));
    renderNexusDetails(title, [['Entity type', profile.entity?.type], ['Risk level', profile.profile?.risk_level || 'Not assessed'], ['Risk score', profile.profile?.risk_score == null ? '—' : `${Math.round(Number(profile.profile.risk_score) * 100)}%`], ['Confidence', profile.profile?.risk_confidence == null ? '—' : `${Math.round(Number(profile.profile.risk_confidence) * 100)}%`], ['Linked entities', profile.profile?.linked_entity_count ?? graph.edges?.length ?? 0], ['Activity', profile.profile?.activity_summary || 'No activity summary available'], ['Risk reasons', (profile.profile?.risk_reasons || []).join('; ') || 'None recorded']]);
    await loadNexusCollection(entityId);
  } catch (error) { nexusEmpty('Could not load this graph', error.message); setNexusStatus(error.message); }
}
async function goBackNexusGraph() {
  if (state.nexusGraphHistory.length < 2) return;
  state.nexusGraphHistory.pop();
  const previous = state.nexusGraphHistory.at(-1);
  $('#nexus-back-entity').disabled = state.nexusGraphHistory.length < 2;
  await openNexusEntity(previous, 'Previous graph', { fromHistory: true });
}
async function searchNexus() {
  const query = $('#nexus-search').value.trim();
  if (!query) return setNexusStatus('Enter a phone number, account, wallet, or identity to search.');
  if (state.demo) return setNexusStatus('Switch to Live API mode and sign in as a reviewer or administrator to search FIR/PDR intelligence.');
  setNexusSelectedEvidence(null);
  state.nexusReportId = null;
  state.nexusGraphHistory = [];
  state.nexusNodePositions = null;
  $('#nexus-back-entity').disabled = true;
  $('#nexus-extract-match').hidden = true;
  clearNexusCollection('Select a search match to collect its connected FIR/PDR records.');
  const kind = $('#nexus-search-kind')?.value || 'all';
  setNexusStatus('Searching FIR entities, reports, and exact protected PDR records…');
  try {
    const result = await apiRequest(`/intelligence/layers/search?query=${encodeURIComponent(query)}&kind=${encodeURIComponent(kind)}`);
    const items = result.items || [];
    $('#nexus-workspace-kicker').textContent = 'FIR + PDR search';
    $('#nexus-workspace-title').textContent = `${result.count || 0} matching record(s)`;
    $('#nexus-list').innerHTML = items.length ? items.map((item, index) => `<button class="nexus-result" data-search-result="${index}"><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.source.toUpperCase())} · ${escapeHtml(item.matched_field)} · ${escapeHtml(item.summary)}</span></button>`).join('') : '<p class="helper">No matching records. Try a different term or search type.</p>';
    $('#nexus-list').querySelectorAll('[data-search-result]').forEach(button => button.addEventListener('click', async () => {
        const item = items[Number(button.dataset.searchResult)];
        if (item.kind === 'report') {
          await selectNexusReport(item.record_id, item.title);
          return;
        }
        if (item.source === 'pdr') {
        state.nexusIntakeContext = { source_system: 'pdr', source_record_id: item.record_id,
          entity_id: item.entity_id || undefined, intake_type: item.kind === 'account' && /momo|wallet/i.test(item.account_type || '') ? 'wallet' : item.kind === 'identity' && item.matched_field === 'phone number' ? 'phone' : item.kind,
          label: item.title, summary: item.summary };
        const details = [['Matched field', item.matched_field], ['Partner', item.partner], ['Record type', item.kind], ['Summary', item.summary]];
        if (item.verification_status) details.push(['Verification', item.verification_status], ['Verified ownership', item.verified_ownership ? 'Yes' : 'No']);
        if (item.account_type) details.push(['Account type', item.account_type], ['Account status', item.account_status], ['Service provider', item.service_provider]);
        if (item.kind === 'transaction') details.push(['Amount', `${item.amount} ${item.currency}`], ['Status', item.transaction_status], ['Timestamp', item.timestamp]);
        $('#nexus-workspace-kicker').textContent = `${item.kind} match`;
        if (item.entity_id) await openNexusEntity(item.entity_id, item.title);
        else nexusEmpty('No linked graph entity', 'This PDR record matched, but its account references have not been resolved into graph nodes yet.');
        const pdrEvidenceType = item.kind === 'transaction' ? 'transaction' : item.kind === 'identity' && item.matched_field === 'phone number' ? 'phone_number' : item.kind === 'identity' ? 'identity' : 'other';
        setNexusSelectedEvidence({ evidence_type: pdrEvidenceType, source: 'nexus_pdr', value: item.record_id,
          details: { source_record_id: item.record_id, intake_type: item.kind, entity_id: item.entity_id || null,
            partner: item.partner, matched_field: item.matched_field } });
        renderNexusDetails(item.title, details);
        setNexusStatus(item.entity_id ? `${item.title} · connected graph loaded.` : `${item.title} · matched in PDR; no graph node is linked yet.`);
        } else {
          state.nexusIntakeContext = { source_system: 'graph', entity_id: item.entity_id,
            intake_type: nexusIntakeType(item.entity_type), label: item.title,
            summary: item.summary };
          $('#nexus-extract-match').hidden = true;
          await openNexusEntity(item.entity_id, item.title);
        }
      }));
    nexusEmpty(items.length ? 'Choose a search match' : 'No matching intelligence', items.length
      ? 'Select a result to inspect its graph, related intelligence, or report details.'
      : 'Try a different term or select another search type.');
    renderNexusDetails('Select a match');
    setNexusStatus(`${items.length} FIR entity, report, or exact PDR match(es) found.`);
  } catch (error) { nexusEmpty('Search failed', error.message); renderNexusDetails('No selection'); setNexusStatus(`Search failed: ${error.message}`); }
}
async function loadNexusTab(tab) {
  $$('.nexus-nav-item').forEach(button => button.classList.toggle('active', button.dataset.nexusTab === tab));
  setNexusSelectedEvidence(null);
  state.nexusReportId = null;
  state.nexusIntakeContext = null;
  $('#nexus-extract-match').hidden = true;
  if (tab !== 'graph') clearNexusCollection('Select a graph entity to collect its connected FIR/PDR records.');
  if (tab === 'graph') {
    $('#nexus-workspace-kicker').textContent = 'Investigation graph';
    if (!state.nexusEntityId) { nexusEmpty('Start with an indicator', 'Search a reported phone, account, wallet, or identity to build its connected graph.'); setNexusStatus(state.demo ? 'Switch to Live API mode and sign in to access FIR/PDR investigations.' : 'Search uses active community intelligence and then loads its FIR/PDR graph.'); }
    else await openNexusEntity(state.nexusEntityId);
    $('#nexus-workspace-title').textContent = state.nexusEntityId ? 'Entity graph' : 'Start with an indicator';
    $('#nexus-list').innerHTML = '<p class="helper">Search an indicator or choose an entity from Entities.</p>';
    return;
  }
  if (state.demo) { $('#nexus-list').innerHTML = '<p class="helper">Switch to Live API mode and sign in to load investigation records.</p>'; nexusEmpty('Live data required', 'NEXUS displays persisted FIR/PDR records from the authenticated API.'); return; }
  $('#nexus-workspace-kicker').textContent = tab === 'entities' ? 'Entity index' : tab === 'reports' ? 'Report queue' : 'Investigation cases';
  $('#nexus-workspace-title').textContent = tab === 'entities' ? 'Highest risk entities' : tab === 'reports' ? 'Recent reports' : 'Investigation cases';
  setNexusStatus('Loading records…');
  try {
    let items = [];
    if (tab === 'entities') items = (await apiRequest('/admin/intelligence')).top_entities || [];
    if (tab === 'reports') items = (await apiRequest('/fir/reports?limit=50&offset=0')).items || [];
    if (tab === 'investigations') items = await apiRequest('/cases?limit=50&offset=0') || [];
    $('#nexus-list').innerHTML = items.length ? items.map((item, index) => {
      const id = item.entity_id || item.id;
      const label = item.display_value || item.subject || item.title || `Case ${String(id).slice(0, 8)}`;
      const detail = item.risk_level || item.status || item.report_type || 'Investigation';
      return `<button class="nexus-result" data-nexus-result="${escapeHtml(id)}" data-nexus-result-kind="${tab}" data-nexus-result-index="${index}"><b>${escapeHtml(label)}</b><span>${escapeHtml(detail)}</span></button>`;
    }).join('') : '<p class="helper">No records found.</p>';
    $('#nexus-list').querySelectorAll('[data-nexus-result]').forEach(button => button.addEventListener('click', async () => {
      const item = items[Number(button.dataset.nexusResultIndex)];
      if (tab === 'entities') {
        $('#nexus-extract-match').hidden = true;
        const type = nexusIntakeType(item.type);
        state.nexusIntakeContext = { source_system: 'graph', entity_id: item.id, intake_type: type,
          label: item.display_value || item.type, summary: `${item.risk_level || 'unassessed'} entity selected from the risk index.` };
        openNexusEntity(item.id, item.display_value || item.type);
      } else if (tab === 'reports') {
        await selectNexusReport(item.id, item.subject || item.report_type || 'FIR report');
      } else {
        $('#nexus-extract-match').hidden = true;
        try {
          const detail = await apiRequest(`/cases/${encodeURIComponent(item.id)}`);
          await activateNexusCase(detail.id, detail);
          const intake = detail.evidence?.find(evidence => evidence.details?.intake_type);
          const entityId = intake?.details?.entity_id;
          if (entityId) await openNexusEntity(entityId, item.title);
          else nexusEmpty('No linked graph yet', 'This investigation has no starting graph entity attached.');
          const evidenceRows = (detail.evidence || []).map(evidence => [
            `Starting evidence · ${evidence.details?.intake_type || evidence.evidence_type}`,
            `${evidence.source} · ${evidence.details?.source_record_id || 'protected reference'}`,
          ]);
          renderNexusDetails(detail.title || 'Investigation', [
            ['Status', detail.status || '—'], ['Case ID', detail.id],
            ['Summary', detail.summary || 'No case summary available'], ...evidenceRows,
          ]);
          setNexusStatus(`${(detail.evidence || []).length} evidence item(s) attached to this investigation.`);
        } catch (error) {
          renderNexusDetails(item.title || 'Investigation', [['Status', item.status || '—'], ['Case ID', item.id], ['Summary', item.summary || 'No case summary available']]);
          nexusEmpty('Could not load investigation', error.message);
        }
      }
    }));
    setNexusStatus(`${items.length} ${tab} record(s) loaded from the API.`);
    nexusEmpty(tab === 'entities' ? 'Choose an entity' : tab === 'reports' ? 'Choose a report' : 'Choose an investigation', 'Select a record from the left panel to inspect its graph or details.');
  } catch (error) { $('#nexus-list').innerHTML = `<p class="helper">${escapeHtml(error.message)}</p>`; nexusEmpty('Could not load records', error.message); setNexusStatus(error.message); }
}

$$('.nav-tab').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
$$('.admin-nav-link[data-admin-target]').forEach(button => button.addEventListener('click', () => navigateAdmin(button.dataset.adminTarget)));
$$('[data-smart-action]').forEach(button => button.addEventListener('click', () => {
  const action = button.dataset.smartAction;
  if (action === 'sms') { $('#smart-message').focus(); $('#smart-message').scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  if (action === 'phone') { $('#smart-number').focus(); $('#smart-number').scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  if (action === 'report') { $('#smart-report-message').focus(); $('#smart-report-message').scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  if (action === 'reports') { $('#smart-reports-panel').scrollIntoView({ behavior: 'smooth', block: 'center' }); loadSmartReports(); }
}));
$('#request-otp').addEventListener('click', requestOtp); $('#verify-otp').addEventListener('click', verifyOtp);
$('#open-settings').addEventListener('click', openSettings); $('#open-settings-top').addEventListener('click', openSettings); $('#save-settings').addEventListener('click', saveSettings); $('#smart-analyze').addEventListener('click', analyzeSmartMessage); $('#smart-number-lookup').addEventListener('click', checkSmartNumber); $('#smart-report').addEventListener('click', submitSmartReport); $('#smart-reports-refresh').addEventListener('click', loadSmartReports); $('#lite-send').addEventListener('click', liteSend); $('#lite-mic').addEventListener('click', toggleLiteVoiceRecording); $('#lite-reset').addEventListener('click', () => { state.gatewayCaseId = ''; localStorage.removeItem('safeguard.gatewayCaseId'); liteMenu(); logGateway('READY', 'Session reset. A new shared gateway case will be created on the next assessment.'); }); $('#admin-refresh').addEventListener('click', loadAdminDashboard); $('#refresh-intelligence').addEventListener('click', () => Promise.all([loadAdminIntelligence(), loadAdminMonitoring()])); $('#seed-intelligence-demo').addEventListener('click', seedAdminIntelligenceDemo); $('#review-submit').addEventListener('click', submitReviewDecision);
$('#go-admin-reports')?.addEventListener('click', () => { navigateAdmin('admin-reports-section'); loadAdminReports(); });
$('#admin-reports-refresh')?.addEventListener('click', loadAdminReports);
$('#toggle-intelligence-trends')?.addEventListener('click', toggleIntelligenceTrends);
$('#analytics-tactic-period')?.addEventListener('change', () => renderMobileMoneyTactics(state.lastIntelligenceDashboard?.mobile_money_tactics || {}));
$('#admin-nav-nexus')?.addEventListener('click', () => switchView('nexus'));
$('#admin-nav-atlas')?.addEventListener('click', () => openAdminAtlasSearch());
$('#monitoring-open-nexus')?.addEventListener('click', () => switchView('nexus'));
$('#monitoring-open-atlas')?.addEventListener('click', () => openAdminAtlasSearch());
$('#monitoring-open-awareness')?.addEventListener('click', () => navigateAdmin('awareness-operations-panel'));
$('#awareness-deliveries-refresh')?.addEventListener('click', () => Promise.all([loadAwarenessDeliveries(), loadAwarenessOutreachStats()]));
$('#awareness-campaigns-refresh')?.addEventListener('click', () => Promise.all([loadAwarenessCampaigns(), loadAwarenessOperations()]));
$('#awareness-ops-refresh')?.addEventListener('click', loadAwarenessOperations);
$('#awareness-ops-run')?.addEventListener('click', runAwarenessSchedulerNow);
$('#admin-fraud-monitoring')?.addEventListener('click', event => {
  const nexusBtn = event.target.closest('[data-open-nexus]');
  if (nexusBtn) { event.preventDefault(); openAdminNexus(nexusBtn.dataset.openNexus, 'Monitoring entity'); return; }
  const atlasEntity = event.target.closest('[data-open-atlas-entity]');
  if (atlasEntity) { event.preventDefault(); openAdminAtlasSearch(atlasEntity.dataset.openAtlasEntity); return; }
  const atlasSignal = event.target.closest('[data-open-atlas-signal]');
  if (atlasSignal) { event.preventDefault(); openAdminAtlasSearch(atlasSignal.dataset.openAtlasSignal); }
});
$('#awareness-preferences-save').addEventListener('click', saveAwarenessPreferences); $('#awareness-inbox-refresh').addEventListener('click', loadAwarenessInbox);
$('#partner-create').addEventListener('click', createAdminPartner);
$('#partner-refresh').addEventListener('click', loadAdminPartners);
$('#open-nexus').addEventListener('click', () => switchView('nexus'));
$('#atlas-back').addEventListener('click', () => switchView('admin'));
$('#atlas-refresh').addEventListener('click', () => { atlasCatalog = null; loadAtlas(); });
$('#atlas-search-form').addEventListener('submit', event => { event.preventDefault(); loadAtlas(); });
$('#atlas-zoom-in').addEventListener('click', () => zoomAtlas(1.2));
$('#atlas-zoom-out').addEventListener('click', () => zoomAtlas(1 / 1.2));
$('#atlas-fit').addEventListener('click', () => { atlasView.scale = 1; atlasView.x = 0; atlasView.y = 0; updateAtlasView(); });
$('#atlas-graph').addEventListener('wheel', event => {
  if (!$('#atlas-scene')) return;
  event.preventDefault();
  zoomAtlas(event.deltaY < 0 ? 1.12 : 1 / 1.12);
}, { passive: false });
$('#atlas-graph').addEventListener('pointerdown', event => {
  if (event.button !== 0 || !$('#atlas-graph svg')) return;
  const node = event.target.closest('.atlas-node');
  atlasPointer = { kind: node ? 'node' : 'pan', element: node, x: event.clientX, y: event.clientY, moved: false };
  (node || $('#atlas-graph')).setPointerCapture(event.pointerId);
  if (!node) $('#atlas-graph').classList.add('is-panning');
});
$('#atlas-graph').addEventListener('pointermove', event => {
  if (!atlasPointer) return;
  const dx = event.clientX - atlasPointer.x, dy = event.clientY - atlasPointer.y;
  if (Math.abs(dx) + Math.abs(dy) > 2) atlasPointer.moved = true;
  if (atlasPointer.kind === 'node') moveAtlasNode(atlasPointer.element, dx, dy);
  else {
    const svg = $('#atlas-graph svg'), rect = svg.getBoundingClientRect();
    const screenX = dx * 1000 / rect.width, screenY = dy * 620 / rect.height;
    atlasView.x += screenX; atlasView.y += screenY; updateAtlasView();
  }
  atlasPointer.x = event.clientX; atlasPointer.y = event.clientY;
});
const finishAtlasPointer = () => {
  if (atlasPointer?.moved && atlasPointer.kind === 'node') atlasSuppressClick = true;
  atlasPointer = null; $('#atlas-graph').classList.remove('is-panning');
};
$('#atlas-graph').addEventListener('pointerup', finishAtlasPointer);
$('#atlas-graph').addEventListener('pointercancel', finishAtlasPointer);
$('#nexus-back').addEventListener('click', () => switchView('admin'));
$('#nexus-search-form').addEventListener('submit', event => { event.preventDefault(); searchNexus(); });
$('#nexus-start-investigation').addEventListener('click', () => openNexusIntake(state.nexusIntakeContext));
$('#nexus-extract-match').addEventListener('click', extractAndMatchNexusReport);
$('#nexus-intake-form').addEventListener('submit', createNexusInvestigation);
$('#nexus-intake-close').addEventListener('click', () => $('#nexus-intake-dialog').close());
$('#nexus-add-to-case').addEventListener('click', addSelectedNexusEvidence);
$('#nexus-clear-active-case').addEventListener('click', clearNexusActiveCase);
$$('.nexus-nav-item').forEach(button => button.addEventListener('click', () => loadNexusTab(button.dataset.nexusTab)));
$$('.nexus-collection-tabs button').forEach(button => button.addEventListener('click', () => renderNexusCollectionTab(button.dataset.collectionTab)));
$('#nexus-referral-form').addEventListener('submit', createNexusReferral);
document.addEventListener('click', handleReferralAction);
$('#nexus-back-entity').addEventListener('click', goBackNexusGraph);
function applyNexusGraphView() {
  const scene = $('#nexus-graph .nexus-scene');
  if (scene) scene.setAttribute('transform', `translate(${state.nexusGraphView.x} ${state.nexusGraphView.y}) scale(${state.nexusGraphView.scale})`);
  const zoomLabel = $('#nexus-zoom-level');
  if (zoomLabel) zoomLabel.textContent = `${Math.round(state.nexusGraphView.scale * 100)}%`;
}
function zoomNexusGraph(factor, focus = null) {
  const { width, height } = nexusViewBoxSize();
  if (!focus) focus = { x: width / 2, y: height / 2 };
  const view = state.nexusGraphView;
  const scale = Math.max(0.5, Math.min(3, view.scale * factor));
  const actualFactor = scale / view.scale;
  view.x = focus.x - (focus.x - view.x) * actualFactor;
  view.y = focus.y - (focus.y - view.y) * actualFactor;
  view.scale = scale;
  applyNexusGraphView();
}
function resetNexusGraphView() {
  state.nexusGraphView = { scale: 1, x: 0, y: 0 };
  applyNexusGraphView();
  const svg = $('#nexus-graph svg');
  if (svg) { svg.classList.remove('nexus-fit'); void svg.getBoundingClientRect(); svg.classList.add('nexus-fit'); }
}
$('#nexus-zoom-in').addEventListener('click', () => zoomNexusGraph(1.2));
$('#nexus-zoom-out').addEventListener('click', () => zoomNexusGraph(1 / 1.2));
$('#nexus-fit-graph').addEventListener('click', resetNexusGraphView);
let nexusPointer = null;
let nexusSuppressClick = false;
$('#nexus-graph').addEventListener('wheel', event => {
  if (!$('#nexus-graph svg') || (!event.ctrlKey && !event.metaKey)) return;
  event.preventDefault();
  const rect = $('#nexus-graph svg').getBoundingClientRect();
  const { width, height } = nexusViewBoxSize();
  zoomNexusGraph(event.deltaY < 0 ? 1.12 : 1 / 1.12, {
    x: (event.clientX - rect.left) * width / rect.width,
    y: (event.clientY - rect.top) * height / rect.height,
  });
}, { passive: false });
$('#nexus-graph').addEventListener('pointerdown', event => {
  const svg = $('#nexus-graph svg');
  if (!svg || event.button !== 0) return;
  if (event.target.closest('.nexus-hub-badge')) return;
  const node = event.target.closest('.nexus-node');
  const link = !node && event.target.closest('.nexus-link, [data-nexus-edge]');
  if (link) return;
  nexusPointer = {
    kind: node ? 'node' : 'pan',
    element: node,
    x: event.clientX,
    y: event.clientY,
    moved: false,
    startX: state.nexusGraphView.x,
    startY: state.nexusGraphView.y,
    panX: event.clientX,
    panY: event.clientY,
  };
  (node || $('#nexus-graph')).setPointerCapture(event.pointerId);
  if (!node) $('#nexus-graph').classList.add('is-panning');
});
$('#nexus-graph').addEventListener('pointermove', event => {
  if (!nexusPointer) return;
  const dx = event.clientX - nexusPointer.x, dy = event.clientY - nexusPointer.y;
  if (Math.abs(dx) + Math.abs(dy) > 2) nexusPointer.moved = true;
  if (nexusPointer.kind === 'node') nexusMoveNode(nexusPointer.element, dx, dy);
  else {
    const rect = $('#nexus-graph svg').getBoundingClientRect();
    const { width, height } = nexusViewBoxSize();
    state.nexusGraphView.x = nexusPointer.startX + (event.clientX - nexusPointer.panX) * width / rect.width;
    state.nexusGraphView.y = nexusPointer.startY + (event.clientY - nexusPointer.panY) * height / rect.height;
    applyNexusGraphView();
  }
  nexusPointer.x = event.clientX;
  nexusPointer.y = event.clientY;
});
const endNexusPointer = () => {
  if (nexusPointer?.moved && nexusPointer.kind === 'node') nexusSuppressClick = true;
  nexusPointer = null;
  $('#nexus-graph').classList.remove('is-panning');
};
$('#nexus-graph').addEventListener('pointerup', endNexusPointer);
$('#nexus-graph').addEventListener('pointercancel', endNexusPointer);
$('#partner-secret-copy').addEventListener('click', async () => {
  const secret = $('#partner-secret-value').textContent;
  try { await navigator.clipboard.writeText(secret); $('#partner-secret-copy').textContent = 'Copied'; }
  catch { $('#partner-create-status').textContent = 'Clipboard access is unavailable. Select and copy the secret above.'; }
});
document.addEventListener('click', event => { const ussdButton = event.target.closest('[data-ussd]'); const action = ussdButton?.dataset.ussd; if (action) action === 'menu' ? (state.liteStep = 'menu', liteMenu()) : liteAction(action, ussdButton.dataset.value || ''); const reportButton = event.target.closest('[data-report-action]'); if (reportButton) openReviewDialog(reportButton.dataset.reportId || null, 'Review report'); const partnerButton = event.target.closest('[data-partner-id]'); if (partnerButton) setPartnerStatus(partnerButton.dataset.partnerId, partnerButton.dataset.partnerStatus); const campaignButton = event.target.closest('[data-campaign-send]'); if (campaignButton) sendAwarenessCampaign(campaignButton.dataset.campaignSend, campaignButton.dataset.campaignScheduled === 'true'); const readButton = event.target.closest('[data-awareness-read]'); if (readButton) markAwarenessRead(readButton.dataset.awarenessRead); });
setModeLabel(); liteMenu(); loadIntelligenceCapabilities(); loadAwarenessPreferences();
