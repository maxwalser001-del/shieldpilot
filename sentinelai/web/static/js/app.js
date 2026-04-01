/**
 * ShieldPilot Dashboard - Main SPA Application
 * Vanilla JS ES module. Hash-based router, JWT auth, API client.
 */

import {
    escapeHtml,
    relativeTimeString,
    scoreLevel,
    truncate,
    Badge,
    ScoreBadge,
    SeverityBadge,
    TypeBadge,
    StatCard,
    DataTable,
    RelativeTime,
    CommandText,
    SignalList,
    ForensicsPanel,
    ThreatList,
    IncidentCard,
    ActivityItem,
    ActivityFilterBar,
    Pagination,
    CommandFilterBar,
    EmptyState,
    Spinner,
    showToast,
    showModal,
    showPaywallModal,
    RiskDistributionChart,
    TimelineChart,
    ScoreHistogramChart,
    InjectionTimelineChart,
    DailyCommandsChart,
    HealthComponent,
    HealthProgressBar,
    SparklineChart,
    BlockRateGauge,
    TopBlockedTable,
    ScoreDistributionBars,
    DonutChart,
    CommandsLineChart,
    RiskScoreBarChart,
    ExportDropdown,
    SecurityStatusBar,
    OpsCard,
    OpsScoreCard,
    ThreatTimelineChart,
    ThreatTypesList,
    PeriodSelector,
    LiveIndicator,
    CCHeader,
    ValueBanner,
    TrustBar,
    ProFeatureLock,
    UpgradeCTACard,
    ScanScoreCircle,
    ScanResultDisplay,
    ScanStatsBar,
    ScanStatusBadge,
    ScanEmptyState,
    mountPendingCharts,
    destroyAllCharts,
} from './components.js?v=12';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TOKEN_KEY = 'sentinel_token';
const LOGIN_PATH = '/login';
const DEFAULT_HASH = '#/dashboard';

// Local-first mode: localhost connections skip auth (set by /api/auth/mode check)
let _localFirstMode = false;

/**
 * Safely format a Unix timestamp (seconds) to a locale date string.
 * Returns fallback string when the timestamp is null, undefined, or 0.
 */
function formatPeriodDate(ts, fallback = 'N/A') {
    if (!ts || typeof ts !== 'number') return fallback;
    return new Date(ts * 1000).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
}

// Global usage cache (refreshed periodically)
let usageCache = null;

// ---------------------------------------------------------------------------
// JWT Helpers
// ---------------------------------------------------------------------------

function getToken() {
    return localStorage.getItem(TOKEN_KEY);
}

function clearToken() {
    localStorage.removeItem(TOKEN_KEY);
}

/**
 * Decode the payload of a JWT (no verification -- that is the server's job).
 * Returns null if the token is malformed.
 */
function decodeJwtPayload(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        return payload;
    } catch {
        return null;
    }
}

/**
 * Returns true if the stored JWT exists and is not expired, or local-first mode is active.
 */
function isAuthenticated() {
    if (_localFirstMode) return true;
    const token = getToken();
    if (!token) return false;
    const payload = decodeJwtPayload(token);
    if (!payload || !payload.exp) return false;
    return payload.exp * 1000 > Date.now();
}

function requireAuth() {
    if (_localFirstMode) return true;
    if (!isAuthenticated()) {
        clearToken();
        window.location.href = LOGIN_PATH;
        return false;
    }
    return true;
}

/**
 * Check /api/auth/mode to detect local-first mode (no auth needed on localhost).
 * Called once at SPA startup before routing.
 */
async function checkLocalFirstMode() {
    try {
        const resp = await fetch('/api/auth/mode');
        if (resp.ok) {
            const data = await resp.json();
            _localFirstMode = data.local_first === true;
        }
    } catch { /* ignore — server not reachable, fall back to normal auth */ }
}

// ---------------------------------------------------------------------------
// API Client
// ---------------------------------------------------------------------------

/**
 * Make an authenticated API request.
 * @param {string} path   e.g. "/api/stats"
 * @param {Object} options  fetch options (method, body, params, etc.)
 * @returns {Promise<any>} parsed JSON
 */
async function api(path, options = {}) {
    const token = getToken();
    const headers = { ...(options.headers || {}) };
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const method = (options.method || 'GET').toUpperCase();
    if (method === 'POST' || method === 'PATCH' || method === 'PUT') {
        headers['Content-Type'] = 'application/json';
    }

    const fetchOpts = {
        method,
        headers,
    };

    if (options.body !== undefined) {
        fetchOpts.body = typeof options.body === 'string'
            ? options.body
            : JSON.stringify(options.body);
    }

    // Build URL with query params
    let url = path;
    if (options.params) {
        const qs = new URLSearchParams();
        for (const [k, v] of Object.entries(options.params)) {
            if (v !== null && v !== undefined && v !== '') {
                qs.append(k, v);
            }
        }
        const qsStr = qs.toString();
        if (qsStr) url += `?${qsStr}`;
    }

    try {
        const resp = await fetch(url, fetchOpts);

        if (resp.status === 401) {
            // If user had a token (now expired), clear it and redirect to login
            // even in local-first mode — expired tokens must be refreshed via login
            if (getToken()) {
                clearToken();
                window.location.href = LOGIN_PATH;
                return null;
            }
            // No token + local-first: let the error pass through (shouldn't happen
            // since backend returns local-admin for tokenless localhost requests)
            if (_localFirstMode) return null;
            window.location.href = LOGIN_PATH;
            return null;
        }

        if (!resp.ok) {
            const errBody = await resp.text();
            let errMsg;
            try {
                const errJson = JSON.parse(errBody);
                const detail = errJson.detail;
                if (typeof detail === 'string') {
                    errMsg = detail;
                } else if (detail && typeof detail === 'object') {
                    errMsg = detail.message || detail.error || JSON.stringify(detail);
                } else {
                    errMsg = errJson.message || errBody;
                }
            } catch {
                errMsg = errBody;
            }
            showToast(`API error: ${errMsg}`, 'error');
            return null;
        }

        // Handle 204 No Content
        if (resp.status === 204) return null;

        return await resp.json();
    } catch (err) {
        showToast(`Network error: ${err.message}`, 'error');
        return null;
    }
}

// ---------------------------------------------------------------------------
// Export Helpers
// ---------------------------------------------------------------------------

/** Export URL map: data-export value → { path, filename } */
const EXPORT_MAP = {
    commands:  { path: '/api/export/commands',  name: 'shieldpilot-commands' },
    incidents: { path: '/api/export/incidents', name: 'shieldpilot-incidents' },
    scans:     { path: '/api/export/scans',     name: 'shieldpilot-scans' },
    report:    { path: '/api/export/report',    name: 'shieldpilot-report' },
};

/**
 * Trigger an authenticated file download via fetch + Blob.
 * @param {string} key     Export key (commands, incidents, scans, report)
 * @param {string} format  Format: csv, json, or html (for report)
 */
async function triggerExportDownload(key, format) {
    const entry = EXPORT_MAP[key];
    if (!entry) return;
    const token = getToken();
    const url = key === 'report'
        ? entry.path
        : `${entry.path}?format=${encodeURIComponent(format)}`;

    try {
        const resp = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` },
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => null);
            showToast(err?.detail?.message || `Export failed (${resp.status})`, 'error');
            return;
        }
        const blob = await resp.blob();
        const ext = key === 'report' ? 'html' : format;
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `${entry.name}.${ext}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(a.href);
        showToast(`${key.charAt(0).toUpperCase() + key.slice(1)} exported as ${ext.toUpperCase()}`, 'success');
    } catch (err) {
        showToast(`Export failed: ${err.message}`, 'error');
    }
}

/**
 * Wire up an ExportDropdown component inside a container element.
 * @param {HTMLElement} container  Element containing the ExportDropdown HTML.
 */
function wireExportDropdown(container) {
    const toggleBtn = container.querySelector('#export-toggle-btn');
    const menu = container.querySelector('#export-dropdown-menu');
    if (!toggleBtn || !menu) return;

    toggleBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const open = menu.style.display === 'block';
        menu.style.display = open ? 'none' : 'block';
        toggleBtn.setAttribute('aria-expanded', open ? 'false' : 'true');
    });

    menu.querySelectorAll('.export-option').forEach(opt => {
        opt.addEventListener('click', () => {
            const key = opt.dataset.export;
            const format = key === 'report' ? 'html' : 'csv';
            triggerExportDownload(key, format);
            menu.style.display = 'none';
            toggleBtn.setAttribute('aria-expanded', 'false');
        });
    });

    document.addEventListener('click', () => {
        menu.style.display = 'none';
        toggleBtn.setAttribute('aria-expanded', 'false');
    });
}

/**
 * Render an inline export bar with CSV + JSON buttons for a specific data type.
 * @param {"commands"|"incidents"|"scans"} type
 * @returns {string} HTML
 */
function InlineExportBar(type, tierEnabled) {
    const enabled = tierEnabled !== false;
    const label = type.charAt(0).toUpperCase() + type.slice(1);
    const disabledAttr = enabled ? '' : ' disabled';
    const proClass = enabled ? '' : ' btn-pro-only';
    const tooltip = enabled ? '' : ' title="Paid feature"';
    return `<div class="inline-export-bar">
    <span class="inline-export-label">Export ${escapeHtml(label)}:</span>
    <button class="btn btn-xs btn-secondary inline-export-btn${proClass}"${disabledAttr}${tooltip} data-export-type="${escapeHtml(type)}" data-export-format="csv">CSV</button>
    <button class="btn btn-xs btn-secondary inline-export-btn${proClass}"${disabledAttr}${tooltip} data-export-type="${escapeHtml(type)}" data-export-format="json">JSON</button>
</div>`;
}

/**
 * Wire inline export buttons inside a container.
 * @param {HTMLElement} container
 */
function wireInlineExportButtons(container) {
    container.querySelectorAll('.inline-export-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.dataset.exportType;
            const format = btn.dataset.exportFormat;
            triggerExportDownload(type, format);
        });
    });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const routes = {
    '#/dashboard': renderDashboard,
    '#/commands': renderCommands,
    '#/incidents': renderIncidents,
    '#/scans': renderScans,
    '#/activity': renderActivity,
    '#/config': renderConfig,
    '#/health': renderHealth,
    '#/settings': renderSettings,
    '#/setup': renderSetup,
    '#/library': renderLibrary,
    '#/pricing': renderPricing,
    '#/legal/terms': renderLegalTerms,
    '#/legal/privacy': renderLegalPrivacy,
    '#/legal/impressum': renderLegalImpressum,
    '#/legal/withdrawal': renderLegalWithdrawal,
};

/** Currently active intervals/connections that should be cleared on navigation. */
let activeIntervals = [];

function clearActiveIntervals() {
    activeIntervals.forEach(item => {
        // Handle EventSource and other closeable objects
        if (item && typeof item.close === 'function') {
            item.close();
        } else if (typeof item === 'number') {
            // Handle setInterval IDs
            clearInterval(item);
        }
    });
    activeIntervals = [];
}

function registerInterval(id) {
    activeIntervals.push(id);
    return id;
}

function getPageContent() {
    return document.getElementById('page-content');
}

function navigate(hash) {
    window.location.hash = hash;
}

function currentHash() {
    return window.location.hash || DEFAULT_HASH;
}

async function handleRoute() {
    if (!requireAuth()) return;
    clearActiveIntervals();
    destroyAllCharts();

    // Refresh usage on every navigation (fire-and-forget)
    fetchUsage();

    const hash = currentHash();

    // Admin-only route guard
    if (hash === '#/config' && usageCache && !usageCache.is_admin) {
        showToast('Config is admin-only', 'error');
        navigate('#/dashboard');
        return;
    }

    const handler = routes[hash] || routes[DEFAULT_HASH];

    // Update active nav
    document.querySelectorAll('.nav-item').forEach(el => {
        const target = el.getAttribute('data-route');
        el.classList.toggle('active', target === hash);
    });

    try {
        await handler();
    } catch (err) {
        console.error(`Route ${hash} failed:`, err);
        const page = getPageContent();
        if (page) page.innerHTML = `<h1>Error</h1><p>Failed to load page: ${escapeHtml(err.message)}</p>`;
    }

    // Mount ApexCharts from page render + render Lucide icons
    mountPendingCharts();
    if (window.lucide) window.lucide.createIcons();

    // Animate.css page transition
    const pageEl = getPageContent();
    if (pageEl) {
        pageEl.classList.remove('animate__animated', 'animate__fadeIn');
        void pageEl.offsetWidth; // force reflow
        pageEl.classList.add('animate__animated', 'animate__fadeIn');
    }
}

// ---------------------------------------------------------------------------
// W4: Drill-Down Navigation Helpers
// ---------------------------------------------------------------------------

/**
 * Wire click handlers on stat cards with data-navigate attribute.
 * Clicking navigates to the target hash route.
 * @param {HTMLElement} container
 */
function wireStatCardNavigation(container) {
    container.querySelectorAll('.stat-card[data-navigate]').forEach(card => {
        card.addEventListener('click', () => {
            const target = card.dataset.navigate;
            if (target) navigate(target);
        });
    });
}

/**
 * Wire click handlers on activity items for drill-down navigation.
 * CMD/NET/FILE -> #/commands, INC/INCIDENT -> #/incidents, SCAN -> #/scans.
 * @param {HTMLElement} container
 */
function wireActivityItemNavigation(container) {
    container.querySelectorAll('.activity-item').forEach(el => {
        el.addEventListener('click', () => {
            const type = (el.dataset.type || '').toUpperCase();
            if (type === 'INC' || type === 'INCIDENT') {
                navigate('#/incidents');
            } else if (type === 'SCAN') {
                navigate('#/scans');
            } else {
                navigate('#/commands');
            }
        });
    });
}

/**
 * Wire click on incident card body to toggle technical details.
 * Clicks on buttons (resolve, investigate) are excluded via stopPropagation.
 * @param {HTMLElement} container
 */
function wireIncidentCardClick(container) {
    container.querySelectorAll('.incident-card').forEach(card => {
        card.addEventListener('click', (e) => {
            // Don't trigger if clicking a button or link
            if (e.target.closest('button') || e.target.closest('a') || e.target.closest('input')) return;
            const details = card.querySelector('.incident-technical');
            if (details) {
                details.open = !details.open;
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Page Renderers
// ---------------------------------------------------------------------------

// -- Dashboard --------------------------------------------------------------

async function renderDashboard() {
    const page = getPageContent();
    page.innerHTML = `<div style="padding:var(--space-lg)">${Spinner()}</div>`;

    // Fetch core data + Command Center data in parallel
    let ccPeriod = localStorage.getItem('cc_period') || '7d';
    const [stats, usage, secStatus, threatIntel, attackSummary] = await Promise.all([
        api('/api/stats', { params: { hours: 24 } }),
        fetchUsage(),
        api('/api/dashboard/security-status').catch(() => null),
        api('/api/dashboard/threat-intel', { params: { period: ccPeriod } }).catch(() => null),
        api('/api/dashboard/attack-summary').catch(() => null),
    ]);

    if (!stats) {
        page.innerHTML = `<h1>Dashboard</h1>${EmptyState('Failed to load stats.')}`;
        return;
    }

    updateIncidentBadge(stats.unresolved_incidents);

    const limitBanner = LimitReachedBanner(usage);
    const approachingBanner = ApproachingLimitBanner(usage);
    const usageMeter = UsageMeter(usage);

    const isProTier = usage && ['pro', 'pro_plus', 'enterprise', 'unlimited'].includes(usage.tier);
    const isAdmin = usage && usage.is_admin === true;
    const isFree = !isAdmin && !isProTier;
    // Free users are locked to 24h — override any saved preference
    if (isFree && ccPeriod !== '24h') ccPeriod = '24h';
    let currentStats = stats;
    let timeRange = isAdmin ? (localStorage.getItem('dash_time_range') || '24h') : '24h';

    function rangeLabel(range) {
        return range === 'all' ? 'All Time' : '24h';
    }

    function rangeEmptyLabel(range) {
        return range === 'all' ? 'all time' : '24 hours';
    }

    function getRangeStats(s, range) {
        if (range === 'all') {
            return {
                allowed: s.all_time_allowed ?? 0,
                warned: s.all_time_warned ?? 0,
                blocked: s.all_time_blocked ?? 0,
                incidents: s.all_time_incidents ?? 0,
                scans: s.all_time_scans ?? 0,
            };
        }
        return {
            allowed: s.allowed_commands ?? 0,
            warned: s.warned_commands ?? 0,
            blocked: s.blocked_commands ?? 0,
            incidents: s.total_incidents ?? 0,
            scans: s.total_scans ?? 0,
        };
    }

    // Store daily sparkline data once analytics loads
    let dailySparklineData = null;

    function renderStatCards(s, range) {
        const r = getRangeStats(s, range);
        const label = rangeLabel(range);
        const allowedSpark = dailySparklineData
            ? SparklineChart(dailySparklineData.map(d => Math.max(0, (d.commands || 0) - (d.blocked || 0) - (d.warned || 0))), { width: 100, height: 28, color: 'var(--color-allow)', label: '' })
            : null;
        const warnedSpark = dailySparklineData
            ? SparklineChart(dailySparklineData.map(d => d.warned || 0), { width: 100, height: 28, color: 'var(--color-warn)', label: '' })
            : null;
        const blockedSpark = dailySparklineData
            ? SparklineChart(dailySparklineData.map(d => d.blocked || 0), { width: 100, height: 28, color: 'var(--color-block)', label: '' })
            : null;
        const cards = [
            StatCard(r.allowed, `Allowed (${label})`, 'var(--color-allow)', 'check', 'accent-allow', allowedSpark, '#/commands'),
            StatCard(r.warned, `Warned (${label})`, 'var(--color-warn)', 'alert-triangle', 'accent-warn', warnedSpark, '#/commands'),
            StatCard(r.blocked, `Blocked (${label})`, 'var(--color-block)', 'shield-x', 'accent-block', blockedSpark, '#/commands'),
            StatCard(r.incidents, `Incidents (${label})`, 'var(--color-warn)', 'alert-triangle', 'accent-warn', null, '#/incidents'),
            StatCard(s.unresolved_incidents ?? 0, 'Open Incidents', 'var(--color-warn)', 'alert-circle', 'accent-warn', null, '#/incidents'),
            StatCard(r.scans, `Scans (${label})`, null, 'scan-search', null, null, '#/scans'),
        ];
        // Staggered Animate.css entrance
        return cards.map((card, i) =>
            card.replace('class="stat-card', `class="stat-card animate__animated animate__fadeInUp" style="animation-delay:${i * 0.08}s`)
        ).join('\n');
    }

    function renderTimeToggle(range) {
        const allTimeLocked = !isAdmin;
        const lockIcon = allTimeLocked ? ' <span class="lock-icon" title="Admin access required">🔒</span>' : '';
        const lockedClass = allTimeLocked ? ' locked' : '';
        return `<div class="time-toggle" role="group" aria-label="Time Range">
    <button class="btn btn-sm time-toggle-btn ${range === '24h' ? 'active' : ''}" data-range="24h">24h</button>
    <button class="btn btn-sm time-toggle-btn${lockedClass} ${range === 'all' ? 'active' : ''}" data-range="all">All Time${lockIcon}</button>
</div>`;
    }

    function renderRiskChart(s, range) {
        const r = getRangeStats(s, range);
        return RiskDistributionChart(r.allowed, r.warned, r.blocked, rangeEmptyLabel(range));
    }

    // --- Build Command Center Operations Grid ---
    const blocked24 = secStatus ? secStatus.threats_blocked_today : (stats.blocked_commands ?? 0);
    const blocked7d = secStatus ? secStatus.threats_blocked_7d : (stats.all_time_blocked ?? 0);
    const blocked30d = secStatus ? secStatus.threats_blocked_30d : 0;
    const trendPct = secStatus ? secStatus.blocked_trend_pct : 0;
    const trendHtml = trendPct !== 0
        ? `<span style="font-size:0.72rem;color:${trendPct > 0 ? 'var(--color-block)' : 'var(--color-allow)'}">${trendPct > 0 ? '▲' : '▼'} ${Math.abs(trendPct)}%</span>`
        : '';

    const opsGridHtml = `<div class="ops-grid">
    ${OpsCard('Threats Blocked', blocked24, blocked24 > 0 ? 'tone-bad' : 'tone-good', [
        { label: '7 Days', value: blocked7d },
        { label: '30 Days', value: blocked30d },
    ], trendHtml)}
    ${OpsScoreCard(secStatus ? secStatus.security_score : 100)}
    ${OpsCard('Open Incidents', secStatus ? secStatus.unresolved_incidents : (stats.unresolved_incidents ?? 0),
        (secStatus ? secStatus.unresolved_incidents : (stats.unresolved_incidents ?? 0)) > 0 ? 'tone-warn' : 'tone-good', [
        { label: 'Suspicious', value: secStatus ? secStatus.suspicious_today : 0, sub: 'today' },
    ])}
    ${OpsCard('Scans', stats.total_scans ?? 0, 'tone-neutral', [
        { label: 'Allowed', value: stats.allowed_commands ?? 0 },
        { label: 'Warned', value: stats.warned_commands ?? 0 },
    ])}
    ${usage && !isAdmin && (usage.tier === 'free' || usage.tier === 'pro') ? UpgradeCTACard(usage.tier) : ''}
</div>`;

    // --- Build Threat Intelligence Section ---
    const threatTimelineHtml = threatIntel
        ? ThreatTimelineChart(threatIntel.timeline)
        : Spinner();
    const threatTypesHtml = threatIntel
        ? ThreatTypesList(threatIntel.top_threat_types)
        : Spinner();

    const isBlocked = usage && usage.limit_reached && !usage.is_admin;
    page.innerHTML = `${CCHeader(ccPeriod, isFree)}
${limitBanner}
${approachingBanner}
${isAdmin ? `<div id="chain-health-container">${ChainHealthWidget(null)}</div>` : ''}
<div id="usage-meter-container">${usageMeter}</div>
<div id="dashboard-content-wrapper" class="dashboard-content-wrapper${isBlocked ? ' paywall-active' : ''}">
<div id="cc-status-bar">${secStatus ? SecurityStatusBar(secStatus) : Spinner()}</div>
${TrustBar(stats, secStatus)}
${opsGridHtml}
<div class="threat-intel-grid">
    <section class="dashboard-section">
        <h2>Threat Timeline</h2>
        <div id="cc-threat-timeline">${threatTimelineHtml}</div>
    </section>
    <section class="dashboard-section">
        <h2>Top Threat Types</h2>
        <div id="cc-threat-types">${threatTypesHtml}</div>
    </section>
</div>
<div class="stat-grid">
${renderStatCards(currentStats, timeRange)}
</div>
<section class="dashboard-section dashboard-section-full">
    <h2>Commands Trend (7 Days)</h2>
    <div id="commands-line-chart">${Spinner()}</div>
</section>
<section class="dashboard-section dashboard-section-full">
    <h2>Daily Commands Breakdown (7 Days)</h2>
    <div id="daily-commands-chart">${Spinner()}</div>
</section>
<div class="dashboard-grid">
    <section class="dashboard-section">
        <div class="dashboard-section-header">
            <h2 id="risk-dist-title">Risk Distribution (${rangeLabel(timeRange)})</h2>
            ${renderTimeToggle(timeRange)}
        </div>
        <div id="risk-dist-chart">${renderRiskChart(currentStats, timeRange)}</div>
        <div id="risk-score-bars">${Spinner()}</div>
        <div id="score-histogram">${Spinner()}</div>
    </section>
    <section class="dashboard-section">
        <h2>Recent Activity <a href="#/activity" class="section-view-all">View all &rarr;</a></h2>
        <div id="dash-activity">
            <div id="dash-activity-filter"></div>
            <div id="dash-activity-list">${Spinner()}</div>
        </div>
    </section>
</div>
<div class="dashboard-grid dashboard-grid-3col">
    <section class="dashboard-section">
        <h2>Block Rate</h2>
        <div id="dash-block-gauge">${Spinner()}</div>
    </section>
    <section class="dashboard-section">
        <h2>Top Blocked Commands</h2>
        <div id="dash-top-blocked">${Spinner()}</div>
    </section>
    <section class="dashboard-section">
        <h2>Top Categories</h2>
        <div id="dash-top-categories">${Spinner()}</div>
    </section>
</div>
<div class="dashboard-grid">
    <section class="dashboard-section">
        <h2>Score Distribution</h2>
        <div id="dash-score-dist">${Spinner()}</div>
    </section>
    <section class="dashboard-section">
        <h2>Recent Incidents <a href="#/incidents" class="section-view-all">View all &rarr;</a></h2>
        <div id="dash-incidents">${Spinner()}</div>
    </section>
</div>
${ValueBanner(blocked30d || blocked7d || blocked24)}
${DashboardPaywall(usage)}
</div>`;

    // W4: Wire clickable stat cards — navigate on click
    wireStatCardNavigation(page);

    // W4: Wire export dropdown
    wireExportDropdown(page);

    // Fetch chain health (non-blocking, admin only)
    if (isAdmin) {
        fetch('/api/health/chain', {
            headers: { 'Authorization': 'Bearer ' + localStorage.getItem('sentinel_token') }
        })
        .then(r => r.ok ? r.json() : Promise.reject('not ok'))
        .then(data => {
            const container = document.getElementById('chain-health-container');
            if (container) {
                container.innerHTML = ChainHealthWidget(data);
                initChainWidgetDismiss(container);
            }
        })
        .catch(() => {
            const widget = document.getElementById('chain-health-container');
            if (widget) widget.innerHTML = '';
        });
    }

    // Load activity feed with filter bar
    const feed = await api('/api/activity/feed', { params: { limit: 20 } });
    const actFilterContainer = document.getElementById('dash-activity-filter');
    const actListContainer = document.getElementById('dash-activity-list');
    const feedEvents = feed ? (feed.events || feed) : [];
    let dashActivityFilter = '';

    function renderDashActivityItems(filter) {
        if (!actListContainer) return;
        const filtered = filter
            ? feedEvents.filter(e => (e.type || '').toUpperCase() === filter.toUpperCase())
            : feedEvents;
        if (filtered.length > 0) {
            actListContainer.innerHTML = filtered.slice(0, 10).map(e => ActivityItem(e)).join('');
            wireActivityItemNavigation(actListContainer);
        } else {
            actListContainer.innerHTML = EmptyState('No activity for this filter.', 'Try a different filter or check back later.');
        }
    }

    if (Array.isArray(feedEvents) && feedEvents.length) {
        // Render filter bar
        if (actFilterContainer) {
            actFilterContainer.innerHTML = ActivityFilterBar(dashActivityFilter);
            actFilterContainer.querySelectorAll('.activity-type-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    dashActivityFilter = btn.getAttribute('data-type') || '';
                    // Update active states
                    actFilterContainer.querySelectorAll('.activity-type-btn').forEach(b => {
                        const isActive = (b.getAttribute('data-type') || '') === dashActivityFilter;
                        b.classList.toggle('active', isActive);
                        b.setAttribute('aria-pressed', isActive ? 'true' : 'false');
                    });
                    renderDashActivityItems(dashActivityFilter);
                });
            });
        }
        // Render initial unfiltered list
        renderDashActivityItems(dashActivityFilter);
    } else {
        if (actFilterContainer) actFilterContainer.innerHTML = '';
        actListContainer.innerHTML = EmptyState('No recent activity.');
    }

    // K1: Load recent open incidents
    const incidentsContainer = document.getElementById('dash-incidents');
    if (incidentsContainer) {
        const incResult = await api('/api/incidents', { params: { resolved: 'false', limit: 5 } });
        const incidents = incResult ? (Array.isArray(incResult) ? incResult : (incResult.items || incResult.incidents || [])) : [];
        if (incidents.length > 0) {
            incidentsContainer.innerHTML = incidents.slice(0, 5).map(inc => IncidentCard(inc)).join('');
            // Wire resolve buttons within dashboard incident feed
            incidentsContainer.querySelectorAll('.btn-resolve').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const incidentId = btn.getAttribute('data-incident-id');
                    showResolveForm(incidentId, btn);
                });
            });
            // W2: Wire investigate buttons in dashboard incident feed
            incidentsContainer.querySelectorAll('.btn-investigate').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const card = btn.closest('.incident-card');
                    if (card) {
                        const details = card.querySelector('.incident-technical');
                        if (details) {
                            details.open = true;
                            details.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                        }
                    }
                });
            });
            // W4: Wire clickable incident cards — toggle technical details
            wireIncidentCardClick(incidentsContainer);
        } else {
            incidentsContainer.innerHTML = EmptyState('No open incidents.');
        }
    }

    // K2: Load score histogram from recent commands
    const histogramContainer = document.getElementById('score-histogram');
    if (histogramContainer) {
        const cmdResult = await api('/api/commands', { params: { limit: 200 } });
        const commands = cmdResult ? (cmdResult.items || cmdResult.commands || cmdResult) : [];
        const riskScores = Array.isArray(commands) ? commands.map(c => c.risk_score ?? c.score ?? 0) : [];
        if (riskScores.length > 0) {
            histogramContainer.innerHTML = `<h3 class="histogram-section-title">Score Distribution (last ${riskScores.length} commands)</h3>` + ScoreHistogramChart(riskScores);
            mountPendingCharts();
        } else {
            histogramContainer.innerHTML = '';
        }
    }

    // K2: Daily commands chart + K1: Line chart + Donut + K3: Sparklines
    const dailyChartContainer = document.getElementById('daily-commands-chart');
    const lineChartContainer = document.getElementById('commands-line-chart');
    const categoriesContainer = document.getElementById('dash-top-categories');
    try {
        const analyticsData = await api('/api/stats/analytics', { params: { days: 7 } });
        if (analyticsData && analyticsData.daily && analyticsData.daily.length > 0) {
            // K2: Render daily commands stacked bar chart (reverse for chronological order)
            const dailyReversed = [...analyticsData.daily].reverse();
            if (dailyChartContainer) {
                dailyChartContainer.innerHTML = DailyCommandsChart(dailyReversed);
            }
            // K1: Render SVG line chart for commands trend
            if (lineChartContainer) {
                lineChartContainer.innerHTML = CommandsLineChart(dailyReversed);
            }
            // K1: Render donut chart for top categories
            if (categoriesContainer) {
                const topCats = analyticsData.top_categories || [];
                if (topCats.length > 0) {
                    categoriesContainer.innerHTML = DonutChart(topCats, 'Top Signal Categories');
                } else {
                    categoriesContainer.innerHTML = EmptyState('No category data.', 'Check back after some activity.');
                }
            }
            // K3: Store daily data for sparklines and re-render stat cards
            dailySparklineData = analyticsData.daily;
            const statGrid = page.querySelector('.stat-grid');
            if (statGrid) {
                statGrid.innerHTML = renderStatCards(currentStats, timeRange);
                // W4: Re-wire stat card navigation after sparkline re-render
                wireStatCardNavigation(statGrid);
            }
            // Mount all charts from this batch (daily, line, donut, sparklines)
            mountPendingCharts();
            if (window.lucide) window.lucide.createIcons();
        } else {
            if (dailyChartContainer) {
                dailyChartContainer.innerHTML = EmptyState('No daily data available.', 'Check back after some activity.');
            }
            if (lineChartContainer) {
                lineChartContainer.innerHTML = EmptyState('No trend data available.', 'Check back after some activity.');
            }
            if (categoriesContainer) {
                categoriesContainer.innerHTML = EmptyState('No category data.', 'Check back after some activity.');
            }
        }
    } catch (e) {
        if (dailyChartContainer) {
            dailyChartContainer.innerHTML = EmptyState('Chart unavailable.', 'The analytics endpoint may not be ready yet.');
        }
        if (lineChartContainer) {
            lineChartContainer.innerHTML = EmptyState('Chart unavailable.', 'The analytics endpoint may not be ready yet.');
        }
        if (categoriesContainer) {
            categoriesContainer.innerHTML = EmptyState('Categories unavailable.', 'The analytics endpoint may not be ready yet.');
        }
    }

    // K3: Load block rate gauge, top blocked commands, and score distribution
    const gaugeContainer = document.getElementById('dash-block-gauge');
    const topBlockedContainer = document.getElementById('dash-top-blocked');
    const scoreDistContainer = document.getElementById('dash-score-dist');
    const riskBarsContainer = document.getElementById('risk-score-bars');
    try {
        const statsData = await api('/api/stats', { params: { hours: 24 } });
        if (statsData) {
            // Block Rate Gauge
            if (gaugeContainer) {
                const total = (statsData.allowed_commands ?? 0) + (statsData.warned_commands ?? 0) + (statsData.blocked_commands ?? 0);
                const blockRate = total > 0 ? ((statsData.blocked_commands ?? 0) / total) * 100 : 0;
                gaugeContainer.innerHTML = BlockRateGauge(blockRate);
            }
            // Top Blocked Commands
            if (topBlockedContainer) {
                const topBlocked = statsData.top_blocked_commands || [];
                if (topBlocked.length > 0) {
                    topBlockedContainer.innerHTML = TopBlockedTable(topBlocked);
                } else {
                    topBlockedContainer.innerHTML = EmptyState('No blocked commands.', 'All commands were allowed in the last 24h.');
                }
            }
            // K1: Risk Score Horizontal Bar Chart (SVG)
            if (riskBarsContainer) {
                const scoreDist = statsData.score_distribution || [];
                if (scoreDist.length > 0) {
                    riskBarsContainer.innerHTML = `<h3 class="histogram-section-title">Risk Score Breakdown</h3>` + RiskScoreBarChart(scoreDist);
                } else {
                    riskBarsContainer.innerHTML = '';
                }
            }
            // Score Distribution Bars
            if (scoreDistContainer) {
                const scoreDist = statsData.score_distribution || [];
                if (scoreDist.length > 0) {
                    scoreDistContainer.innerHTML = ScoreDistributionBars(scoreDist);
                } else {
                    scoreDistContainer.innerHTML = EmptyState('No score data.', 'Check back after some commands are analyzed.');
                }
            }
            // Mount charts from stats batch (gauge, risk bars, score dist)
            mountPendingCharts();
        }
    } catch (e) {
        if (gaugeContainer) gaugeContainer.innerHTML = EmptyState('Gauge unavailable.');
        if (topBlockedContainer) topBlockedContainer.innerHTML = EmptyState('Data unavailable.');
        if (scoreDistContainer) scoreDistContainer.innerHTML = EmptyState('Data unavailable.');
    }

    // Real-time updates via SSE with polling fallback
    function updateDashboardStats(freshStats, sseUsage) {
        if (!freshStats) return;
        currentStats = freshStats;
        updateIncidentBadge(freshStats.unresolved_incidents);
        const grid = page.querySelector('.stat-grid');
        if (grid) {
            grid.innerHTML = renderStatCards(freshStats, timeRange);
            // W4: Re-wire stat card navigation after real-time update
            wireStatCardNavigation(grid);
        }
        const chart = page.querySelector('#risk-dist-chart');
        if (chart) {
            chart.innerHTML = renderRiskChart(freshStats, timeRange);
        }
        mountPendingCharts();
        if (window.lucide) window.lucide.createIcons();
        const title = page.querySelector('#risk-dist-title');
        if (title) {
            title.textContent = `Risk Distribution (${rangeLabel(timeRange)})`;
        }
        // Refresh usage meter — use SSE data if available, otherwise fetch
        const usagePromise = sseUsage
            ? Promise.resolve(sseUsage)
            : fetchUsage();

        usagePromise.then(freshUsage => {
            if (!freshUsage) return;
            if (sseUsage) { usageCache = sseUsage; updateTierBadge(sseUsage); updateSecurityBanner(sseUsage); }
            // Update usage meter bars via shared function
            updateUsageMeterBars(freshUsage);
            // Update limit banner
            const banner = page.querySelector('.limit-banner:not(.approaching-limit-banner):not(.payment-issue-banner):not(.cancellation-banner)');
            const newBanner = LimitReachedBanner(freshUsage);
            if (banner && !newBanner) banner.remove();
            if (!banner && newBanner) {
                const wrap = document.createElement('div');
                wrap.innerHTML = newBanner;
                if (wrap.firstElementChild) page.querySelector('h1')?.after(wrap.firstElementChild);
            }
            // Enforce paywall overlay
            applyDashboardPaywall(freshUsage, document.getElementById('dashboard-content-wrapper'));
        });
    }

    // Try SSE first, fall back to polling
    let sseConnected = false;
    let lastBlockedCount = stats.blocked_commands ?? 0;
    const token = localStorage.getItem('sentinel_token');

    if (typeof EventSource !== 'undefined') {
        try {
            const eventSource = new EventSource(`/api/stats/stream?hours=24&token=${encodeURIComponent(token)}`);

            eventSource.onmessage = (event) => {
                sseConnected = true;
                try {
                    const data = JSON.parse(event.data);
                    const sseUsage = data.usage || null;
                    delete data.usage;

                    // Injection alert toast when new blocks detected
                    const newBlocked = data.blocked_commands ?? 0;
                    if (newBlocked > lastBlockedCount) {
                        const diff = newBlocked - lastBlockedCount;
                        showToast(`${diff} command${diff > 1 ? 's' : ''} blocked — potential threat detected`, 'error');
                    }
                    lastBlockedCount = newBlocked;

                    updateDashboardStats(data, sseUsage);
                } catch (e) {
                    console.error('SSE parse error:', e);
                }
            };

            eventSource.onerror = () => {
                eventSource.close();
                // Always fall back to polling when SSE disconnects
                startPolling();
            };

            // Register for cleanup on navigation
            registerInterval({ close: () => eventSource.close() });
        } catch (e) {
            startPolling();
        }
    } else {
        startPolling();
    }

    function startPolling() {
        const refreshId = setInterval(async () => {
            const freshStats = await api('/api/stats', { params: { hours: 24 } });
            updateDashboardStats(freshStats);
        }, 10000); // Poll every 10 seconds
        registerInterval(refreshId);
    }

    // K1: SSE stream for real-time incident feed updates
    if (typeof EventSource !== 'undefined') {
        try {
            const activitySource = new EventSource(`/api/activity/stream?token=${encodeURIComponent(token)}`);
            activitySource.onmessage = (event) => {
                try {
                    const newEvent = JSON.parse(event.data);
                    // If it's an incident event, prepend to dashboard incidents
                    if (newEvent.type === 'INC' || newEvent.type === 'INCIDENT') {
                        const dashInc = document.getElementById('dash-incidents');
                        if (dashInc) {
                            // Remove empty state if present
                            const emptyEl = dashInc.querySelector('.empty-state');
                            if (emptyEl) emptyEl.remove();
                            // Create a lightweight incident card from SSE event data
                            const tempDiv = document.createElement('div');
                            const incidentData = {
                                id: newEvent.id,
                                severity: newEvent.severity || 'high',
                                category: newEvent.category || 'unknown',
                                timestamp: newEvent.timestamp,
                                description: newEvent.summary || '',
                                resolved: false,
                            };
                            tempDiv.innerHTML = IncidentCard(incidentData);
                            const newEl = tempDiv.firstElementChild;
                            if (newEl) {
                                newEl.classList.add('activity-item-new');
                                dashInc.insertBefore(newEl, dashInc.firstChild);
                                setTimeout(() => newEl.classList.remove('activity-item-new'), 500);
                                // Keep max 5 items
                                while (dashInc.children.length > 5) {
                                    dashInc.removeChild(dashInc.lastChild);
                                }
                            }
                        }
                    }
                } catch (e) {
                    console.error('Dashboard activity SSE parse error:', e);
                }
            };
            activitySource.onerror = () => activitySource.close();
            registerInterval({ close: () => activitySource.close() });
        } catch (e) { /* SSE not available */ }
    }

    // Time toggle event listeners
    page.querySelectorAll('.time-toggle-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const range = btn.getAttribute('data-range');
            if (!range || range === timeRange) return;

            // Show paywall for non-admins trying to access "All Time"
            if (range === 'all' && !isAdmin) {
                showPaywallModal('blocked-history');
                return;
            }

            timeRange = range;
            localStorage.setItem('dash_time_range', timeRange);
            updateDashboardStats(currentStats);
            page.querySelectorAll('.time-toggle-btn').forEach(b => {
                b.classList.toggle('active', b.getAttribute('data-range') === timeRange);
            });
        });
    });

    // CC Period selector event listeners
    page.querySelectorAll('.period-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const period = btn.getAttribute('data-period');
            if (!period || period === ccPeriod) return;

            // Free users locked to 24h — show paywall for 7d/30d
            if (isFree && period !== '24h') {
                showPaywallModal('blocked-history');
                return;
            }

            ccPeriod = period;
            localStorage.setItem('cc_period', ccPeriod);
            page.querySelectorAll('.period-btn').forEach(b => {
                b.classList.toggle('active', b.getAttribute('data-period') === ccPeriod);
            });
            // Refresh threat intel with new period
            const timelineEl = document.getElementById('cc-threat-timeline');
            const typesEl = document.getElementById('cc-threat-types');
            if (timelineEl) timelineEl.innerHTML = Spinner();
            if (typesEl) typesEl.innerHTML = Spinner();
            const freshIntel = await api('/api/dashboard/threat-intel', { params: { period: ccPeriod } }).catch(() => null);
            if (freshIntel) {
                if (timelineEl) timelineEl.innerHTML = ThreatTimelineChart(freshIntel.timeline);
                if (typesEl) typesEl.innerHTML = ThreatTypesList(freshIntel.top_threat_types);
                mountPendingCharts();
            } else {
                if (timelineEl) timelineEl.innerHTML = EmptyState('Failed to load threat data.');
                if (typesEl) typesEl.innerHTML = EmptyState('Failed to load threat types.');
            }
        });
    });

    // K3: Export dropdown toggle + download logic
    const exportToggle = document.getElementById('export-toggle-btn');
    const exportMenu = document.getElementById('export-dropdown-menu');
    if (exportToggle && exportMenu) {
        exportToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = exportMenu.style.display === 'block';
            exportMenu.style.display = isOpen ? 'none' : 'block';
            exportToggle.setAttribute('aria-expanded', isOpen ? 'false' : 'true');
        });
        // Close dropdown when clicking outside
        document.addEventListener('click', () => {
            exportMenu.style.display = 'none';
            exportToggle.setAttribute('aria-expanded', 'false');
        });
        // Handle export option clicks
        exportMenu.querySelectorAll('.export-option').forEach(opt => {
            opt.addEventListener('click', async (e) => {
                e.stopPropagation();
                const exportType = opt.getAttribute('data-export');
                exportMenu.style.display = 'none';
                exportToggle.setAttribute('aria-expanded', 'false');
                try {
                    const token = localStorage.getItem('sentinel_token');
                    const endpoints = {
                        commands: '/api/export/commands',
                        incidents: '/api/export/incidents',
                        scans: '/api/export/scans',
                        report: '/api/export/report',
                    };
                    const endpoint = endpoints[exportType];
                    if (!endpoint) return;
                    const resp = await fetch(endpoint, {
                        headers: { 'Authorization': 'Bearer ' + token },
                    });
                    if (resp.status === 403 || resp.status === 402) {
                        showPaywallModal('export');
                        return;
                    }
                    if (!resp.ok) {
                        showToast('Export failed. Please try again.', 'error');
                        return;
                    }
                    const blob = await resp.blob();
                    const contentDisposition = resp.headers.get('Content-Disposition') || '';
                    const filenameMatch = contentDisposition.match(/filename=([^;]+)/);
                    const filename = filenameMatch ? filenameMatch[1].trim() : `shieldpilot-${exportType}.${exportType === 'report' ? 'html' : 'csv'}`;
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    showToast(`${exportType.charAt(0).toUpperCase() + exportType.slice(1)} exported successfully.`, 'success');
                } catch (err) {
                    showToast('Export failed: ' + (err.message || 'Unknown error'), 'error');
                }
            });
        });
    }

    // Fetch subscription status for billing banners
    try {
        const settingsResp = await fetch('/api/settings', { headers: { 'Authorization': 'Bearer ' + localStorage.getItem('sentinel_token') } });
        if (settingsResp.ok) {
            const settingsData = await settingsResp.json();
            const paymentBanner = PaymentIssueBanner(settingsData);
            const cancelBanner = CancellationWarningBanner(settingsData);
            if (paymentBanner || cancelBanner) {
                const bannerDiv = document.createElement('div');
                bannerDiv.innerHTML = paymentBanner + cancelBanner;
                const firstSection = page.querySelector('.dashboard-grid, section');
                if (firstSection) {
                    page.insertBefore(bannerDiv, firstSection);
                }
            }
            // Wire up payment fix button
            const fixBtn = document.getElementById('fix-payment-btn');
            if (fixBtn) {
                fixBtn.addEventListener('click', async () => {
                    try {
                        const resp = await fetch('/api/billing/portal', {
                            method: 'POST',
                            headers: { 'Authorization': 'Bearer ' + localStorage.getItem('sentinel_token'), 'Content-Type': 'application/json' }
                        });
                        if (resp.ok) {
                            const data = await resp.json();
                            window.open(data.url, '_blank');
                        }
                    } catch (e) { console.error(e); }
                });
            }
            const reactivateBtn = document.getElementById('reactivate-sub-btn');
            if (reactivateBtn) {
                reactivateBtn.addEventListener('click', async () => {
                    try {
                        const resp = await fetch('/api/billing/portal', {
                            method: 'POST',
                            headers: { 'Authorization': 'Bearer ' + localStorage.getItem('sentinel_token'), 'Content-Type': 'application/json' }
                        });
                        if (resp.ok) {
                            const data = await resp.json();
                            window.open(data.url, '_blank');
                        }
                    } catch (e) { console.error(e); }
                });
            }
        }
    } catch (e) { /* ignore */ }
}

// -- Commands ---------------------------------------------------------------

let commandState = { page: 1, action: null, riskMin: null, riskMax: null, search: '', category: '', since: '', until: '' };
let commandData = [];
let commandDebounce = null;

async function renderCommands() {
    const page = getPageContent();
    commandState = { page: 1, action: null, riskMin: null, riskMax: null, search: '', category: '', since: '', until: '' };

    const usage = usageCache;
    const limitHit = usage && usage.limit_reached && !usage.is_admin;
    const commandsWarning = limitHit ? `<div class="commands-unprotected-banner">
        <div class="commands-unprotected-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#F85149" stroke-width="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
        </div>
        <div class="commands-unprotected-text">
            <strong>Threat scanning disabled</strong>
            <span>New commands from your AI agents are NOT being scanned for security threats. Dangerous commands will pass through unchecked.</span>
        </div>
    </div>` : '';

    const exportEnabled = !usageCache || usageCache.tier !== 'free';
    page.innerHTML = `<div class="page-header-row"><h1>Commands</h1>${InlineExportBar('commands', exportEnabled)}</div>${commandsWarning}${CommandFilterBar()}<div id="cmd-table">${Spinner()}</div><div id="cmd-pagination"></div>`;

    wireInlineExportButtons(page);
    await fetchAndRenderCommands();
    wireCommandFilters();
}

async function fetchAndRenderCommands() {
    const tableEl = document.getElementById('cmd-table');
    const pagEl = document.getElementById('cmd-pagination');
    if (!tableEl) return;

    tableEl.innerHTML = Spinner();

    const limit = 50;
    const params = {
        limit: limit,
        offset: (commandState.page - 1) * limit,
        action: commandState.action,
        risk_min: commandState.riskMin,
        risk_max: commandState.riskMax,
        search: commandState.search || commandState.category || null,
        since: commandState.since || null,
        until: commandState.until || null,
    };

    const result = await api('/api/commands', { params });
    if (!result) {
        tableEl.innerHTML = EmptyState('Failed to load commands.');
        return;
    }

    const items = result.items || result.commands || result;
    const totalPages = result.total_pages || result.pages || 1;
    commandData = Array.isArray(items) ? items : [];

    if (commandData.length === 0) {
        tableEl.innerHTML = EmptyState('No commands found.', 'Try adjusting your filters.', 'terminal');
        if (pagEl) pagEl.innerHTML = '';
        return;
    }

    const headers = [
        { key: 'timestamp', label: 'Time', width: '140px' },
        { key: 'command', label: 'Command' },
        { key: 'action', label: 'Action', width: '90px', align: 'center' },
        { key: 'score', label: 'Score', width: '80px', align: 'center' },
        { key: 'user', label: 'User', width: '100px' },
    ];

    const rows = commandData.map(cmd => ({
        timestamp: { __html: RelativeTime(cmd.timestamp) },
        command: { __html: CommandText(cmd.command || cmd.cmd, 60) },
        action: { __html: Badge(cmd.action_taken || cmd.action || 'unknown') },
        score: { __html: ScoreBadge(cmd.risk_score ?? cmd.score ?? 0) },
        user: escapeHtml(cmd.user || '-'),
    }));

    // Expose row-click handler globally for onclick attribute
    window.__sentinelExpandCommand = expandCommandRow;

    tableEl.innerHTML = DataTable(headers, rows, {
        expandable: true,
        onRowClick: '__sentinelExpandCommand',
    });

    if (pagEl) {
        window.__sentinelCmdPage = (p) => {
            commandState.page = p;
            fetchAndRenderCommands();
        };
        pagEl.innerHTML = Pagination(commandState.page, totalPages, '__sentinelCmdPage');
    }
}

function expandCommandRow(index, trElement) {
    const expandRow = document.querySelector(`tr[data-expand-index="${index}"]`);
    if (!expandRow) return;

    // Find the chevron button for ARIA state
    const chevronBtn = trElement ? trElement.querySelector('.expand-chevron') : null;

    // Toggle visibility
    const isVisible = expandRow.style.display !== 'none';
    if (isVisible) {
        expandRow.style.display = 'none';
        if (trElement) trElement.classList.remove('expanded');
        if (chevronBtn) {
            chevronBtn.setAttribute('aria-expanded', 'false');
            chevronBtn.setAttribute('aria-label', 'Expand row details');
        }
        return;
    }
    expandRow.style.display = '';
    if (trElement) trElement.classList.add('expanded');
    if (chevronBtn) {
        chevronBtn.setAttribute('aria-expanded', 'true');
        chevronBtn.setAttribute('aria-label', 'Collapse row details');
    }

    const cmd = commandData[index];
    if (!cmd) return;

    const content = expandRow.querySelector('.expand-content');
    if (!content) return;

    content.innerHTML = ForensicsPanel(cmd);
}

function wireCommandFilters() {
    // Action filter buttons
    document.querySelectorAll('.filter-actions .filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-actions .filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            commandState.action = btn.getAttribute('data-action') || null;
            commandState.page = 1;
            fetchAndRenderCommands();
        });
    });

    // Risk range inputs
    const riskMin = document.getElementById('risk-min');
    const riskMax = document.getElementById('risk-max');
    const debouncedFetch = () => {
        clearTimeout(commandDebounce);
        commandDebounce = setTimeout(() => {
            commandState.riskMin = riskMin && riskMin.value !== '' ? Number(riskMin.value) : null;
            commandState.riskMax = riskMax && riskMax.value !== '' ? Number(riskMax.value) : null;
            commandState.page = 1;
            fetchAndRenderCommands();
        }, 300);
    };
    if (riskMin) riskMin.addEventListener('input', debouncedFetch);
    if (riskMax) riskMax.addEventListener('input', debouncedFetch);

    // K3: Category filter
    const categorySelect = document.getElementById('cmd-category');
    if (categorySelect) {
        categorySelect.addEventListener('change', () => {
            commandState.category = categorySelect.value;
            // Only set search from category if user has not typed a manual search
            const searchInput = document.getElementById('cmd-search');
            if (!searchInput || !searchInput.value.trim()) {
                commandState.search = '';
            }
            commandState.page = 1;
            fetchAndRenderCommands();
        });
    }

    // K3: Date range filters
    const sinceInput = document.getElementById('cmd-since');
    const untilInput = document.getElementById('cmd-until');
    if (sinceInput) {
        sinceInput.addEventListener('change', () => {
            commandState.since = sinceInput.value || '';
            commandState.page = 1;
            fetchAndRenderCommands();
        });
    }
    if (untilInput) {
        untilInput.addEventListener('change', () => {
            commandState.until = untilInput.value || '';
            commandState.page = 1;
            fetchAndRenderCommands();
        });
    }

    // Search input
    const searchInput = document.getElementById('cmd-search');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            clearTimeout(commandDebounce);
            commandDebounce = setTimeout(() => {
                commandState.search = searchInput.value;
                commandState.page = 1;
                fetchAndRenderCommands();
            }, 300);
        });
    }
}

// -- Incidents --------------------------------------------------------------

let incidentTab = 'open'; // 'open' | 'resolved' | 'all'

async function renderIncidents() {
    const page = getPageContent();
    incidentTab = 'open';

    const exportEnabled = !usageCache || usageCache.tier !== 'free';
    page.innerHTML = `<div class="page-header-row"><h1>Incidents</h1>${InlineExportBar('incidents', exportEnabled)}</div>
<div class="tab-bar">
    <button class="tab-btn active" data-tab="open">Open</button>
    <button class="tab-btn" data-tab="resolved">Resolved</button>
    <button class="tab-btn" data-tab="all">All</button>
</div>
<div id="incident-list">${Spinner()}</div>`;

    wireInlineExportButtons(page);
    await fetchAndRenderIncidents();

    // Wire tabs
    document.querySelectorAll('.tab-bar .tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-bar .tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            incidentTab = btn.getAttribute('data-tab');
            fetchAndRenderIncidents();
        });
    });
}

async function fetchAndRenderIncidents() {
    const container = document.getElementById('incident-list');
    if (!container) return;
    container.innerHTML = Spinner();

    const params = {};
    if (incidentTab === 'open') params.resolved = 'false';
    else if (incidentTab === 'resolved') params.resolved = 'true';

    const result = await api('/api/incidents', { params });
    if (!result) {
        container.innerHTML = EmptyState('Failed to load incidents.');
        return;
    }

    const incidents = Array.isArray(result) ? result : (result.items || result.incidents || []);
    if (incidents.length === 0) {
        container.innerHTML = EmptyState('No incidents found.', 'All clear! No security incidents detected.', 'shield-check');
        return;
    }

    container.innerHTML = incidents.map(inc => IncidentCard(inc)).join('');

    // Wire resolve buttons
    container.querySelectorAll('.btn-resolve').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const incidentId = btn.getAttribute('data-incident-id');
            showResolveForm(incidentId, btn);
        });
    });

    // W2: Wire investigate buttons — open the <details> technical section
    container.querySelectorAll('.btn-investigate').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const card = btn.closest('.incident-card');
            if (card) {
                const details = card.querySelector('.incident-technical');
                if (details) {
                    details.open = true;
                    details.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }
            }
        });
    });

    // W4: Wire clickable incident cards — toggle technical details on card body click
    wireIncidentCardClick(container);
}

function showResolveForm(incidentId, btnElement) {
    // Replace button with inline form
    const card = btnElement.closest('.incident-card');
    const actionsDiv = card.querySelector('.incident-actions');
    actionsDiv.innerHTML = `<div class="resolve-form">
    <input type="text" class="filter-input" id="resolve-note-${escapeHtml(incidentId)}" placeholder="Resolution note..." />
    <button class="btn btn-sm btn-primary" id="resolve-submit-${escapeHtml(incidentId)}">Submit</button>
    <button class="btn btn-sm btn-secondary" id="resolve-cancel-${escapeHtml(incidentId)}">Cancel</button>
</div>`;

    document.getElementById(`resolve-cancel-${incidentId}`).addEventListener('click', () => {
        fetchAndRenderIncidents();
    });

    document.getElementById(`resolve-submit-${incidentId}`).addEventListener('click', async () => {
        const noteInput = document.getElementById(`resolve-note-${incidentId}`);
        const note = noteInput ? noteInput.value : '';
        const resp = await api(`/api/incidents/${encodeURIComponent(incidentId)}/resolve`, {
            method: 'PATCH',
            body: { resolution_notes: note },
        });
        if (resp !== null) {
            showToast('Incident resolved.', 'success');
            fetchAndRenderIncidents();
            // Refresh badge
            const stats = await api('/api/stats', { params: { hours: 24 } });
            if (stats) updateIncidentBadge(stats.unresolved_incidents);
        }
    });
}

// -- Scans ------------------------------------------------------------------

async function renderScans() {
    const page = getPageContent();

    // Check if scan limit is reached
    const usage = usageCache || await fetchUsage();
    const scanLimitHit = usage && !usage.is_admin && usage.scans_limit > 0 && usage.scans_used >= usage.scans_limit;

    const exportEnabled = !usageCache || usageCache.tier !== 'free';
    page.innerHTML = `<div class="page-header-row"><h1>Scans</h1>${InlineExportBar('scans', exportEnabled)}</div>
${scanLimitHit ? `<div class="scan-limit-banner">
    <div class="scan-limit-info">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <div>
            <strong>Daily scan limit reached (${escapeHtml(String(usage.scans_used))}/${escapeHtml(String(usage.scans_limit))})</strong>
            <p class="text-muted">You've used all your <strong>${escapeHtml(usage.tier === 'pro_plus' ? 'Pro+' : usage.tier)}</strong> tier scans for today. ${usage.tier === 'pro' ? 'Go Pro+ for unlimited scans \u2014 just \u20ac10 more/mo.' : 'Upgrade for more scans.'}</p>
        </div>
    </div>
    <a href="#/pricing" class="btn btn-primary">${usage.tier === 'pro' ? 'Upgrade to Pro+' : 'Upgrade to Pro'}</a>
</div>` : `<div class="scan-form-card">
    <h3>Scan Text for Prompt Injection</h3>
    <textarea id="scan-input" class="scan-textarea" rows="4" placeholder="Paste text to scan for prompt injection patterns..." maxlength="50000"></textarea>
    <div class="scan-form-actions">
        <button id="scan-submit-btn" class="btn btn-primary">Scan</button>
        <span id="scan-status" class="text-muted"></span>
    </div>
    <div id="scan-result"></div>
</div>`}
<div id="scan-timeline"></div>
<div id="scan-stats"></div>
<div id="scan-table">${Spinner()}</div>`;

    wireInlineExportButtons(page);

    // Wire up scan form (only exists when limit not hit)
    const scanBtn = document.getElementById('scan-submit-btn');
    if (!scanBtn) { loadScanTable(); return; }
    const scanInput = document.getElementById('scan-input');
    const scanStatus = document.getElementById('scan-status');
    const scanResult = document.getElementById('scan-result');

    scanBtn.addEventListener('click', async () => {
        const text = scanInput.value.trim();
        if (!text) {
            scanStatus.textContent = 'Please enter text to scan.';
            return;
        }
        scanBtn.disabled = true;
        scanStatus.textContent = 'Scanning...';
        scanResult.innerHTML = '';

        const result = await api('/api/scan/prompt', {
            method: 'POST',
            body: { content: text, source: 'dashboard' },
        });

        scanBtn.disabled = false;

        if (!result) {
            scanStatus.textContent = 'Scan failed. Check your connection or usage limits.';
            return;
        }

        scanStatus.textContent = '';
        scanResult.innerHTML = ScanResultDisplay(result);

        // Refresh usage cache so dashboard scan bar updates
        fetchUsage();

        // Reload scan list to include the new entry
        loadScanTable();
    });

    loadScanTable();

    // Accumulated scans for load-more pagination
    let allScans = [];
    let scanTotal = 0;
    const SCAN_PAGE_SIZE = 20;

    async function loadScanTable(append = false) {
        const container = document.getElementById('scan-table');
        if (!container) return;
        if (!append) container.innerHTML = Spinner();

        const offset = append ? allScans.length : 0;
        const result = await api(`/api/scans?limit=${SCAN_PAGE_SIZE}&offset=${offset}`);
        if (!result) {
            if (!append) container.innerHTML = EmptyState('Failed to load scans.');
            return;
        }

        const newScans = Array.isArray(result) ? result : (result.items || result.scans || []);
        scanTotal = result.total ?? newScans.length;

        if (append) {
            allScans = allScans.concat(newScans);
        } else {
            allScans = newScans;
        }

        if (allScans.length === 0) {
            // Better empty state with magnifying glass
            const statsContainer = document.getElementById('scan-stats');
            if (statsContainer) statsContainer.innerHTML = '';
            container.innerHTML = ScanEmptyState();
            return;
        }

        // Render injection timeline above the scan table (only on initial load)
        if (!append) {
            const timelineContainer = document.getElementById('scan-timeline');
            if (timelineContainer && allScans.length > 0) {
                timelineContainer.innerHTML = `<section class="dashboard-section scan-timeline-section">
                    <h2>Scan Timeline</h2>
                    ${InjectionTimelineChart(allScans.slice(0, 20))}
                </section>`;
            }
        }

        // Compute and render stats bar
        const statsContainer = document.getElementById('scan-stats');
        if (statsContainer) {
            const todayStr = new Date().toISOString().slice(0, 10);
            let scansToday = 0;
            let threatsDetected = 0;
            let blocked = 0;
            for (const s of allScans) {
                if (s.timestamp && s.timestamp.slice(0, 10) === todayStr) scansToday++;
                const tc = s.threat_count ?? (s.threats ? s.threats.length : 0);
                if (tc > 0) threatsDetected++;
                if ((s.overall_score ?? 0) >= 80) blocked++;
            }
            statsContainer.innerHTML = ScanStatsBar({ scansToday, threatsDetected, blocked });
        }

        const headers = [
            { key: 'timestamp', label: 'Time', width: '140px' },
            { key: 'source', label: 'Source' },
            { key: 'threat_count', label: 'Threats', width: '80px', align: 'center' },
            { key: 'score', label: 'Score', width: '80px', align: 'center' },
            { key: 'status', label: 'Status', width: '100px', align: 'center' },
        ];

        window.__sentinelExpandScan = (index, tr) => {
            const expandRow = document.querySelector(`tr[data-expand-index="${index}"]`);
            if (!expandRow) return;

            const chevronBtn = tr ? tr.querySelector('.expand-chevron') : null;

            const isVisible = expandRow.style.display !== 'none';
            if (isVisible) {
                expandRow.style.display = 'none';
                if (tr) tr.classList.remove('expanded');
                if (chevronBtn) {
                    chevronBtn.setAttribute('aria-expanded', 'false');
                    chevronBtn.setAttribute('aria-label', 'Expand row details');
                }
                return;
            }
            expandRow.style.display = '';
            if (tr) tr.classList.add('expanded');
            if (chevronBtn) {
                chevronBtn.setAttribute('aria-expanded', 'true');
                chevronBtn.setAttribute('aria-label', 'Collapse row details');
            }

            const content = expandRow.querySelector('.expand-content');
            if (!content) return;
            const scan = allScans[index];
            const scanThreats = scan.threats || [];
            if (scanThreats.length > 0) {
                content.innerHTML = ThreatList(scanThreats);
            } else {
                content.innerHTML = '<em class="text-muted">No threats detected.</em>';
            }
        };

        const rows = allScans.map(s => ({
            timestamp: { __html: RelativeTime(s.timestamp) },
            source: escapeHtml(s.source || '-'),
            threat_count: s.threat_count ?? (s.threats ? s.threats.length : 0),
            score: { __html: ScoreBadge(s.overall_score ?? 0) },
            status: { __html: ScanStatusBadge(s.overall_score ?? 0) },
        }));

        const tableHtml = DataTable(headers, rows, {
            expandable: true,
            onRowClick: '__sentinelExpandScan',
        });

        // Build load-more footer
        const hasMore = allScans.length < scanTotal;
        const footerHtml = `<div class="scan-table-footer">
            <span class="text-muted">Showing ${escapeHtml(String(allScans.length))} of ${escapeHtml(String(scanTotal))} scans</span>
            ${hasMore ? '<button class="btn btn-sm scan-load-more-btn" id="scan-load-more">Load more</button>' : ''}
        </div>`;

        container.innerHTML = tableHtml + footerHtml;

        // Wire load-more button
        const loadMoreBtn = document.getElementById('scan-load-more');
        if (loadMoreBtn) {
            loadMoreBtn.addEventListener('click', async () => {
                loadMoreBtn.disabled = true;
                loadMoreBtn.textContent = 'Loading...';
                await loadScanTable(true);
            });
        }
    }
}

// -- Activity Feed ----------------------------------------------------------

let activityPaused = false;
let activityState = { page: 1, type: null, severity: null };
const ACTIVITY_PAGE_SIZE = 20;

async function renderActivity() {
    const page = getPageContent();
    activityPaused = false;
    activityState = { page: 1, type: null, severity: null };

    page.innerHTML = `<h1>Activity Feed</h1>
<div class="activity-controls">
    <button class="btn btn-sm" id="activity-toggle">Pause</button>
    <span id="activity-status" class="status-indicator" role="status" aria-live="polite"></span>
</div>
<div class="activity-filter-bar" role="toolbar" aria-label="Activity feed filters">
    <div class="activity-filter-group" role="group" aria-label="Event type filter">
        <button class="activity-type-btn active" data-type="" aria-pressed="true">All</button>
        <button class="activity-type-btn" data-type="CMD" aria-pressed="false">CMD</button>
        <button class="activity-type-btn" data-type="INC" aria-pressed="false">INC</button>
        <button class="activity-type-btn" data-type="SCAN" aria-pressed="false">SCAN</button>
        <button class="activity-type-btn" data-type="NET" aria-pressed="false">NET</button>
        <button class="activity-type-btn" data-type="FILE" aria-pressed="false">FILE</button>
    </div>
    <div class="activity-filter-group activity-severity-group" role="group" aria-label="Severity filter">
        <label for="activity-severity-select" class="activity-severity-label">Severity:</label>
        <select id="activity-severity-select" class="activity-severity-select" aria-label="Filter by severity">
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
        </select>
    </div>
</div>
<div id="activity-feed">${Spinner()}</div>
<div id="activity-pagination"></div>`;

    // Wire up type filter buttons
    page.querySelectorAll('.activity-type-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const newType = btn.getAttribute('data-type') || null;
            activityState.type = newType;
            activityState.page = 1;
            // Update active state
            page.querySelectorAll('.activity-type-btn').forEach(b => {
                const isActive = (b.getAttribute('data-type') || null) === newType;
                b.classList.toggle('active', isActive);
                b.setAttribute('aria-pressed', isActive ? 'true' : 'false');
            });
            // Show/hide severity filter (only relevant when type is INC or All)
            const sevGroup = page.querySelector('.activity-severity-group');
            if (sevGroup) {
                sevGroup.style.display = (!newType || newType === 'INC') ? '' : 'none';
            }
            fetchAndRenderActivity();
        });
    });

    // Wire up severity dropdown
    const sevSelect = document.getElementById('activity-severity-select');
    if (sevSelect) {
        sevSelect.addEventListener('change', () => {
            activityState.severity = sevSelect.value || null;
            activityState.page = 1;
            fetchAndRenderActivity();
        });
    }

    // Make pagination callback global
    window.__activityGoToPage = (pageNum) => {
        activityState.page = pageNum;
        fetchAndRenderActivity();
    };

    await fetchAndRenderActivity();

    const token = localStorage.getItem('sentinel_token');
    let sseConnected = false;

    // Try SSE first for real-time updates
    if (typeof EventSource !== 'undefined') {
        try {
            const eventSource = new EventSource(`/api/activity/stream?token=${encodeURIComponent(token)}`);
            const statusEl = document.getElementById('activity-status');

            eventSource.onopen = () => {
                sseConnected = true;
                if (statusEl) statusEl.textContent = 'Live';
            };

            eventSource.onmessage = (event) => {
                if (activityPaused) return;
                // Only prepend SSE events when no filters are active and on page 1
                if (activityState.type || activityState.severity || activityState.page > 1) return;
                try {
                    const newEvent = JSON.parse(event.data);
                    prependActivityEvent(newEvent);
                } catch (e) {
                    console.error('SSE parse error:', e);
                }
            };

            eventSource.onerror = () => {
                eventSource.close();
                if (statusEl) statusEl.textContent = '';
                if (!sseConnected) {
                    startActivityPolling();
                }
            };

            registerInterval({ close: () => eventSource.close() });
        } catch (e) {
            startActivityPolling();
        }
    } else {
        startActivityPolling();
    }

    function startActivityPolling() {
        const intervalId = setInterval(() => {
            if (!activityPaused && !activityState.type && !activityState.severity && activityState.page === 1) {
                fetchAndRenderActivity();
            }
        }, 30000); // K2: Poll every 30s for new entries
        registerInterval(intervalId);
    }

    // Toggle button
    const toggleBtn = document.getElementById('activity-toggle');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            activityPaused = !activityPaused;
            toggleBtn.textContent = activityPaused ? 'Resume' : 'Pause';
        });
    }
}

// Helper to prepend new activity event to the feed
function prependActivityEvent(event) {
    const container = document.getElementById('activity-feed');
    if (!container) return;

    // Check if this event already exists (by id and type)
    const existingIds = new Set();
    container.querySelectorAll('.activity-item').forEach(el => {
        const id = el.dataset.id;
        const type = el.dataset.type;
        if (id && type) existingIds.add(`${type}-${id}`);
    });

    const eventKey = `${event.type}-${event.id}`;
    if (existingIds.has(eventKey)) return; // Skip duplicates

    // Create new element and prepend
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = ActivityItem(event);
    const newEl = tempDiv.firstElementChild;
    if (newEl) {
        newEl.dataset.id = event.id;
        newEl.dataset.type = event.type;
        newEl.classList.add('activity-item-new');
        container.insertBefore(newEl, container.firstChild);

        // W4: Wire click handler on the new activity item
        newEl.addEventListener('click', () => {
            const type = (newEl.dataset.type || '').toUpperCase();
            if (type === 'INC' || type === 'INCIDENT') {
                navigate('#/incidents');
            } else if (type === 'SCAN') {
                navigate('#/scans');
            } else {
                navigate('#/commands');
            }
        });

        // Remove "new" animation class after animation completes
        setTimeout(() => newEl.classList.remove('activity-item-new'), 500);

        // Keep only last 50 items
        while (container.children.length > 50) {
            container.removeChild(container.lastChild);
        }
    }
}

async function fetchAndRenderActivity() {
    const container = document.getElementById('activity-feed');
    if (!container) return;

    const offset = (activityState.page - 1) * ACTIVITY_PAGE_SIZE;
    const params = { limit: ACTIVITY_PAGE_SIZE, offset };
    if (activityState.type) params.event_type = activityState.type;
    if (activityState.severity) params.severity = activityState.severity;

    const result = await api('/api/activity/feed', { params });
    if (!result) return; // Keep existing content on error

    // Support both old array format and new paginated format
    let events, total;
    if (Array.isArray(result)) {
        events = result;
        total = result.length;
    } else {
        events = result.events || result.items || [];
        total = result.total || events.length;
    }

    if (events.length === 0) {
        container.innerHTML = EmptyState('No activity matching filters.', 'Try changing the filters or check back later.', 'activity');
        const paginationContainer = document.getElementById('activity-pagination');
        if (paginationContainer) paginationContainer.innerHTML = '';
        return;
    }

    container.innerHTML = events.map(e => ActivityItem(e)).join('');

    // W4: Wire clickable activity items for drill-down navigation
    wireActivityItemNavigation(container);

    // Render pagination with "Page X of Y" label
    const totalPages = Math.max(1, Math.ceil(total / ACTIVITY_PAGE_SIZE));
    const paginationContainer = document.getElementById('activity-pagination');
    if (paginationContainer) {
        const pageInfo = totalPages > 1
            ? `<div class="activity-page-info">Page ${escapeHtml(String(activityState.page))} of ${escapeHtml(String(totalPages))}</div>`
            : '';
        paginationContainer.innerHTML = pageInfo + Pagination(activityState.page, totalPages, '__activityGoToPage');
    }
}


// -- Config -----------------------------------------------------------------

async function renderConfig() {
    const page = getPageContent();
    page.innerHTML = `<h1>Configuration <span class="badge-admin">Admin</span></h1><div id="config-content">${Spinner()}</div>`;

    const config = await api('/api/config/summary');
    const container = document.getElementById('config-content');
    if (!config) {
        container.innerHTML = EmptyState('Failed to load configuration.', '', 'settings-2');
        return;
    }

    function statusBadge(value, onLabel = 'Enabled', offLabel = 'Disabled') {
        if (value === true || value === 'enforce') {
            return `<span class="config-badge config-badge-on">${escapeHtml(onLabel)}</span>`;
        }
        if (value === 'audit' || value === 'monitor') {
            return `<span class="config-badge config-badge-warn">${escapeHtml(String(value).toUpperCase())}</span>`;
        }
        return `<span class="config-badge config-badge-off">${escapeHtml(offLabel)}</span>`;
    }

    function boolIcon(val) {
        return val ? '<span class="config-check">&#10003;</span>' : '<span class="config-cross">&#10007;</span>';
    }

    const mode = config.mode || 'enforce';
    const rt = config.risk_thresholds || {};
    const tierColors = { free: '#94a3b8', pro: '#3b82f6', pro_plus: '#39D2C0', unlimited: '#39D2C0' };
    const tierNames = { free: 'FREE', pro: 'PRO', pro_plus: 'PRO+', unlimited: 'UNLIMITED' };
    const bt = config.billing_tier || 'free';
    const tc = tierColors[bt] || '#94a3b8';
    const tn = tierNames[bt] || bt.toUpperCase();

    container.innerHTML = `<div class="config-sections">
    <div class="config-section">
        <h3 class="config-section-title">Security Engine</h3>
        <div class="config-grid">
            <div class="config-item"><span class="config-label">Mode</span>${statusBadge(mode, mode.toUpperCase(), 'DISABLED')}</div>
            <div class="config-item"><span class="config-label">Block Threshold</span><span class="config-val">&ge; ${rt.block ?? 80}</span></div>
            <div class="config-item"><span class="config-label">Warn Threshold</span><span class="config-val">&ge; ${rt.warn ?? 40}</span></div>
            <div class="config-item"><span class="config-label">Chain Hashing</span>${boolIcon(config.chain_hashing)}</div>
        </div>
    </div>
    <div class="config-section">
        <h3 class="config-section-title">Sandbox</h3>
        <div class="config-grid">
            <div class="config-item"><span class="config-label">Status</span>${statusBadge(config.sandbox_enabled)}</div>
            <div class="config-item"><span class="config-label">Timeout</span><span class="config-val">${config.sandbox_timeout ?? 30}s</span></div>
        </div>
    </div>
    <div class="config-section">
        <h3 class="config-section-title">LLM Analysis</h3>
        <div class="config-grid">
            <div class="config-item"><span class="config-label">Status</span>${statusBadge(config.llm_enabled)}</div>
            <div class="config-item"><span class="config-label">Model</span><span class="config-val">${config.llm_model ? escapeHtml(config.llm_model) : '&mdash;'}</span></div>
        </div>
    </div>
    <div class="config-section">
        <h3 class="config-section-title">Rules</h3>
        <div class="config-grid">
            <div class="config-item"><span class="config-label">Whitelist</span><span class="config-val">${config.whitelist_count ?? 0} commands</span></div>
            <div class="config-item"><span class="config-label">Blacklist</span><span class="config-val">${config.blacklist_count ?? 0} commands</span></div>
            <div class="config-item"><span class="config-label">Protected Paths</span><span class="config-val">${config.protected_paths_count ?? 0} paths</span></div>
            <div class="config-item"><span class="config-label">Secret Patterns</span><span class="config-val">${config.secret_patterns_count ?? 0} patterns</span></div>
        </div>
    </div>
    <div class="config-section">
        <h3 class="config-section-title">Billing</h3>
        <div class="config-grid">
            <div class="config-item"><span class="config-label">Tier</span><span class="tier-badge" style="background:${tc}20;color:${tc};border:1px solid ${tc}40">${tn}</span></div>
        </div>
    </div>
</div>`;
}

// -- Health -----------------------------------------------------------------

async function renderHealth() {
    const page = getPageContent();
    page.innerHTML = `<h1>System Health</h1><div id="health-content">${Spinner()}</div>`;

    const health = await api('/api/health');
    const container = document.getElementById('health-content');
    if (!health) {
        container.innerHTML = EmptyState('Failed to load health status.', '', 'heart-pulse');
        return;
    }

    renderHealthContent(health, container);
}

function renderHealthContent(health, container) {
    const statusColor = health.status === 'ok' || health.status === 'healthy'
        ? 'var(--color-allow)' : health.status === 'degraded'
        ? 'var(--color-warn)' : 'var(--color-block)';

    const uptimeSec = health.uptime_seconds || 0;
    const uptimeStr = uptimeSec >= 86400
        ? Math.floor(uptimeSec / 86400) + 'd ' + Math.floor((uptimeSec % 86400) / 3600) + 'h'
        : uptimeSec >= 3600
        ? Math.floor(uptimeSec / 3600) + 'h ' + Math.floor((uptimeSec % 3600) / 60) + 'm'
        : uptimeSec >= 60 ? Math.floor(uptimeSec / 60) + 'm ' + (uptimeSec % 60) + 's'
        : uptimeSec + 's';

    const comp = health.components || {};
    const isAdmin = usageCache?.is_admin === true;

    // --- Database component ---
    const db = comp.database || {};
    const dbBody = `<div class="health-meta-grid">
        <div class="health-meta-item"><span class="health-meta-label">Response Time</span><span class="health-meta-value">${escapeHtml(db.response_ms !== undefined ? db.response_ms.toFixed(1) + 'ms' : '-')}</span></div>
    </div>`;

    // --- Disk component ---
    const disk = comp.disk || {};
    const diskPct = disk.disk_usage_pct || 0;
    const diskBody = `<div class="health-meta-grid">
        <div class="health-meta-item"><span class="health-meta-label">DB Size</span><span class="health-meta-value">${escapeHtml(disk.db_size_mb !== undefined ? disk.db_size_mb.toFixed(1) + ' MB' : '-')}</span></div>
        <div class="health-meta-item"><span class="health-meta-label">Disk Free</span><span class="health-meta-value">${escapeHtml(disk.disk_free_mb !== undefined ? (disk.disk_free_mb / 1024).toFixed(1) + ' GB' : '-')}</span></div>
        <div class="health-meta-item"><span class="health-meta-label">Disk Total</span><span class="health-meta-value">${escapeHtml(disk.disk_total_mb !== undefined ? (disk.disk_total_mb / 1024).toFixed(1) + ' GB' : '-')}</span></div>
    </div>
    ${HealthProgressBar(diskPct)}`;

    // --- Chain integrity component ---
    const chain = comp.chain_integrity || {};
    const chainTables = chain.tables || {};
    const chainRows = Object.entries(chainTables).map(([table, info]) => {
        const valid = info.valid;
        const entries = info.entries ?? 0;
        const icon = valid ? '<span class="health-check-icon health-check-icon--ok" aria-label="Valid">&#10003;</span>'
            : '<span class="health-check-icon health-check-icon--error" aria-label="Invalid">&#10007;</span>';
        return `<tr>
            <td>${icon}</td>
            <td>${escapeHtml(table)}</td>
            <td>${escapeHtml(String(entries))} entries</td>
        </tr>`;
    }).join('');
    const chainBody = Object.keys(chainTables).length > 0
        ? `<table class="health-chain-table"><thead><tr><th></th><th>Table</th><th>Entries</th></tr></thead><tbody>${chainRows}</tbody></table>`
        : '<p class="text-muted">No chain data available.</p>';

    // --- Services component ---
    const smtp = comp.smtp || {};
    const stripe = comp.stripe || {};
    const oauth = comp.google_oauth || {};

    function serviceItem(name, status, detail) {
        const isOk = status === 'ok' || status === 'healthy' || status === 'configured';
        const icon = isOk
            ? '<span class="health-check-icon health-check-icon--ok" aria-label="OK">&#10003;</span>'
            : '<span class="health-check-icon health-check-icon--error" aria-label="Error">&#10007;</span>';
        return `<div class="health-service-item">${icon} <span class="health-service-name">${escapeHtml(name)}</span> <span class="health-service-detail">${escapeHtml(detail)}</span></div>`;
    }

    const smtpDetail = smtp.host ? `host: ${smtp.host}` : (smtp.status || 'unchecked');
    const stripeDetail = stripe.webhook_configured ? 'webhook: configured' : (stripe.status || 'unchecked');
    const oauthDetail = oauth.status || 'unchecked';

    const servicesBody = `<div class="health-services-list">
        ${serviceItem('SMTP', smtp.status, smtpDetail)}
        ${serviceItem('Stripe', stripe.status, stripeDetail)}
        ${serviceItem('Google OAuth', oauth.status, oauthDetail)}
    </div>`;

    // --- Admin buttons ---
    const refreshBtn = '<button class="btn btn-sm" id="health-refresh-btn" aria-label="Refresh health data">Refresh</button>';
    const chainBtn = isAdmin
        ? '<button class="btn btn-sm btn-primary" id="health-verify-chains-btn" aria-label="Verify audit chains">Verify Chains</button>'
        : '';

    container.innerHTML = `<div class="health-actions">
    ${refreshBtn}
    ${chainBtn}
</div>
<div class="stat-grid health-stat-grid">
    ${StatCard(health.status || 'unknown', 'Status', statusColor)}
    ${StatCard(health.version || '-', 'Version')}
    ${StatCard(uptimeStr, 'Uptime')}
</div>
<div class="health-components-grid">
    ${HealthComponent('Database', db.status, dbBody)}
    ${HealthComponent('Disk', disk.status, diskBody)}
    ${HealthComponent('Chain Integrity', chain.status, chainBody)}
    ${HealthComponent('Services', 'ok', servicesBody)}
</div>
<div id="health-chain-detail"></div>`;

    // Wire refresh button
    const refreshEl = document.getElementById('health-refresh-btn');
    if (refreshEl) {
        refreshEl.addEventListener('click', async () => {
            refreshEl.disabled = true;
            refreshEl.textContent = 'Refreshing...';
            const freshHealth = await api('/api/health');
            if (freshHealth) {
                renderHealthContent(freshHealth, container);
                showToast('Health data refreshed.', 'success');
            } else {
                showToast('Failed to refresh health data.', 'error');
                refreshEl.disabled = false;
                refreshEl.textContent = 'Refresh';
            }
        });
    }

    // Wire chain verification button (admin only)
    const chainBtnEl = document.getElementById('health-verify-chains-btn');
    if (chainBtnEl) {
        chainBtnEl.addEventListener('click', async () => {
            const detailContainer = document.getElementById('health-chain-detail');
            if (!detailContainer) return;
            chainBtnEl.disabled = true;
            chainBtnEl.textContent = 'Verifying...';
            detailContainer.innerHTML = Spinner();

            try {
                const chainResult = await api('/api/health/chain');
                if (chainResult) {
                    const tables = chainResult.tables || chainResult;
                    const tableEntries = typeof tables === 'object' && !Array.isArray(tables)
                        ? Object.entries(tables)
                        : [];

                    if (tableEntries.length > 0) {
                        const rows = tableEntries.map(([tableName, info]) => {
                            const valid = info.valid !== undefined ? info.valid : info.status === 'ok';
                            const entries = info.entries ?? info.total ?? '-';
                            const broken = info.broken ?? info.invalid ?? 0;
                            const icon = valid
                                ? '<span class="health-check-icon health-check-icon--ok">&#10003;</span>'
                                : '<span class="health-check-icon health-check-icon--error">&#10007;</span>';
                            return `<tr>
                                <td>${icon}</td>
                                <td>${escapeHtml(tableName)}</td>
                                <td>${escapeHtml(String(entries))}</td>
                                <td>${escapeHtml(String(broken))}</td>
                                <td>${valid ? '<span class="text-allow">Valid</span>' : '<span class="text-block">Broken</span>'}</td>
                            </tr>`;
                        }).join('');

                        detailContainer.innerHTML = `<section class="health-component health-chain-detail-section">
                            <div class="health-component-header">
                                <h3 class="health-component-title">Chain Verification Results</h3>
                            </div>
                            <div class="health-component-body">
                                <table class="health-chain-table">
                                    <thead><tr><th></th><th>Table</th><th>Entries</th><th>Broken</th><th>Status</th></tr></thead>
                                    <tbody>${rows}</tbody>
                                </table>
                            </div>
                        </section>`;
                    } else {
                        detailContainer.innerHTML = `<p class="text-muted">Chain verification returned no table data.</p>`;
                    }
                } else {
                    detailContainer.innerHTML = `<p class="text-muted">Chain verification failed.</p>`;
                }
            } catch (e) {
                detailContainer.innerHTML = `<p class="text-muted">Chain verification error: ${escapeHtml(e.message)}</p>`;
            }

            chainBtnEl.disabled = false;
            chainBtnEl.textContent = 'Verify Chains';
        });
    }
}

// -- Setup (Connect Your AI) ------------------------------------------------

async function renderSetup() {
    const page = getPageContent();
    page.innerHTML = `<h1>Connect Your AI Agent</h1><div id="setup-content">${Spinner()}</div>`;

    // Fetch settings to check if API key exists
    const settings = await api('/api/settings');
    const hasKey = settings && settings.has_api_key;

    const container = document.getElementById('setup-content');
    container.innerHTML = `
<div class="setup-page">
    <!-- Quick Start -->
    <section class="setup-section">
        <h2>Quick Start</h2>
        <p class="setup-desc">Get ShieldPilot protecting your AI agent in 3 steps.</p>

        <div class="setup-steps">
            <div class="setup-step">
                <div class="setup-step-number">1</div>
                <div class="setup-step-content">
                    <h3>Install ShieldPilot</h3>
                    <p>Install the package from PyPI</p>
                    <div class="setup-code">
                        <code>pip install shieldpilot</code>
                        <button class="setup-copy-btn" data-copy="pip install shieldpilot" title="Copy">
                            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                        </button>
                    </div>
                </div>
            </div>

            <div class="setup-step">
                <div class="setup-step-number">2</div>
                <div class="setup-step-content">
                    <h3>Activate the Security Hook</h3>
                    <p>Install the Claude Code PreToolUse hook that evaluates every command before execution</p>
                    <div class="setup-code">
                        <code>sentinel hook install</code>
                        <button class="setup-copy-btn" data-copy="sentinel hook install" title="Copy">
                            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                        </button>
                    </div>
                </div>
            </div>

            <div class="setup-step">
                <div class="setup-step-number">3</div>
                <div class="setup-step-content">
                    <h3>Start the Dashboard</h3>
                    <p>Launch the security monitoring dashboard</p>
                    <div class="setup-code">
                        <code>sentinel dashboard</code>
                        <button class="setup-copy-btn" data-copy="sentinel dashboard" title="Copy">
                            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- How It Works -->
    <section class="setup-section">
        <h2>How It Works</h2>
        <div class="setup-flow">
            <div class="setup-flow-step">
                <span class="setup-flow-icon">AI</span>
                <span class="setup-flow-label">Your AI Agent</span>
            </div>
            <span class="setup-flow-arrow">&rarr;</span>
            <div class="setup-flow-step">
                <span class="setup-flow-icon" style="color:#39D2C0;">&#9741;</span>
                <span class="setup-flow-label">ShieldPilot Hook</span>
            </div>
            <span class="setup-flow-arrow">&rarr;</span>
            <div class="setup-flow-step">
                <span class="setup-flow-icon" style="color:#F0883E;">8x</span>
                <span class="setup-flow-label">Risk Analyzers</span>
            </div>
            <span class="setup-flow-arrow">&rarr;</span>
            <div class="setup-flow-step">
                <span class="setup-flow-icon" style="color:#3FB950;">&#10003;</span>
                <span class="setup-flow-label">Allow / Warn / Block</span>
            </div>
        </div>
        <p class="setup-desc" style="margin-top:16px;">Every command your AI agent tries to execute is intercepted, analyzed by 8 specialized risk analyzers, and either allowed, flagged for review, or blocked. All activity is logged to this dashboard.</p>
    </section>

    <!-- Platform Adapters -->
    <section class="setup-section">
        <h2>Platform Adapters</h2>
        <p class="setup-desc">ShieldPilot auto-detects your AI platform and uses the right protocol. Three adapters are supported out of the box.</p>

        <div class="setup-tools">
            <div class="setup-tool">
                <strong>Claude Code</strong>
                <span class="badge" style="margin-left:8px;font-size:11px;background:#39D2C0;color:#0D1117;">Native</span>
                <p>Registers as a <code>PreToolUse</code> hook. Reads <code>tool_name</code> + <code>tool_input</code> JSON from stdin, responds with <code>hookSpecificOutput</code>.</p>
                <div class="setup-code" style="margin-top:8px;">
                    <code>sentinel hook install</code>
                    <button class="setup-copy-btn" data-copy="sentinel hook install" title="Copy">
                        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                    </button>
                </div>
            </div>

            <div class="setup-tool">
                <strong>OpenClaw</strong>
                <span class="badge" style="margin-left:8px;font-size:11px;background:#F0883E;color:#0D1117;">Event-Based</span>
                <p>Intercepts <code>preToolExecution</code> events. Tool names auto-map (<code>shell</code>&rarr;<code>Bash</code>, <code>writeFile</code>&rarr;<code>Write</code>, etc.).</p>
                <div class="setup-code" style="margin-top:8px;">
                    <code>echo '{"event":"preToolExecution","tool":{"name":"shell","parameters":{"command":"ls"}}}' | sentinel run --stdin</code>
                    <button class="setup-copy-btn" data-copy='echo &apos;{"event":"preToolExecution","tool":{"name":"shell","parameters":{"command":"ls"}}}&apos; | sentinel run --stdin' title="Copy">
                        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                    </button>
                </div>
                <p style="margin-top:8px;font-size:13px;color:#8B949E;">Response: <code>{"action":"allow"}</code> or <code>{"action":"deny","message":"...","riskScore":85}</code></p>
            </div>

            <div class="setup-tool">
                <strong>Generic / REST API</strong>
                <span class="badge" style="margin-left:8px;font-size:11px;background:#8B949E;color:#0D1117;">Universal</span>
                <p>Send any JSON with a <code>command</code> field via stdin or the REST API. Works with any AI tool.</p>
                <div class="setup-code" style="margin-top:8px;">
                    <code>echo '{"command":"ls -la","tool":"Bash"}' | sentinel run --stdin</code>
                    <button class="setup-copy-btn" data-copy='echo &apos;{"command":"ls -la","tool":"Bash"}&apos; | sentinel run --stdin' title="Copy">
                        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                    </button>
                </div>
                <p style="margin-top:8px;font-size:13px;color:#8B949E;">Response: <code>{"allowed":true,"risk_score":0,"reasons":[]}</code></p>
            </div>
        </div>
    </section>

    <!-- Developer Quickstart -->
    <section class="setup-section">
        <h2>Developer Quickstart</h2>
        <p class="setup-desc">From zero to protected in under 5 minutes.</p>

        <div class="setup-steps">
            <div class="setup-step">
                <div class="setup-step-number">1</div>
                <div class="setup-step-content">
                    <h3>Install &amp; Initialize</h3>
                    <div class="setup-code">
                        <code>pip install shieldpilot &amp;&amp; sentinel init</code>
                        <button class="setup-copy-btn" data-copy="pip install shieldpilot && sentinel init" title="Copy">
                            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                        </button>
                    </div>
                    <p style="margin-top:6px;font-size:13px;color:#8B949E;">Creates <code>sentinel.yaml</code> with safe defaults (mode: enforce, thresholds: warn=40, block=80).</p>
                </div>
            </div>

            <div class="setup-step">
                <div class="setup-step-number">2</div>
                <div class="setup-step-content">
                    <h3>Install the Hook</h3>
                    <div class="setup-code">
                        <code>sentinel hook install</code>
                        <button class="setup-copy-btn" data-copy="sentinel hook install" title="Copy">
                            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                        </button>
                    </div>
                    <p style="margin-top:6px;font-size:13px;color:#8B949E;">Registers ShieldPilot as a Claude Code PreToolUse hook. For other platforms, use <code>sentinel run --stdin</code>.</p>
                </div>
            </div>

            <div class="setup-step">
                <div class="setup-step-number">3</div>
                <div class="setup-step-content">
                    <h3>Test the Hook</h3>
                    <div class="setup-code">
                        <code>sentinel hook test</code>
                        <button class="setup-copy-btn" data-copy="sentinel hook test" title="Copy">
                            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                        </button>
                    </div>
                    <p style="margin-top:6px;font-size:13px;color:#8B949E;">Runs a safe test command through the risk engine and shows the analysis result.</p>
                </div>
            </div>

            <div class="setup-step">
                <div class="setup-step-number">4</div>
                <div class="setup-step-content">
                    <h3>Verify &amp; Monitor</h3>
                    <div class="setup-code">
                        <code>sentinel status &amp;&amp; sentinel dashboard</code>
                        <button class="setup-copy-btn" data-copy="sentinel status && sentinel dashboard" title="Copy">
                            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                        </button>
                    </div>
                    <p style="margin-top:6px;font-size:13px;color:#8B949E;">Check hook status, then launch the dashboard at <code>http://localhost:8420</code>.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- How ShieldPilot Protects You -->
    <section class="setup-section">
        <h2>How ShieldPilot Protects You</h2>
        <div class="info-box">
            <p>ShieldPilot runs 8 security analyzers on every command in real-time. Here's what to expect:</p>
            <ul>
                <li>Commands are scored 0&ndash;100 and automatically allowed, flagged, or blocked based on your configured thresholds.</li>
                <li>All decisions are logged in a tamper-evident audit trail for forensic review.</li>
                <li>No security tool catches 100% of threats &mdash; ShieldPilot adds an important layer, and works best alongside good security practices.</li>
            </ul>
            <p class="info-box-footer">See our <a href="#/legal/terms">Terms of Service</a> for full details.</p>
        </div>
    </section>

    <!-- API Key -->
    <section class="setup-section">
        <h2>API Key</h2>
        <p class="setup-desc">Use an API key to authenticate REST API requests from your AI tools.</p>
        <div id="api-key-container">
            ${hasKey ? `
                <div class="setup-api-key-display">
                    <code class="setup-api-key-masked">sk-****...****</code>
                    <button class="btn btn-sm btn-danger" id="revoke-api-key-btn">Revoke Key</button>
                </div>
                <p class="setup-hint">Your API key was shown only once when generated. If you lost it, revoke and generate a new one.</p>
            ` : `
                <button class="btn btn-sm btn-primary" id="generate-api-key-btn">Generate API Key</button>
                <p class="setup-hint">The key will be shown only once. Store it securely.</p>
            `}
        </div>
        <div id="api-key-result" style="display:none;"></div>

        <h3 class="setup-subsection-title" style="margin-top:20px;">Example Usage</h3>
        <div class="setup-code">
            <code>curl -H "X-API-Key: YOUR_KEY" http://localhost:8420/api/stats</code>
        </div>
    </section>
</div>`;

    // Wire copy buttons
    container.querySelectorAll('.setup-copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const text = btn.getAttribute('data-copy');
            navigator.clipboard.writeText(text).then(() => {
                btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="#3FB950"><path d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z"/></svg>';
                setTimeout(() => {
                    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>';
                }, 2000);
            });
        });
    });

    // Wire API key generation
    const genBtn = document.getElementById('generate-api-key-btn');
    if (genBtn) {
        genBtn.addEventListener('click', async () => {
            genBtn.disabled = true;
            genBtn.textContent = 'Generating...';
            const result = await api('/api/settings/api-key', { method: 'POST' });
            if (result && result.api_key) {
                const resultEl = document.getElementById('api-key-result');
                resultEl.style.display = 'block';
                resultEl.innerHTML = `
                    <div class="setup-api-key-revealed">
                        <strong>Your API Key (shown once):</strong>
                        <div class="setup-code" style="margin-top:8px;">
                            <code>${escapeHtml(result.api_key)}</code>
                            <button class="setup-copy-btn" data-copy="${escapeHtml(result.api_key)}" title="Copy">
                                <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/></svg>
                            </button>
                        </div>
                        <p class="setup-hint" style="color:#F85149;">Save this key now. It will not be shown again.</p>
                    </div>`;
                // Wire the new copy button
                resultEl.querySelector('.setup-copy-btn').addEventListener('click', function() {
                    navigator.clipboard.writeText(this.getAttribute('data-copy'));
                    showToast('API key copied!', 'success');
                });
                genBtn.style.display = 'none';
            } else {
                genBtn.disabled = false;
                genBtn.textContent = 'Generate API Key';
            }
        });
    }

    // Wire API key revoke
    const revokeBtn = document.getElementById('revoke-api-key-btn');
    if (revokeBtn) {
        revokeBtn.addEventListener('click', async () => {
            if (!confirm('Revoke your API key? Any tools using it will lose access.')) return;
            const result = await api('/api/settings/api-key', { method: 'DELETE' });
            if (result) {
                showToast('API key revoked', 'success');
                renderSetup();  // Re-render page
            }
        });
    }
}

// -- Library ----------------------------------------------------------------

async function renderLibrary() {
    const page = getPageContent();
    page.innerHTML = `<h1>Library</h1><div class="library-layout"><aside class="library-sidebar" id="library-sidebar">${Spinner()}</aside><div class="library-main" id="library-main">${Spinner()}</div></div>`;

    const isAdmin = usageCache?.is_admin === true;

    // Load topics for sidebar
    const topics = await api('/api/library/topics') || [];
    const sidebar = document.getElementById('library-sidebar');

    let activeTopic = null;

    function renderTopicNav() {
        const topicItems = topics.map(t =>
            `<button class="library-topic-btn ${activeTopic === t.id ? 'active' : ''}" data-topic-id="${t.id}">${escapeHtml(t.name)}</button>`
        ).join('');
        sidebar.innerHTML = `<div class="library-topic-nav">
            <button class="library-topic-btn ${activeTopic === null ? 'active' : ''}" data-topic-id="">All</button>
            ${topicItems}
        </div>
        <div class="library-search">
            <input type="text" id="library-search-input" class="input" placeholder="Search library..." />
        </div>`;

        sidebar.querySelectorAll('.library-topic-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tid = btn.getAttribute('data-topic-id');
                activeTopic = tid ? parseInt(tid) : null;
                renderTopicNav();
                loadItems();
            });
        });

        const searchInput = document.getElementById('library-search-input');
        let debounceTimer;
        if (searchInput) {
            searchInput.addEventListener('input', () => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => loadItems(searchInput.value.trim()), 300);
            });
        }
    }

    let allItems = [];

    async function loadItems(searchQuery = '') {
        const main = document.getElementById('library-main');
        if (!main) return;
        main.innerHTML = Spinner();

        const params = new URLSearchParams({ limit: '50', offset: '0' });
        if (activeTopic) params.set('topic_id', String(activeTopic));

        const url = isAdmin ? `/api/library/admin?${params}` : `/api/library?${params}`;
        const result = await api(url);
        const items = Array.isArray(result) ? result : (result?.items || []);

        // Client-side search filter
        allItems = searchQuery
            ? items.filter(i => (i.title + ' ' + (i.short_preview || '')).toLowerCase().includes(searchQuery.toLowerCase()))
            : items;

        if (allItems.length === 0) {
            main.innerHTML = EmptyState('No items found.', activeTopic ? 'Try a different topic.' : 'Check back soon for new content.', 'book-open');
            return;
        }

        main.innerHTML = `<div class="library-grid">${allItems.map((item, i) => renderLibraryCard(item, i)).join('')}</div>`;

        // Wire card clicks
        main.querySelectorAll('.library-card').forEach(card => {
            card.addEventListener('click', () => {
                const idx = parseInt(card.getAttribute('data-index'));
                showLibraryDetail(allItems[idx]);
            });
        });
    }

    function renderLibraryCard(item, index) {
        const locked = item.full_content_locked;
        const typeBadge = item.type === 'skill' ? 'Skill' : 'Prompt';
        const tags = (item.tags || []).slice(0, 3).map(t => `<span class="library-tag">${escapeHtml(t)}</span>`).join('');

        return `<div class="library-card ${locked ? 'library-card-locked' : ''}" data-index="${index}" tabindex="0" role="button" aria-label="View ${escapeHtml(item.title)}">
            <div class="library-card-header">
                <span class="library-type-badge library-type-${escapeHtml(item.type)}">${escapeHtml(typeBadge)}</span>
                ${locked ? '<span class="library-lock-icon">&#x1F512;</span>' : ''}
            </div>
            <h4 class="library-card-title">${escapeHtml(item.title)}</h4>
            <p class="library-card-preview">${escapeHtml(item.short_preview || '')}</p>
            <div class="library-card-tags">${tags}</div>
            ${locked ? '<div class="library-card-overlay"><span>PRO</span></div>' : ''}
        </div>`;
    }

    function showLibraryDetail(item) {
        const main = document.getElementById('library-main');
        if (!main) return;

        if (item.full_content_locked) {
            main.innerHTML = `<div class="library-detail">
                <button class="btn btn-sm library-back-btn" id="library-back">&#x2190; Back</button>
                <h2>${escapeHtml(item.title)}</h2>
                <p class="text-muted">${escapeHtml(item.short_preview || '')}</p>
                <div class="pro-feature-lock">
                    <div class="pro-feature-lock-icon"><i data-lucide="lock" style="width:48px;height:48px;color:var(--text-muted)"></i></div>
                    <p class="pro-feature-lock-text">Full content is available on the Pro plan</p>
                    <a href="#/pricing" class="btn btn-primary">Upgrade to Pro</a>
                </div>
            </div>`;
        } else {
            const content = item.full_content || item.short_preview || '';
            const tags = (item.tags || []).map(t => `<span class="library-tag">${escapeHtml(t)}</span>`).join('');
            main.innerHTML = `<div class="library-detail">
                <button class="btn btn-sm library-back-btn" id="library-back">&#x2190; Back</button>
                <div class="library-detail-header">
                    <h2>${escapeHtml(item.title)}</h2>
                    <button class="btn btn-sm" id="library-copy-btn">Copy to Clipboard</button>
                </div>
                <div class="library-detail-meta">
                    <span class="library-type-badge library-type-${escapeHtml(item.type)}">${escapeHtml(item.type === 'skill' ? 'Skill' : 'Prompt')}</span>
                    ${item.topic_name ? `<span class="text-muted">${escapeHtml(item.topic_name)}</span>` : ''}
                    <div class="library-card-tags">${tags}</div>
                </div>
                <div class="library-detail-content"><pre class="library-content-pre">${escapeHtml(content)}</pre></div>
            </div>`;

            const copyBtn = document.getElementById('library-copy-btn');
            if (copyBtn) {
                copyBtn.addEventListener('click', () => {
                    navigator.clipboard.writeText(content).then(() => {
                        showToast('Copied to clipboard!', 'success');
                        copyBtn.textContent = 'Copied!';
                        setTimeout(() => { copyBtn.textContent = 'Copy to Clipboard'; }, 2000);
                    }).catch(() => {
                        showToast('Failed to copy.', 'error');
                    });
                });
            }
        }

        // Re-init Lucide icons for the lock icon
        if (window.lucide) lucide.createIcons();

        const backBtn = document.getElementById('library-back');
        if (backBtn) {
            backBtn.addEventListener('click', () => {
                renderTopicNav();
                loadItems();
            });
        }
    }

    renderTopicNav();
    loadItems();
}

// -- Pricing ----------------------------------------------------------------

async function renderPricing() {
    const page = getPageContent();
    page.innerHTML = `<h1>Pricing <span class="badge-early-access">Early Access</span></h1>${Spinner()}`;

    // Check for checkout result in URL
    const hashParts = window.location.hash.split('?');
    const urlParams = new URLSearchParams(hashParts[1] || '');
    const checkoutResult = urlParams.get('checkout');

    const pricing = await api('/api/billing/pricing');
    if (!pricing) {
        page.innerHTML = `<h1>Pricing</h1>${EmptyState('Failed to load pricing.')}`;
        return;
    }

    const currentTier = pricing.current_tier;
    const tiers = pricing.tiers;

    // Success/cancel banner
    let banner = '';
    if (checkoutResult === 'success') {
        banner = `<div class="pricing-banner pricing-banner-success">
            <strong>Payment successful!</strong> Activating your subscription...
        </div>`;
        showToast('Payment successful! Activating your subscription...', 'success');
        let pollAttempts = 0;
        const pollTier = async () => {
            const usage = await fetchUsage();
            if (usage && usage.tier !== 'free') {
                const dn = usage.tier === 'pro_plus' ? 'Pro+' : usage.tier.charAt(0).toUpperCase() + usage.tier.slice(1);
                showToast(`Welcome to ${dn}! All features unlocked.`, 'success');
                render();
            } else if (pollAttempts < 10) {
                pollAttempts++;
                setTimeout(pollTier, 2000);
            } else {
                showToast('Subscription activated! Refresh if your plan hasn\'t updated.', 'info');
            }
        };
        pollTier();
    } else if (checkoutResult === 'cancel') {
        banner = `<div class="pricing-banner pricing-banner-cancel">
            Checkout was cancelled. No charges were made.
        </div>`;
    }

    // Human-readable benefit lists per tier
    const tierBenefits = {
        free: [
            'Up to 50 commands per day',
            '10 security scans per day',
            '1 day incident history',
            'Real-time threat detection',
            'Tamper-proof audit trail',
        ],
        pro: [
            'Everything in Free, plus:',
            '1,000 commands per day',
            '100 security scans per day',
            '30 day incident history',
            'Export reports (CSV & JSON)',
            'REST API access',
            'Full prompts & skills library',
        ],
        pro_plus: [
            'Everything in Pro, plus:',
            'Unlimited commands & scans',
            '90 day incident history',
            'AI-powered threat analysis',
            'Up to 5 API keys',
            'Priority support',
        ],
    };

    // Billing period state
    let isAnnual = false;

    function renderCards() {
        const tierOrder = ['free', 'pro', 'pro_plus'];
        return tierOrder.map(key => {
            const t = tiers[key];
            if (!t) return '';
            const isCurrent = currentTier === key;
            const isUpgrade = tierOrder.indexOf(key) > tierOrder.indexOf(currentTier);
            const isUnlimited = currentTier === 'unlimited';
            const currency = t.currency || '\u20AC';
            const benefits = tierBenefits[key] || [];

            // Price display
            const safeCurrency = escapeHtml(currency);
            let priceDisplay;
            if (t.price_monthly === 0) {
                priceDisplay = `<span class="pricing-amount">${safeCurrency}0</span><span class="pricing-period">/forever</span>`;
            } else if (isAnnual) {
                priceDisplay = `<span class="pricing-amount">${safeCurrency}${escapeHtml(String(t.price_annual))}</span><span class="pricing-period">/year</span>`;
            } else {
                priceDisplay = `<span class="pricing-amount">${safeCurrency}${escapeHtml(String(t.price_monthly))}</span><span class="pricing-period">/month</span>`;
            }

            // Annual savings badge
            let savingsBadge = '';
            if (isAnnual && t.price_monthly > 0) {
                const monthlyTotal = t.price_monthly * 12;
                const savingsPercent = Math.round((1 - t.price_annual / monthlyTotal) * 100);
                if (savingsPercent > 0) {
                    savingsBadge = `<span class="pricing-savings">Save ${savingsPercent}%</span>`;
                }
            }

            // Action button
            let actionButton = '';
            const priceKeySuffix = isAnnual ? 'annual' : 'monthly';
            if (isUnlimited) {
                actionButton = '<span class="pricing-current-label">Admin</span>';
            } else if (isCurrent) {
                actionButton = '<span class="pricing-current-label">Current Plan</span>';
            } else if (key === 'free') {
                actionButton = '';
            } else if (isUpgrade) {
                actionButton = `<button class="btn btn-primary pricing-btn" data-price-key="${escapeHtml(key)}_${priceKeySuffix}">
                    Upgrade to ${escapeHtml(t.name)}
                </button>
                <p class="checkout-consent-note">By subscribing, you agree that the service begins immediately. <a href="#/legal/withdrawal" class="tos-link">14-day cancellation policy</a></p>`;
            }

            const popularBadge = key === 'pro_plus' ? '<span class="pricing-popular">Best Value</span>' : '';

            // Benefits list
            const benefitItems = benefits.map((b, i) => {
                if (i === 0 && b.startsWith('Everything in')) {
                    return `<li class="pricing-feature pricing-includes-label">${escapeHtml(b)}</li>`;
                }
                return `<li class="pricing-feature"><span class="pricing-check">&#10003;</span> ${escapeHtml(b)}</li>`;
            }).join('');

            return `<div class="pricing-card ${isCurrent ? 'pricing-card-current' : ''} ${key === 'pro_plus' ? 'pricing-card-featured' : ''}">
                ${popularBadge}
                <h3 class="pricing-tier-name">${escapeHtml(t.name)}</h3>
                <p class="pricing-description">${escapeHtml(t.description || '')}</p>
                <div class="pricing-price">
                    ${priceDisplay}
                    ${savingsBadge}
                </div>
                <ul class="pricing-features">
                    ${benefitItems}
                </ul>
                ${actionButton}
            </div>`;
        }).join('');
    }

    // Manage subscription link (for paid users)
    const manageLink = (currentTier === 'pro' || currentTier === 'pro_plus')
        ? `<div class="pricing-manage">
            <button class="btn btn-sm" id="manage-subscription-btn">Manage Subscription</button>
            <span class="text-muted">Change plan, update payment method, or cancel</span>
        </div>`
        : '';

    function render() {
        page.innerHTML = `<h1>Pricing <span class="badge-early-access">Early Access</span></h1>
${banner}
<p class="pricing-subtitle">Choose the plan that fits your security needs.</p>
<div class="pricing-toggle-wrapper">
    <div class="pricing-toggle">
        <button class="pricing-toggle-option ${!isAnnual ? 'active' : ''}" data-period="monthly">Monthly</button>
        <button class="pricing-toggle-option ${isAnnual ? 'active' : ''}" data-period="annual">Annual</button>
    </div>
</div>
<div class="pricing-grid">${renderCards()}</div>
${manageLink}
<div class="pricing-extras">
    <div class="pricing-enterprise-cta">
        <span class="pricing-enterprise-icon">&#x1F3E2;</span>
        <div>
            <strong>Need custom deployment or dedicated support?</strong>
            <p>We offer tailored plans for teams and enterprises with custom SLAs, on-premise options, and dedicated onboarding.</p>
        </div>
        <a href="mailto:contact@shieldpilot.dev" class="btn btn-sm">Contact Us</a>
    </div>
    <div class="pricing-booster-teaser">
        <span class="pricing-booster-icon">&#x26A1;</span>
        <div>
            <strong>Just need a little more today?</strong>
            <p>Command Booster &mdash; &euro;4.99 for +500 commands (expires at midnight UTC)</p>
        </div>
        <button class="btn btn-sm btn-outline" id="pricing-buy-booster">Buy Booster</button>
    </div>
</div>
<div class="pricing-comparison">
    <h3>Feature Comparison</h3>
    <table class="pricing-table">
        <thead><tr>
            <th>Feature</th><th>Free</th><th>Pro</th><th>Pro+</th>
        </tr></thead>
        <tbody>
            <tr><td>Commands / day</td><td>50</td><td>1,000</td><td>Unlimited</td></tr>
            <tr><td>Scans / day</td><td>10</td><td>100</td><td>Unlimited</td></tr>
            <tr><td>History retention</td><td>1 day</td><td>30 days</td><td>90 days</td></tr>
            <tr><td>AI / LLM analysis</td><td>&mdash;</td><td>&mdash;</td><td>&#10003;</td></tr>
            <tr><td>Export (CSV / JSON)</td><td>&mdash;</td><td>&#10003;</td><td>&#10003;</td></tr>
            <tr><td>REST API access</td><td>&mdash;</td><td>&#10003;</td><td>&#10003;</td></tr>
            <tr><td>Prompts &amp; Skills Library</td><td>Preview</td><td>Full</td><td>Full</td></tr>
            <tr><td>Priority support</td><td>&mdash;</td><td>&mdash;</td><td>&#10003;</td></tr>
        </tbody>
    </table>
</div>
<p class="pricing-disclaimer">
    Prices include applicable VAT. Features and pricing may change during Early Access.
    Cancel anytime. See <a href="#/legal/terms">Terms of Service</a>.
</p>`;

        // Wire toggle
        page.querySelectorAll('.pricing-toggle-option').forEach(btn => {
            btn.addEventListener('click', () => {
                isAnnual = btn.getAttribute('data-period') === 'annual';
                render();
            });
        });

        // Wire upgrade buttons
        page.querySelectorAll('.pricing-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                btn.disabled = true;
                btn.textContent = 'Redirecting...';
                const priceKey = btn.getAttribute('data-price-key');
                const result = await api('/api/billing/checkout', {
                    method: 'POST',
                    body: { price_key: priceKey },
                });
                if (result && result.url) {
                    window.location.href = result.url;
                } else {
                    btn.disabled = false;
                    btn.textContent = 'Try Again';
                    showToast('Failed to start checkout. Is Stripe configured?', 'error');
                }
            });
        });

        // Wire manage subscription button
        const manageBtn = document.getElementById('manage-subscription-btn');
        if (manageBtn) {
            manageBtn.addEventListener('click', async () => {
                manageBtn.disabled = true;
                manageBtn.textContent = 'Opening...';
                const result = await api('/api/billing/portal', { method: 'POST' });
                if (result && result.url) {
                    window.location.href = result.url;
                } else {
                    manageBtn.disabled = false;
                    manageBtn.textContent = 'Manage Subscription';
                }
            });
        }

        // Wire booster button on pricing page
        const boosterBtn = document.getElementById('pricing-buy-booster');
        if (boosterBtn) {
            boosterBtn.addEventListener('click', async () => {
                boosterBtn.disabled = true;
                boosterBtn.textContent = 'Redirecting...';
                const result = await api('/api/billing/booster', { method: 'POST' });
                if (result && result.checkout_url) {
                    window.location.href = result.checkout_url;
                } else {
                    boosterBtn.disabled = false;
                    boosterBtn.textContent = 'Buy Booster';
                    showToast('Failed to start booster checkout.', 'error');
                }
            });
        }
    }

    render();
}

// -- Settings ---------------------------------------------------------------

async function renderSettings() {
    const page = getPageContent();
    page.innerHTML = `<h1>Settings</h1><div id="settings-content">${Spinner()}</div>`;

    const settings = await api('/api/settings');
    const container = document.getElementById('settings-content');
    if (!settings) {
        container.innerHTML = EmptyState('Failed to load settings.');
        return;
    }

    const tierColors = {
        free: '#94a3b8', pro: '#3b82f6', pro_plus: '#39D2C0', enterprise: '#39D2C0', unlimited: '#39D2C0',
    };
    const tierColor = tierColors[settings.tier] || '#94a3b8';
    const tierDisplayNames = { pro_plus: 'Pro+', unlimited: 'Admin' };
    const tierName = escapeHtml(tierDisplayNames[settings.tier] || settings.tier.charAt(0).toUpperCase() + settings.tier.slice(1));
    const tierPricing = { pro: '\u20ac19.99/mo', pro_plus: '\u20ac29.99/mo' };

    const verifiedBadge = settings.email_verified
        ? '<span class="settings-badge settings-badge-verified">Verified</span>'
        : '<span class="settings-badge settings-badge-unverified">Not Verified</span>';

    const googleBadge = settings.has_google
        ? '<span class="settings-badge settings-badge-verified">Linked</span>'
        : '<span class="settings-badge settings-badge-unverified">Not Linked</span>';

    const createdAt = settings.created_at
        ? new Date(settings.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
        : '-';

    container.innerHTML = `
<div class="settings-grid">
    <!-- Profile Section -->
    <section class="settings-section">
        <h2>Profile</h2>
        <div class="settings-rows">
            <div class="settings-row">
                <span class="settings-label">Email</span>
                <span class="settings-value">${escapeHtml(settings.email || '-')}</span>
            </div>
            <div class="settings-row">
                <span class="settings-label">Username</span>
                <div class="settings-inline-form">
                    <input type="text" id="settings-username" class="settings-input" value="${escapeHtml(settings.username)}" />
                    <button class="btn btn-sm" id="save-username-btn">Save</button>
                </div>
            </div>
            <div class="settings-row">
                <span class="settings-label">Tier</span>
                <span class="settings-value"><span class="tier-badge" style="background: ${tierColor}20; color: ${tierColor}; border: 1px solid ${tierColor}40;">${tierName}</span></span>
            </div>
            <div class="settings-row">
                <span class="settings-label">Role</span>
                <span class="settings-value">${escapeHtml(settings.role)}</span>
            </div>
            <div class="settings-row">
                <span class="settings-label">Member Since</span>
                <span class="settings-value">${escapeHtml(createdAt)}</span>
            </div>
        </div>
    </section>

    <!-- Security Section -->
    <section class="settings-section">
        <h2>Security</h2>
        <div class="settings-rows">
            <div class="settings-row">
                <span class="settings-label">Email Verification</span>
                <span class="settings-value">${verifiedBadge}</span>
            </div>
            <div class="settings-row">
                <span class="settings-label">Google Account</span>
                <span class="settings-value">${googleBadge}</span>
            </div>
        </div>

        <h3 class="settings-subsection-title">Change Password</h3>
        <form id="change-password-form" class="settings-form">
            <div class="settings-form-field">
                <label for="current-password">Current Password</label>
                <input type="password" id="current-password" class="settings-input" placeholder="Enter current password" ${settings.has_password ? '' : 'disabled'} />
                ${!settings.has_password ? '<span class="settings-hint">No password set (OAuth-only account)</span>' : ''}
            </div>
            <div class="settings-form-field">
                <label for="new-password">New Password</label>
                <input type="password" id="new-password" class="settings-input" placeholder="At least 6 characters" />
            </div>
            <div class="settings-form-field">
                <label for="confirm-new-password">Confirm New Password</label>
                <input type="password" id="confirm-new-password" class="settings-input" placeholder="Confirm new password" />
            </div>
            <button type="submit" class="btn btn-sm btn-primary" id="change-password-btn">Update Password</button>
            <div class="settings-form-message" id="password-message"></div>
        </form>
    </section>

    <!-- Subscription Section -->
    ${(settings.has_subscription || settings.tier !== 'free') ? `
    <section class="settings-section">
        <h2>Subscription</h2>
        <div class="settings-rows">
            <div class="settings-row">
                <span class="settings-label">Current Plan</span>
                <span class="settings-value"><span class="tier-badge tier-${escapeHtml(settings.tier)}">${escapeHtml(tierDisplayNames[settings.tier] || settings.tier.charAt(0).toUpperCase() + settings.tier.slice(1))}</span>${tierPricing[settings.tier] ? ' <span class="text-muted">(' + tierPricing[settings.tier] + ')</span>' : ''}</span>
            </div>
            ${settings.subscription_status ? `
            <div class="settings-row">
                <span class="settings-label">Status</span>
                <span class="settings-value"><span class="settings-badge ${
                    settings.subscription_status === 'active' ? 'settings-badge-verified' :
                    settings.subscription_status === 'past_due' ? 'settings-badge-danger' :
                    'settings-badge-unverified'
                }">${
                    settings.cancel_at_period_end && settings.current_period_end ? 'Cancels on ' + formatPeriodDate(settings.current_period_end, 'soon') :
                    settings.cancel_at_period_end ? 'Cancellation pending' :
                    settings.subscription_status === 'active' ? 'Active' :
                    settings.subscription_status === 'past_due' ? 'Payment Issue' :
                    settings.subscription_status === 'canceled' ? 'Canceled' :
                    escapeHtml(settings.subscription_status.charAt(0).toUpperCase() + settings.subscription_status.slice(1))
                }</span></span>
            </div>` : ''}
            ${settings.current_period_end && !settings.cancel_at_period_end ? `
            <div class="settings-row">
                <span class="settings-label">Next billing date</span>
                <span class="settings-value">${formatPeriodDate(settings.current_period_end)}</span>
            </div>` : ''}
        </div>
        <button class="btn btn-sm btn-primary" id="manage-subscription-btn">Manage Subscription</button>
    </section>` : ''}

    <!-- Your Data (GDPR) -->
    <section class="settings-section">
        <h2>Your Data</h2>
        <div class="settings-danger-content">
            <div>
                <strong>Export Personal Data</strong>
                <p class="settings-danger-desc">Download all your personal data as JSON (GDPR Art. 15/20).</p>
            </div>
            <button class="btn btn-sm btn-primary" id="export-data-btn">Export My Data</button>
        </div>
    </section>

    <!-- Danger Zone -->
    ${!settings.is_super_admin ? `
    <section class="settings-section settings-danger-zone">
        <h2>Danger Zone</h2>
        <div class="settings-danger-content">
            <div>
                <strong>Delete Account</strong>
                <p class="settings-danger-desc">Permanently delete your account and all associated data. This action cannot be undone.</p>
            </div>
            <button class="btn btn-danger" id="delete-account-btn">Delete Account</button>
        </div>
    </section>
    ` : ''}
</div>`;

    // Wire username save
    document.getElementById('save-username-btn').addEventListener('click', async () => {
        const input = document.getElementById('settings-username');
        const newUsername = input.value.trim();
        if (!newUsername) return;

        const result = await api('/api/settings/username', {
            method: 'POST',
            body: { username: newUsername },
        });
        if (result) {
            showToast('Username updated!', 'success');
            // Update sidebar immediately
            const nameEl = document.querySelector('.user-name');
            const avatarEl = document.querySelector('.user-avatar');
            if (nameEl) nameEl.textContent = newUsername;
            if (avatarEl) avatarEl.textContent = newUsername.substring(0, 2).toUpperCase();
        }
    });

    // Wire password change
    document.getElementById('change-password-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const msgEl = document.getElementById('password-message');
        msgEl.textContent = '';
        msgEl.className = 'settings-form-message';

        const current = document.getElementById('current-password').value;
        const newPwd = document.getElementById('new-password').value;
        const confirm = document.getElementById('confirm-new-password').value;

        if (newPwd !== confirm) {
            msgEl.textContent = 'Passwords do not match';
            msgEl.className = 'settings-form-message error';
            return;
        }

        if (newPwd.length < 6) {
            msgEl.textContent = 'Password must be at least 6 characters';
            msgEl.className = 'settings-form-message error';
            return;
        }

        const result = await api('/api/settings/password', {
            method: 'POST',
            body: { current_password: current, new_password: newPwd },
        });

        if (result) {
            msgEl.textContent = 'Password updated successfully!';
            msgEl.className = 'settings-form-message success';
            document.getElementById('current-password').value = '';
            document.getElementById('new-password').value = '';
            document.getElementById('confirm-new-password').value = '';
        }
    });

    // Export personal data (GDPR)
    const exportBtn = document.getElementById('export-data-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', async () => {
            exportBtn.disabled = true;
            exportBtn.textContent = 'Exporting...';
            try {
                const token = localStorage.getItem('sentinel_token');
                const resp = await fetch('/api/account/export', {
                    headers: { 'Authorization': 'Bearer ' + token },
                });
                if (!resp.ok) throw new Error('Export failed');
                const blob = await resp.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'shieldpilot-data-export.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showToast('Data exported successfully', 'success');
            } catch {
                showToast('Failed to export data', 'error');
            } finally {
                exportBtn.disabled = false;
                exportBtn.textContent = 'Export My Data';
            }
        });
    }

    // Wire manage subscription
    const manageSubBtn = document.getElementById('manage-subscription-btn');
    if (manageSubBtn) {
        manageSubBtn.addEventListener('click', async () => {
            try {
                const resp = await fetch('/api/billing/portal', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('sentinel_token'), 'Content-Type': 'application/json' }
                });
                if (resp.ok) {
                    const data = await resp.json();
                    window.open(data.url, '_blank');
                } else {
                    showToast('Could not open subscription portal.', 'error');
                }
            } catch (e) {
                showToast('Failed to connect to billing portal.', 'error');
            }
        });
    }

    // Wire delete account
    const deleteBtn = document.getElementById('delete-account-btn');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', () => {
            showDeleteAccountModal();
        });
    }
}

function showDeleteAccountModal() {
    // Remove existing modal if any
    const existing = document.getElementById('delete-modal-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'delete-modal-overlay';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
        <div class="modal-content">
            <h2 class="modal-title">Delete Account</h2>
            <p class="modal-warning">This action is <strong>permanent</strong> and cannot be undone. All your data will be deleted.</p>
            <div class="modal-field">
                <label for="delete-confirm-password">Enter your password to confirm</label>
                <input type="password" id="delete-confirm-password" class="settings-input" placeholder="Your password" />
            </div>
            <div class="modal-error" id="delete-modal-error"></div>
            <div class="modal-actions">
                <button class="btn btn-sm" id="delete-modal-cancel">Cancel</button>
                <button class="btn btn-danger" id="delete-modal-confirm">Delete My Account</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    // Focus password input
    setTimeout(() => document.getElementById('delete-confirm-password').focus(), 100);

    // Cancel
    document.getElementById('delete-modal-cancel').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

    // Confirm delete
    document.getElementById('delete-modal-confirm').addEventListener('click', async () => {
        const password = document.getElementById('delete-confirm-password').value;
        const errorEl = document.getElementById('delete-modal-error');
        errorEl.textContent = '';

        if (!password) {
            errorEl.textContent = 'Password is required';
            return;
        }

        const confirmBtn = document.getElementById('delete-modal-confirm');
        confirmBtn.disabled = true;
        confirmBtn.textContent = 'Deleting...';

        try {
            const token = getToken();
            const res = await fetch('/api/settings/account', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token,
                },
                body: JSON.stringify({ password }),
            });

            if (!res.ok) {
                const data = await res.json();
                const msg = typeof data.detail === 'object' ? (data.detail.error || data.detail.message || JSON.stringify(data.detail)) : (data.detail || 'Failed to delete account');
                throw new Error(msg);
            }

            // Success — clear token and redirect
            clearToken();
            window.location.href = '/login?deleted=true';
        } catch (err) {
            errorEl.textContent = err.message;
            confirmBtn.disabled = false;
            confirmBtn.textContent = 'Delete My Account';
        }
    });
}

// ---------------------------------------------------------------------------
// Incident Badge (sidebar)
// ---------------------------------------------------------------------------

function updateIncidentBadge(count) {
    const badge = document.querySelector('.nav-badge');
    if (!badge) return;
    if (count && count > 0) {
        badge.textContent = count;
        badge.style.display = '';
    } else {
        badge.textContent = '';
        badge.style.display = 'none';
    }
}

// ---------------------------------------------------------------------------
// Usage & Tier Display
// ---------------------------------------------------------------------------

async function fetchUsage() {
    const usage = await api('/api/usage');
    if (usage) {
        usageCache = usage;
        updateTierBadge(usage);
        updateSecurityBanner(usage);
        updateNavLocks(usage);
        updateAdminNav(usage);
        updateSidebarUsage(usage);
        updateSidebarUpgrade(usage);
        updateUsageMeterBars(usage);
    }
    return usage;
}

/**
 * Update the usage meter bars in-place (if they exist on the current page).
 * Extracted so both fetchUsage() and updateDashboardStats() can call it.
 */
function updateUsageMeterBars(freshUsage) {
    const meterContainer = document.getElementById('usage-meter-container');
    if (!meterContainer || !freshUsage) return;

    const existingCard = meterContainer.querySelector('.usage-meter-card');
    if (existingCard && !freshUsage.is_admin) {
        const cmdPct = freshUsage.commands_limit > 0
            ? Math.min(100, Math.round((freshUsage.commands_used / freshUsage.commands_limit) * 100))
            : 0;
        const scanPct = freshUsage.scans_limit > 0
            ? Math.min(100, Math.round((freshUsage.scans_used / freshUsage.scans_limit) * 100))
            : 0;
        const cmdColor = cmdPct >= 90 ? 'var(--color-block)' : cmdPct >= 70 ? 'var(--color-warn)' : 'var(--color-allow)';
        const scanColor = scanPct >= 90 ? 'var(--color-block)' : scanPct >= 70 ? 'var(--color-warn)' : 'var(--color-allow)';

        const bars = meterContainer.querySelectorAll('.usage-bar-fill');
        const counts = meterContainer.querySelectorAll('.usage-count');

        if (bars[0]) {
            const oldWidth = bars[0].style.width;
            bars[0].style.width = `${cmdPct}%`;
            bars[0].style.backgroundColor = cmdColor;
            bars[0].classList.toggle('near-limit', cmdPct >= 80);
            if (oldWidth !== `${cmdPct}%`) {
                bars[0].classList.remove('usage-pulse');
                void bars[0].offsetWidth;
                bars[0].classList.add('usage-pulse');
            }
        }
        if (bars[1]) {
            const oldWidth = bars[1].style.width;
            bars[1].style.width = `${scanPct}%`;
            bars[1].style.backgroundColor = scanColor;
            bars[1].classList.toggle('near-limit', scanPct >= 80);
            if (oldWidth !== `${scanPct}%`) {
                bars[1].classList.remove('usage-pulse');
                void bars[1].offsetWidth;
                bars[1].classList.add('usage-pulse');
            }
        }
        if (counts[0]) {
            const newText = `${freshUsage.commands_used}/${freshUsage.commands_limit < 0 ? '∞' : freshUsage.commands_limit}`;
            if (counts[0].textContent !== newText) {
                counts[0].textContent = newText;
                counts[0].classList.add('usage-count-flash');
                setTimeout(() => counts[0].classList.remove('usage-count-flash'), 600);
            }
        }
        if (counts[1]) {
            const newText = `${freshUsage.scans_used}/${freshUsage.scans_limit < 0 ? '∞' : freshUsage.scans_limit}`;
            if (counts[1].textContent !== newText) {
                counts[1].textContent = newText;
                counts[1].classList.add('usage-count-flash');
                setTimeout(() => counts[1].classList.remove('usage-count-flash'), 600);
            }
        }
        existingCard.classList.toggle('near-limit', cmdPct >= 80 || scanPct >= 80);
    } else {
        // Full re-render (first render or admin/hidden state change)
        meterContainer.innerHTML = UsageMeter(freshUsage);
    }
}

function updateAdminNav(usage) {
    if (!usage) return;
    const isAdmin = usage.is_admin === true;
    document.querySelectorAll('[data-admin-only]').forEach(el => {
        el.style.display = isAdmin ? '' : 'none';
    });
}

function updateSidebarUsage(usage) {
    const el = document.getElementById('sidebar-usage');
    if (!el) return;
    if (!usage || usage.is_admin) {
        el.innerHTML = usage?.is_admin
            ? '<div class="sidebar-usage-inner"><span class="sidebar-usage-unlimited">Unlimited</span></div>'
            : '';
        return;
    }
    const cmdLimit = usage.commands_limit;
    const scanLimit = usage.scans_limit;
    const cmdUsed = usage.commands_used || 0;
    const scanUsed = usage.scans_used || 0;
    const cmdPct = cmdLimit > 0 ? Math.min(100, Math.round((cmdUsed / cmdLimit) * 100)) : 0;
    const scanPct = scanLimit > 0 ? Math.min(100, Math.round((scanUsed / scanLimit) * 100)) : 0;

    function barColor(pct) {
        if (pct >= 90) return 'var(--color-block)';
        if (pct >= 70) return 'var(--color-warn)';
        return 'var(--color-allow)';
    }

    const cmdLabel = cmdLimit < 0 ? `${cmdUsed}/∞` : `${cmdUsed}/${cmdLimit}`;
    const scanLabel = scanLimit < 0 ? `${scanUsed}/∞` : `${scanUsed}/${scanLimit}`;
    const limitReached = usage.limit_reached;

    const boosterCredits = usage.booster_credits_remaining || 0;
    const boosterHtml = boosterCredits > 0
        ? `<div class="sidebar-usage-row sidebar-usage-booster">
            <span class="sidebar-usage-label">&#x26A1; Booster</span>
            <span class="sidebar-usage-count">${boosterCredits}</span>
        </div>`
        : '';
    const showBoosterBtn = (limitReached || cmdPct >= 80) && !boosterCredits;
    const boosterBtnHtml = showBoosterBtn
        ? '<button class="sidebar-booster-btn" id="sidebar-buy-booster">&#x26A1; +500 Cmds — &euro;4.99</button>'
        : '';

    el.innerHTML = `<div class="sidebar-usage-inner">
        <div class="sidebar-usage-row">
            <span class="sidebar-usage-label">Commands</span>
            <span class="sidebar-usage-count">${cmdLabel}</span>
        </div>
        <div class="sidebar-usage-bar"><div class="sidebar-usage-bar-fill" style="width:${cmdPct}%;background:${barColor(cmdPct)}"></div></div>
        <div class="sidebar-usage-row">
            <span class="sidebar-usage-label">Scans</span>
            <span class="sidebar-usage-count">${scanLabel}</span>
        </div>
        <div class="sidebar-usage-bar"><div class="sidebar-usage-bar-fill" style="width:${scanPct}%;background:${barColor(scanPct)}"></div></div>
        ${boosterHtml}
        ${limitReached ? '<a href="#/pricing" class="sidebar-usage-limit">LIMIT REACHED — Upgrade</a>' : ''}
        ${boosterBtnHtml}
    </div>`;

    const boosterBtn = document.getElementById('sidebar-buy-booster');
    if (boosterBtn) {
        boosterBtn.addEventListener('click', async () => {
            boosterBtn.disabled = true;
            boosterBtn.textContent = 'Redirecting...';
            const result = await api('/api/billing/booster', { method: 'POST' });
            if (result && result.checkout_url) {
                window.location.href = result.checkout_url;
            } else {
                boosterBtn.disabled = false;
                boosterBtn.innerHTML = '&#x26A1; +500 Cmds — &euro;4.99';
                showToast('Failed to start booster checkout.', 'error');
            }
        });
    }
}

function updateSidebarUpgrade(usage) {
    const box = document.getElementById('sidebar-upgrade');
    if (!box) return;
    // Show upgrade card only for free-tier non-admin users
    const showUpgrade = usage && usage.tier === 'free' && !usage.is_admin;
    box.style.display = showUpgrade ? '' : 'none';
}

function updateNavLocks(usage) {
    if (!usage) return;
    const isFree = usage.tier === 'free' && !usage.is_admin;
    document.querySelectorAll('[data-requires-pro]').forEach(el => {
        const existing = el.querySelector('.nav-lock-icon');
        if (isFree && !existing) {
            const lockHtml = '<span class="nav-lock-icon" aria-label="Pro feature"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#8b949e" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>';
            const label = el.querySelector('.nav-label');
            if (label) label.insertAdjacentHTML('afterend', lockHtml);
        } else if (!isFree && existing) {
            existing.remove();
        }
    });
}

function updateTierBadge(usage) {
    if (!usage) return;

    // Update or create tier badge in sidebar
    let tierBadge = document.getElementById('tier-badge');
    if (!tierBadge) {
        const logoDiv = document.querySelector('.sidebar-logo');
        if (logoDiv) {
            tierBadge = document.createElement('span');
            tierBadge.id = 'tier-badge';
            tierBadge.className = 'tier-badge';
            logoDiv.appendChild(tierBadge);
        }
    }

    if (tierBadge) {
        const tier = usage.tier || 'free';
        const isUnprotected = usage.limit_reached && !usage.is_admin;

        if (isUnprotected) {
            tierBadge.textContent = 'UNPROTECTED';
            tierBadge.className = 'tier-badge tier-unprotected';
        } else if (tier === 'pro_plus') {
            tierBadge.textContent = 'PRO+';
            tierBadge.className = 'tier-badge tier-pro_plus';
        } else if (tier === 'unlimited') {
            tierBadge.textContent = 'ADMIN';
            tierBadge.className = 'tier-badge tier-unlimited';
        } else {
            const tierName = tier.charAt(0).toUpperCase() + tier.slice(1);
            tierBadge.textContent = tierName;
            tierBadge.className = `tier-badge tier-${tier}`;
        }
    }
}

function SecurityDisabledBanner(usage) {
    if (!usage || !usage.limit_reached || usage.is_admin) return '';

    const cmdUsed = usage.commands_used || 0;
    const ctaText = usage.tier === 'pro' ? 'Upgrade to Pro+ — unlimited' : 'Upgrade to Pro — €19.99/mo';

    return `<div class="security-disabled-inner">
        <div class="security-disabled-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 .34-.08.68-.19 1-.3"
                      stroke="#F85149" stroke-width="1.5" fill="none"/>
                <line x1="2" y1="2" x2="22" y2="22" stroke="#F85149" stroke-width="2.5" stroke-linecap="round"/>
            </svg>
        </div>
        <div class="security-disabled-text">
            <strong>Security Protection DISABLED</strong>
            <span>Your AI agents executed <strong>${cmdUsed} commands</strong> today without security screening. Any of these could contain malicious code, credential theft, or data exfiltration.</span>
        </div>
        <a href="#/pricing" class="btn security-disabled-cta">${ctaText}</a>
    </div>`;
}

function updateSecurityBanner(usage) {
    const banner = document.getElementById('security-disabled-banner');
    if (!banner) return;

    const shouldShow = usage && usage.limit_reached && !usage.is_admin;

    if (shouldShow) {
        banner.innerHTML = SecurityDisabledBanner(usage);
        banner.style.display = '';
    } else {
        banner.innerHTML = '';
        banner.style.display = 'none';
    }
}

function UsageMeter(usage) {
    if (!usage || usage.is_admin) return '';

    const cmdPct = usage.commands_limit > 0
        ? Math.min(100, Math.round((usage.commands_used / usage.commands_limit) * 100))
        : 0;
    const scanPct = usage.scans_limit > 0
        ? Math.min(100, Math.round((usage.scans_used / usage.scans_limit) * 100))
        : 0;

    const cmdColor = cmdPct >= 90 ? 'var(--color-block)' : cmdPct >= 70 ? 'var(--color-warn)' : 'var(--color-allow)';
    const scanColor = scanPct >= 90 ? 'var(--color-block)' : scanPct >= 70 ? 'var(--color-warn)' : 'var(--color-allow)';
    const cmdNearLimit = cmdPct >= 80 ? ' near-limit' : '';
    const scanNearLimit = scanPct >= 80 ? ' near-limit' : '';
    const cardNearLimit = (cmdPct >= 80 || scanPct >= 80) ? ' near-limit' : '';

    const showUpgrade = (usage.tier === 'free' || usage.tier === 'pro') && (cmdPct >= 70 || scanPct >= 70) && !usage.limit_reached;
    const tierDisplayLabel = usage.tier === 'pro_plus' ? 'PRO+' : usage.tier.toUpperCase();

    return `<div class="usage-meter-card${cardNearLimit}">
    <div class="usage-header">
        <span class="usage-title">Daily Usage</span>
        <span class="tier-label tier-${escapeHtml(usage.tier)}">${escapeHtml(tierDisplayLabel)}</span>
    </div>
    <div class="usage-bars">
        <div class="usage-bar-row">
            <span class="usage-label">Commands</span>
            <div class="usage-bar-track">
                <div class="usage-bar-fill${cmdNearLimit}" style="width: ${cmdPct}%; background-color: ${cmdColor};"></div>
            </div>
            <span class="usage-count">${usage.commands_used}/${usage.commands_limit < 0 ? '∞' : usage.commands_limit}</span>
        </div>
        <div class="usage-bar-row">
            <span class="usage-label">Scans</span>
            <div class="usage-bar-track">
                <div class="usage-bar-fill${scanNearLimit}" style="width: ${scanPct}%; background-color: ${scanColor};"></div>
            </div>
            <span class="usage-count">${usage.scans_used}/${usage.scans_limit < 0 ? '∞' : usage.scans_limit}</span>
        </div>
    </div>
    ${showUpgrade ? `<a href="#/pricing" class="upgrade-cta">
        <span>${usage.tier === 'pro' ? 'Upgrade to Pro+' : 'Upgrade to Pro'}</span>
        <span class="upgrade-arrow">→</span>
    </a>` : ''}
</div>`;
}

function LimitReachedBanner(usage) {
    if (!usage || !usage.limit_reached) return '';
    // Don't show if global security banner is already visible (avoids duplicate messaging)
    const secBanner = document.getElementById('security-disabled-banner');
    if (secBanner && secBanner.style.display !== 'none') return '';

    return `<div class="limit-banner">
    <div class="limit-banner-icon">⚠</div>
    <div class="limit-banner-text">
        <strong>Daily limit reached</strong>
        <p>You've used all your ${escapeHtml(usage.tier)} tier allowance for today. Upgrade for unlimited access.</p>
    </div>
    <a href="#/pricing" class="btn btn-primary">Upgrade Now</a>
</div>`;
}

function ApproachingLimitBanner(usage) {
    if (!usage || !usage.approaching_limit || usage.limit_reached) return '';

    const cmdPct = usage.commands_limit > 0
        ? Math.round((usage.commands_used / usage.commands_limit) * 100)
        : 0;
    const scanPct = usage.scans_limit > 0
        ? Math.round((usage.scans_used / usage.scans_limit) * 100)
        : 0;
    const pct = Math.max(cmdPct, scanPct);

    const cmdRemaining = usage.commands_limit > 0 ? Math.max(0, usage.commands_limit - usage.commands_used) : '∞';
    const scanRemaining = usage.scans_limit > 0 ? Math.max(0, usage.scans_limit - usage.scans_used) : '∞';
    const ctaText = usage.tier === 'pro' ? 'Upgrade to Pro+' : 'Upgrade to Pro';

    return `<div class="limit-banner approaching-limit-banner">
    <div class="limit-banner-icon">&#x26A1;</div>
    <div class="limit-banner-text">
        <strong>Approaching daily limit (${pct}%)</strong>
        <p>You've used ${usage.commands_used}/${usage.commands_limit} commands and ${usage.scans_used}/${usage.scans_limit} scans. ${cmdRemaining} commands remaining.</p>
    </div>
    <a href="#/pricing" class="btn btn-secondary">${ctaText}</a>
</div>`;
}

function DashboardPaywall(usage) {
    if (!usage || !usage.limit_reached || usage.is_admin) return '';

    const blockedToday = (usage.commands_used || 0) - (usage.commands_limit > 0 ? usage.commands_limit : 0);
    const blockedText = blockedToday > 0
        ? `ShieldPilot blocked <strong>${blockedToday} additional command${blockedToday !== 1 ? 's' : ''}</strong> after your limit.`
        : `You've used all <strong>${usage.commands_limit}</strong> commands for today.`;
    const ctaText = usage.tier === 'pro' ? 'Upgrade to Pro+ — unlimited' : 'Upgrade to Pro — €19.99/mo';

    return `<div class="dashboard-paywall-overlay" id="dashboard-paywall">
    <div class="dashboard-paywall-content dashboard-paywall-danger">
        <div class="dashboard-paywall-icon">
            <svg width="56" height="56" viewBox="0 0 24 24" fill="none">
                <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2z"
                      stroke="#F85149" stroke-width="1.5" fill="rgba(248,81,73,0.1)"/>
                <line x1="4" y1="4" x2="20" y2="20" stroke="#F85149" stroke-width="2.5" stroke-linecap="round"/>
            </svg>
        </div>
        <h3 class="dashboard-paywall-danger-title">Security Protection Disabled</h3>
        <p class="dashboard-paywall-danger-body">${blockedText} Your AI agents are running <strong>without security checks</strong>.</p>
        <p class="dashboard-paywall-subtext">Upgrade now to restore real-time threat detection, or wait for the daily reset at midnight UTC.</p>
        <div class="dashboard-paywall-actions">
            <a href="#/pricing" class="btn btn-primary dashboard-paywall-upgrade">${ctaText}</a>
            <button class="btn btn-sm btn-outline dashboard-paywall-booster" id="paywall-buy-booster">&#x26A1; +500 Commands — &euro;4.99</button>
        </div>
    </div>
</div>`;
}

function applyDashboardPaywall(usage, wrapper) {
    if (!wrapper) return;
    const existingPaywall = document.getElementById('dashboard-paywall');
    const isBlocked = usage && usage.limit_reached && !usage.is_admin;

    if (isBlocked && !existingPaywall) {
        wrapper.classList.add('paywall-active');
        wrapper.insertAdjacentHTML('beforeend', DashboardPaywall(usage));
        const boosterBtn = document.getElementById('paywall-buy-booster');
        if (boosterBtn) {
            boosterBtn.addEventListener('click', async () => {
                boosterBtn.disabled = true;
                boosterBtn.textContent = 'Redirecting...';
                const result = await api('/api/billing/booster', { method: 'POST' });
                if (result && result.checkout_url) {
                    window.location.href = result.checkout_url;
                } else {
                    boosterBtn.disabled = false;
                    boosterBtn.innerHTML = '&#x26A1; +500 Commands — &euro;4.99';
                    showToast('Failed to start booster checkout.', 'error');
                }
            });
        }
    } else if (!isBlocked && existingPaywall) {
        existingPaywall.remove();
        wrapper.classList.remove('paywall-active');
    }
}

function PaymentIssueBanner(settings) {
    if (!settings || settings.subscription_status !== 'past_due') return '';
    return `<div class="limit-banner payment-issue-banner">
        <div class="limit-banner-icon">&#x26a0;</div>
        <div class="limit-banner-text">
            <strong>Payment issue detected</strong>
            <p>We couldn't process your latest payment. Please update your payment method to keep your ${escapeHtml(settings.tier)} features.</p>
        </div>
        <button class="btn btn-primary" id="fix-payment-btn">Update Payment</button>
    </div>`;
}

function CancellationWarningBanner(settings) {
    if (!settings || !settings.cancel_at_period_end || !settings.current_period_end) return '';
    const formatted = formatPeriodDate(settings.current_period_end, 'soon');
    return `<div class="limit-banner cancellation-banner">
        <div class="limit-banner-icon">&#x1f4c5;</div>
        <div class="limit-banner-text">
            <strong>Your ${escapeHtml(settings.tier)} plan ends on ${formatted}</strong>
            <p>After this date, your account reverts to Free.</p>
        </div>
        <button class="btn btn-primary" id="reactivate-sub-btn">Reactivate</button>
    </div>`;
}

function ChainHealthWidget(chainData) {
    if (!chainData) {
        return '<div class="chain-health-widget loading"><span class="chain-spinner"></span> Verifying audit chains...</div>';
    }

    // If user dismissed the alert this session, don't show it
    if (sessionStorage.getItem('chain_alert_dismissed')) {
        return '';
    }

    const healthy = chainData.healthy;
    const chains = chainData.chains || {};
    const tableNames = Object.keys(chains);
    const totalEntries = tableNames.reduce((sum, t) => sum + (chains[t].total_entries || 0), 0);
    const brokenTables = tableNames.filter(t => !chains[t].valid);

    const stateClass = healthy ? 'healthy' : 'tampered';
    const icon = healthy ? '&#x2713;' : '&#x26A0;';
    const label = healthy ? 'Audit Chain Intact' : 'Chain Integrity Alert';
    const detail = healthy
        ? `${totalEntries} entries across ${tableNames.length} tables`
        : `Tampering detected in: ${brokenTables.map(t => escapeHtml(t)).join(', ')}`;
    const autoDelay = healthy ? 5000 : 8000;

    return `<div class="chain-health-widget ${stateClass}" data-auto-dismiss="${autoDelay}">
        <div class="chain-health-status">
            <span class="chain-icon">${icon}</span>
            <span class="chain-label">${label}</span>
            <span class="chain-detail">${detail}</span>
        </div>
        <button class="chain-dismiss-btn" title="Dismiss">&times;</button>
    </div>`;
}

/** Call after inserting ChainHealthWidget HTML into the DOM. */
function initChainWidgetDismiss(container) {
    const widget = container.querySelector('.chain-health-widget:not(.loading)');
    if (!widget) return;

    function dismiss() {
        if (widget.classList.contains('fade-out')) return;
        sessionStorage.setItem('chain_alert_dismissed', '1');
        widget.classList.add('fade-out');
        // Remove after transition, with fallback timeout
        setTimeout(() => widget.remove(), 600);
    }

    // Manual close button
    const btn = widget.querySelector('.chain-dismiss-btn');
    if (btn) btn.addEventListener('click', dismiss);

    // Auto-dismiss after delay
    const delay = parseInt(widget.dataset.autoDismiss, 10);
    if (delay > 0) setTimeout(dismiss, delay);
}

// ---------------------------------------------------------------------------
// Event Wiring
// ---------------------------------------------------------------------------

function wireGlobalEvents() {
    // Sidebar navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const route = item.getAttribute('data-route');
            if (route) navigate(route);
        });
    });

    // Global search with live dropdown
    const globalSearch = document.getElementById('global-search');
    if (globalSearch) {
        let gsDebounce = null;
        let gsDropdown = null;
        let gsSelectedIdx = -1;

        function getOrCreateDropdown() {
            if (gsDropdown) return gsDropdown;
            gsDropdown = document.createElement('div');
            gsDropdown.className = 'global-search-dropdown';
            gsDropdown.setAttribute('role', 'listbox');
            gsDropdown.id = 'global-search-results';
            globalSearch.parentNode.appendChild(gsDropdown);
            globalSearch.setAttribute('aria-controls', 'global-search-results');
            globalSearch.setAttribute('role', 'combobox');
            globalSearch.setAttribute('aria-expanded', 'false');
            return gsDropdown;
        }

        function closeDropdown() {
            if (gsDropdown) {
                gsDropdown.style.display = 'none';
                globalSearch.setAttribute('aria-expanded', 'false');
            }
            gsSelectedIdx = -1;
        }

        async function performSearch(query) {
            if (!query || query.length < 2) { closeDropdown(); return; }
            const dropdown = getOrCreateDropdown();
            const results = await api('/api/commands', { params: { search: query, limit: 6 } });
            if (!results || !results.items || !results.items.length) {
                dropdown.innerHTML = '<div class="gs-empty">No results found</div>';
                dropdown.style.display = 'block';
                globalSearch.setAttribute('aria-expanded', 'true');
                return;
            }
            dropdown.innerHTML = results.items.map((cmd, i) => {
                const action = (cmd.action_taken || 'unknown').toLowerCase();
                return `<div class="gs-result" role="option" data-index="${i}" data-cmd-id="${cmd.id}">
                    <span class="gs-action badge badge-${escapeHtml(action)}">${escapeHtml(action.toUpperCase())}</span>
                    <code class="gs-cmd">${escapeHtml(truncate(cmd.command || '', 60))}</code>
                    <span class="gs-score" data-level="${scoreLevel(cmd.risk_score || 0)}">${cmd.risk_score || 0}</span>
                </div>`;
            }).join('') + `<div class="gs-footer" role="option" data-action="view-all">View all results for "${escapeHtml(query)}"</div>`;
            dropdown.style.display = 'block';
            globalSearch.setAttribute('aria-expanded', 'true');
            gsSelectedIdx = -1;

            dropdown.querySelectorAll('.gs-result, .gs-footer').forEach(el => {
                el.addEventListener('click', () => {
                    if (el.dataset.action === 'view-all') {
                        commandState.search = query;
                        commandState.page = 1;
                        navigate('#/commands');
                    } else {
                        commandState.search = query;
                        navigate('#/commands');
                    }
                    closeDropdown();
                    globalSearch.value = '';
                });
            });
        }

        globalSearch.addEventListener('input', () => {
            clearTimeout(gsDebounce);
            gsDebounce = setTimeout(() => performSearch(globalSearch.value.trim()), 250);
        });

        globalSearch.addEventListener('keydown', (e) => {
            const items = gsDropdown ? gsDropdown.querySelectorAll('.gs-result, .gs-footer') : [];
            if (e.key === 'ArrowDown' && items.length) {
                e.preventDefault();
                gsSelectedIdx = Math.min(gsSelectedIdx + 1, items.length - 1);
                items.forEach((el, i) => el.classList.toggle('gs-active', i === gsSelectedIdx));
            } else if (e.key === 'ArrowUp' && items.length) {
                e.preventDefault();
                gsSelectedIdx = Math.max(gsSelectedIdx - 1, 0);
                items.forEach((el, i) => el.classList.toggle('gs-active', i === gsSelectedIdx));
            } else if (e.key === 'Escape') {
                closeDropdown();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                if (gsSelectedIdx >= 0 && items[gsSelectedIdx]) {
                    items[gsSelectedIdx].click();
                } else {
                    const query = globalSearch.value.trim();
                    if (query) {
                        commandState.search = query;
                        commandState.page = 1;
                        navigate('#/commands');
                        closeDropdown();
                        globalSearch.value = '';
                    }
                }
            }
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!globalSearch.parentNode.contains(e.target)) closeDropdown();
        });
    }

    // Global export dropdown in nav
    const navExportContainer = document.getElementById('nav-export-container');
    if (navExportContainer) {
        navExportContainer.innerHTML = ExportDropdown();
        wireExportDropdown(navExportContainer);
    }

    // Sign out
    const signOutBtn = document.getElementById('sign-out');
    if (signOutBtn) {
        signOutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            clearToken();
            window.location.href = LOGIN_PATH;
        });
    }

    // Mobile menu toggle
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const sidebar = document.querySelector('.sidebar');
    if (mobileMenuBtn && sidebar) {
        // Create overlay element
        const overlay = document.createElement('div');
        overlay.className = 'mobile-overlay';
        document.body.appendChild(overlay);

        mobileMenuBtn.addEventListener('click', () => {
            const isOpen = sidebar.classList.toggle('mobile-open');
            overlay.classList.toggle('visible', isOpen);
            mobileMenuBtn.setAttribute('aria-expanded', isOpen);
        });

        overlay.addEventListener('click', () => {
            sidebar.classList.remove('mobile-open');
            overlay.classList.remove('visible');
            mobileMenuBtn.setAttribute('aria-expanded', 'false');
        });

        // Close mobile menu on navigation
        sidebar.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                if (window.innerWidth <= 768) {
                    sidebar.classList.remove('mobile-open');
                    overlay.classList.remove('visible');
                    mobileMenuBtn.setAttribute('aria-expanded', 'false');
                }
            });
        });
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Escape: close modals and mobile menu
        if (e.key === 'Escape') {
            // Close any open modal
            const modal = document.querySelector('.modal-overlay, #delete-modal-overlay, #sentinel-modal');
            if (modal) {
                modal.remove();
                return;
            }
            // Close mobile menu
            const sidebar = document.querySelector('.sidebar.mobile-open');
            const overlay = document.querySelector('.mobile-overlay.visible');
            if (sidebar) {
                sidebar.classList.remove('mobile-open');
                if (overlay) overlay.classList.remove('visible');
                const menuBtn = document.getElementById('mobile-menu-btn');
                if (menuBtn) menuBtn.setAttribute('aria-expanded', 'false');
            }
            return;
        }

        // '/' focuses search
        if (e.key === '/' && !isInputFocused()) {
            e.preventDefault();
            const searchEl = document.getElementById('global-search');
            if (searchEl) searchEl.focus();
        }
    });

    // Hash change
    window.addEventListener('hashchange', handleRoute);
}

/**
 * Returns true if the currently focused element is a text input or textarea.
 */
function isInputFocused() {
    const el = document.activeElement;
    if (!el) return false;
    const tag = el.tagName.toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable;
}

// ---------------------------------------------------------------------------
// Onboarding Tour
// ---------------------------------------------------------------------------

const ONBOARDING_STEPS = [
    {
        title: 'Welcome to ShieldPilot',
        text: 'Your AI agents are now protected. ShieldPilot monitors every command in real-time and blocks dangerous actions before they execute.',
        icon: '&#x1f6e1;',
    },
    {
        title: 'Threat Detection',
        text: 'Our 9 security analyzers scan commands for destructive filesystem ops, credential theft, network exfiltration, supply chain attacks, and prompt injection attempts.',
        icon: '&#x1f50d;',
    },
    {
        title: 'Your Dashboard',
        text: 'Track allowed, warned, and blocked commands. Review incidents, run prompt injection scans, and manage your security posture from one place.',
        icon: '&#x1f4ca;',
    },
];

function showOnboardingTour() {
    if (localStorage.getItem('onboarding_done')) return;
    let step = 0;

    const overlay = document.createElement('div');
    overlay.className = 'onboarding-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Onboarding tour');

    function render() {
        const s = ONBOARDING_STEPS[step];
        const dots = ONBOARDING_STEPS.map((_, i) =>
            `<span class="onboarding-dot ${i === step ? 'active' : ''}" aria-hidden="true"></span>`
        ).join('');
        const isLast = step === ONBOARDING_STEPS.length - 1;

        overlay.innerHTML = `<div class="onboarding-card">
            <div class="onboarding-icon">${s.icon}</div>
            <h2 class="onboarding-title">${escapeHtml(s.title)}</h2>
            <p class="onboarding-text">${escapeHtml(s.text)}</p>
            <div class="onboarding-dots">${dots}</div>
            <div class="onboarding-actions">
                <button class="btn btn-secondary onboarding-skip">Skip</button>
                <button class="btn btn-primary onboarding-next">${isLast ? 'Get Started' : 'Next'}</button>
            </div>
        </div>`;

        overlay.querySelector('.onboarding-next').addEventListener('click', () => {
            if (isLast) { finish(); } else { step++; render(); }
        });
        overlay.querySelector('.onboarding-skip').addEventListener('click', finish);
    }

    function finish() {
        localStorage.setItem('onboarding_done', '1');
        overlay.classList.add('onboarding-fade-out');
        setTimeout(() => overlay.remove(), 300);
    }

    render();
    document.body.appendChild(overlay);
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

async function init() {
    // Detect local-first mode before checking auth
    await checkLocalFirstMode();

    if (!requireAuth()) return;

    // Check email verification — block entire app if unverified
    if (showVerificationBlocker()) return;

    // Set default hash if none
    if (!window.location.hash) {
        window.location.hash = DEFAULT_HASH;
    }

    wireGlobalEvents();

    // Render Lucide icons in sidebar (before first route)
    if (window.lucide) window.lucide.createIcons();

    // Update sidebar user info from JWT
    updateSidebarUser();

    // Fetch usage info to show tier badge
    await fetchUsage();

    handleRoute();

    // Refresh usage every 10 seconds (fallback when SSE unavailable)
    setInterval(fetchUsage, 10000);

    // Show onboarding tour on first login
    showOnboardingTour();

    // Token expiry check every 30 minutes — close SSE and redirect on expiry
    setInterval(() => {
        if (!isAuthenticated()) {
            clearActiveIntervals();
            clearToken();
            window.location.href = LOGIN_PATH;
        }
    }, 30 * 60 * 1000);
}

// ---------------------------------------------------------------------------
// Email Verification Full-Screen Blocker
// ---------------------------------------------------------------------------

/**
 * If the current user is unverified (and not super-admin), show a dismissible
 * banner at the top of the page. No longer blocks the app - just warns.
 * Returns false to allow app to continue loading.
 */
function showVerificationBlocker() {
    const token = getToken();
    if (!token) return false;
    const payload = decodeJwtPayload(token);
    if (!payload) return false;

    // Verified users and super-admins pass through
    if (payload.email_verified || payload.is_super_admin) return false;

    // Check if user dismissed in this session
    if (sessionStorage.getItem('verify_banner_dismissed')) return false;

    const userEmail = payload.email || payload.sub || '';

    // Add CSS for the banner
    if (!document.getElementById('verify-banner-styles')) {
        const style = document.createElement('style');
        style.id = 'verify-banner-styles';
        style.textContent = `
            .verify-banner {
                display: flex;
                align-items: center;
                gap: var(--space-md, 16px);
                padding: var(--space-sm, 8px) var(--space-md, 16px);
                background: linear-gradient(90deg, rgba(210, 153, 34, 0.15), rgba(210, 153, 34, 0.1));
                border-bottom: 1px solid rgba(210, 153, 34, 0.3);
                font-size: 13px;
            }
            .verify-banner-icon { font-size: 18px; }
            .verify-banner-text { flex: 1; }
            .verify-banner-text strong { color: var(--color-warn, #D29922); }
            .verify-banner-text p { margin: 2px 0 0; color: var(--text-muted, #6E7681); font-size: 12px; }
            .verify-banner .btn { flex-shrink: 0; }
            .verify-banner-dismiss {
                background: none; border: none; color: var(--text-muted, #6E7681);
                font-size: 18px; cursor: pointer; padding: 4px; line-height: 1;
            }
            .verify-banner-dismiss:hover { color: var(--text-secondary, #8b949e); }
        `;
        document.head.appendChild(style);
    }

    // Create banner
    const banner = document.createElement('div');
    banner.className = 'verify-banner';
    banner.id = 'verify-banner';
    banner.innerHTML = `
        <span class="verify-banner-icon">📧</span>
        <div class="verify-banner-text">
            <strong>Verify your email</strong>
            <p>Please verify ${escapeHtml(userEmail)} to unlock all features.</p>
        </div>
        <button class="btn btn-sm" id="verify-resend-banner">Resend Email</button>
        <button class="verify-banner-dismiss" aria-label="Dismiss">&times;</button>
    `;

    // Insert after top-bar or at the start of main-content
    const topBar = document.querySelector('.top-bar');
    const mainContent = document.querySelector('.main-content');
    if (topBar) {
        topBar.parentNode.insertBefore(banner, topBar.nextSibling);
    } else if (mainContent) {
        mainContent.insertBefore(banner, mainContent.firstChild);
    }

    // Wire dismiss button
    banner.querySelector('.verify-banner-dismiss').addEventListener('click', () => {
        banner.remove();
        sessionStorage.setItem('verify_banner_dismissed', 'true');
    });

    // Wire resend button
    banner.querySelector('#verify-resend-banner').addEventListener('click', async () => {
        const btn = banner.querySelector('#verify-resend-banner');
        btn.disabled = true;
        btn.textContent = 'Sending...';

        const result = await api('/api/auth/verify-email/resend', { method: 'POST' });
        if (result) {
            showToast('Verification email sent! Check your inbox.', 'success');
            btn.textContent = 'Sent!';
            setTimeout(() => {
                btn.textContent = 'Resend Email';
                btn.disabled = false;
            }, 30000);
        } else {
            btn.textContent = 'Resend Email';
            btn.disabled = false;
        }
    });

    return false; // Don't block - allow app to continue
}

// ---------------------------------------------------------------------------
// Sidebar User Info
// ---------------------------------------------------------------------------

function updateSidebarUser() {
    const token = getToken();
    if (!token) return;
    const payload = decodeJwtPayload(token);
    if (!payload) return;

    const nameEl = document.querySelector('.user-name');
    const avatarEl = document.querySelector('.user-avatar');
    const emailEl = document.getElementById('sidebar-user-email');

    // Immediate display from JWT sub field
    const displayName = payload.sub || payload.email || 'user';
    const email = payload.email || '';
    if (nameEl) nameEl.textContent = displayName;
    if (avatarEl) avatarEl.textContent = displayName.substring(0, 2).toUpperCase();
    if (emailEl) emailEl.textContent = email;

    // Async fetch actual username from settings API (may differ from JWT sub)
    fetch('/api/settings', {
        headers: { 'Authorization': 'Bearer ' + token }
    })
    .then(r => r.ok ? r.json() : null)
    .then(data => {
        if (!data) return;
        const name = data.username || displayName;
        if (nameEl) nameEl.textContent = name;
        if (avatarEl) avatarEl.textContent = name.substring(0, 2).toUpperCase();
        if (emailEl && data.email) emailEl.textContent = data.email;
    })
    .catch(() => {});
}

// -- Legal Pages -----------------------------------------------------------

function renderLegalTerms() {
    const page = getPageContent();
    page.innerHTML = `
<div class="legal-page">
    <a href="#/dashboard" class="legal-back-link">&larr; Back to Dashboard</a>
    <h1>Terms of Service</h1>
    <p class="legal-subtitle">Last updated: February 1, 2026 &middot; Version 2026-02-01</p>

    <div class="legal-section">
        <h2>1. Scope and Provider</h2>
        <p>These Terms of Service ("Terms") govern your use of the ShieldPilot security platform ("Service") operated by the entity identified in our <a href="#/legal/impressum">Impressum</a> ("Provider", "we", "us").</p>
        <p>By creating an account or using the Service, you agree to these Terms. If you do not agree, do not use the Service.</p>
    </div>

    <div class="legal-section">
        <h2>2. Description of Service</h2>
        <p>ShieldPilot is a security monitoring platform for AI coding agents. The Service evaluates commands executed by AI agents in real-time, assigns risk scores, and provides audit logging, threat detection, and incident management capabilities.</p>
    </div>

    <div class="legal-section">
        <h2>3. Account Registration</h2>
        <p>You must be at least 18 years old to create an account. You are responsible for maintaining the confidentiality of your credentials and for all activity under your account. You must provide accurate and complete registration information.</p>
    </div>

    <div class="legal-section">
        <h2>4. User Responsibilities</h2>
        <p>You are solely responsible for all commands executed through or monitored by the Service. ShieldPilot provides security analysis as an additional layer of protection, but does not replace your own security practices and due diligence.</p>
        <p>You agree not to:</p>
        <ul>
            <li>Use the Service for any unlawful purpose</li>
            <li>Attempt to circumvent security measures or rate limits</li>
            <li>Reverse engineer or decompile the Service</li>
            <li>Share your account credentials with third parties</li>
        </ul>
    </div>

    <div class="legal-section">
        <h2>5. Service "As Is"</h2>
        <p>THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.</p>
        <p>ShieldPilot is currently in <strong>Early Access</strong>. While we strive for comprehensive threat detection, no security tool can guarantee detection of all threats. The Service is designed to complement, not replace, your existing security measures.</p>
    </div>

    <div class="legal-section">
        <h2>6. Limitation of Liability</h2>
        <p>To the maximum extent permitted by applicable law, the Provider's total liability arising from or related to these Terms shall not exceed the total fees paid by you in the twelve (12) months preceding the event giving rise to the claim.</p>
        <p>The Provider shall not be liable for any indirect, incidental, special, consequential, or punitive damages, including but not limited to loss of data, profits, or business opportunities.</p>
        <p>The limitations above do not apply to liability for intentional misconduct or gross negligence (Vorsatz oder grobe Fahrl&auml;ssigkeit), injury to life, body, or health, or liability under mandatory consumer protection laws.</p>
    </div>

    <div class="legal-section">
        <h2>7. Data Protection</h2>
        <p>We process personal data in accordance with our <a href="#/legal/privacy">Privacy Policy</a> and the EU General Data Protection Regulation (GDPR). By using the Service, you acknowledge that you have read and understood our Privacy Policy.</p>
    </div>

    <div class="legal-section">
        <h2>8. Intellectual Property</h2>
        <p>The Service, including its software, design, logos, and documentation, is the intellectual property of the Provider. Your use of the Service does not grant you any ownership rights. You retain ownership of your data.</p>
    </div>

    <div class="legal-section">
        <h2>9. Subscription and Payment</h2>
        <p>The Service offers free and paid subscription tiers. Paid subscriptions are billed through Stripe. By subscribing to a paid plan, you authorize recurring charges at the applicable rate.</p>
        <p>We may change pricing with at least 30 days' advance notice. Price changes will not affect your current billing period.</p>
        <p><strong>Refunds:</strong> Refunds for paid subscriptions are handled in accordance with your right of withdrawal (see <a href="#/legal/withdrawal">Withdrawal Policy</a>). After the withdrawal period has expired or been waived, no refunds will be issued for partial billing periods. You may cancel your subscription at any time; access continues until the end of the current billing period.</p>
    </div>

    <div class="legal-section">
        <h2>10. Termination</h2>
        <p>You may terminate your account at any time through the Settings page. Upon termination, your personal data will be deleted or anonymized in accordance with our Privacy Policy. Audit logs will be anonymized to preserve chain integrity.</p>
        <p>We may suspend or terminate your account if you violate these Terms, with notice where practicable.</p>
    </div>

    <div class="legal-section">
        <h2>11. Modifications</h2>
        <p>We may modify these Terms at any time. Material changes will be communicated via email at least 14 days before taking effect. Continued use of the Service after the effective date constitutes acceptance of the modified Terms.</p>
    </div>

    <div class="legal-section">
        <h2>12. Governing Law</h2>
        <p>These Terms are governed by the laws of the Federal Republic of Germany, excluding the UN Convention on Contracts for the International Sale of Goods (CISG).</p>
        <p>For consumers residing in the EU: You may also rely on the mandatory consumer protection provisions of your country of residence.</p>
        <p>The European Commission provides an online dispute resolution platform at <a href="https://ec.europa.eu/consumers/odr" target="_blank" rel="noopener">https://ec.europa.eu/consumers/odr</a>. We are not obligated and generally not willing to participate in dispute resolution proceedings before a consumer arbitration board.</p>
    </div>

    <div class="legal-section">
        <h2>13. Severability</h2>
        <p>If any provision of these Terms is held to be invalid or unenforceable, the remaining provisions shall continue in full force and effect.</p>
    </div>

    <div class="legal-section">
        <h2>14. Contact</h2>
        <p>For questions about these Terms, please refer to our <a href="#/legal/impressum">Impressum</a> for contact information.</p>
    </div>
</div>`;
}


function renderLegalPrivacy() {
    const page = getPageContent();
    page.innerHTML = `
<div class="legal-page">
    <a href="#/dashboard" class="legal-back-link">&larr; Back to Dashboard</a>
    <h1>Privacy Policy</h1>
    <p class="legal-subtitle">Last updated: February 1, 2026</p>

    <div class="legal-section">
        <h2>1. Controller</h2>
        <p>The controller responsible for data processing is the entity identified in our <a href="#/legal/impressum">Impressum</a>.</p>
    </div>

    <div class="legal-section">
        <h2>2. Data We Collect</h2>
        <table class="legal-table">
            <thead>
                <tr><th>Category</th><th>Data</th><th>Legal Basis (GDPR)</th></tr>
            </thead>
            <tbody>
                <tr><td>Account Data</td><td>Email, username, password hash</td><td>Art. 6(1)(b) &mdash; Contract performance</td></tr>
                <tr><td>Consent Data</td><td>ToS acceptance timestamp, version, anonymized IP, user agent</td><td>Art. 6(1)(c) &mdash; Legal obligation</td></tr>
                <tr><td>Command Logs</td><td>Commands (masked), risk scores, actions taken</td><td>Art. 6(1)(b) &mdash; Contract performance</td></tr>
                <tr><td>Security Incidents</td><td>Severity, category, evidence (masked)</td><td>Art. 6(1)(b) &mdash; Contract performance</td></tr>
                <tr><td>Scan Results</td><td>Prompt scan scores, threat counts</td><td>Art. 6(1)(b) &mdash; Contract performance</td></tr>
                <tr><td>Billing Data</td><td>Stripe customer/subscription IDs</td><td>Art. 6(1)(b) &mdash; Contract performance</td></tr>
                <tr><td>Usage Data</td><td>Daily command/scan counters</td><td>Art. 6(1)(f) &mdash; Legitimate interest</td></tr>
            </tbody>
        </table>
    </div>

    <div class="legal-section">
        <h2>3. Processing Purposes</h2>
        <ul>
            <li><strong>Security monitoring:</strong> Real-time risk assessment of AI agent commands</li>
            <li><strong>Audit trail:</strong> Tamper-evident logging for forensic review</li>
            <li><strong>Account management:</strong> Authentication, authorization, profile settings</li>
            <li><strong>Billing:</strong> Subscription management via Stripe</li>
            <li><strong>Service improvement:</strong> Aggregated, anonymized usage analytics</li>
        </ul>
    </div>

    <div class="legal-section">
        <h2>4. Data Retention</h2>
        <table class="legal-table">
            <thead>
                <tr><th>Tier</th><th>Retention Period</th></tr>
            </thead>
            <tbody>
                <tr><td>Free</td><td>1 day</td></tr>
                <tr><td>Pro</td><td>30 days</td></tr>
                <tr><td>Enterprise</td><td>365 days</td></tr>
            </tbody>
        </table>
        <p>Account data is retained until you delete your account. Upon deletion, personal data is removed and audit logs are anonymized to preserve chain integrity.</p>
    </div>

    <div class="legal-section">
        <h2>5. Third-Party Services</h2>
        <table class="legal-table">
            <thead>
                <tr><th>Service</th><th>Purpose</th><th>Location</th><th>Safeguards</th></tr>
            </thead>
            <tbody>
                <tr><td>Google OAuth</td><td>Social login</td><td>USA</td><td>Standard Contractual Clauses (SCCs)</td></tr>
                <tr><td>Stripe</td><td>Payment processing</td><td>USA</td><td>Standard Contractual Clauses (SCCs)</td></tr>
                <tr><td>Gmail SMTP</td><td>Transactional emails</td><td>USA</td><td>Standard Contractual Clauses (SCCs)</td></tr>
            </tbody>
        </table>
    </div>

    <div class="legal-section">
        <h2>6. Your Rights (GDPR Art. 15-22)</h2>
        <p>You have the right to:</p>
        <ul>
            <li><strong>Access</strong> your personal data (Art. 15) &mdash; via Settings &gt; Export My Data</li>
            <li><strong>Rectification</strong> of inaccurate data (Art. 16) &mdash; via Settings &gt; Profile</li>
            <li><strong>Erasure</strong> of your data (Art. 17) &mdash; via Settings &gt; Delete Account</li>
            <li><strong>Data portability</strong> (Art. 20) &mdash; JSON export via Settings</li>
            <li><strong>Restriction</strong> of processing (Art. 18)</li>
            <li><strong>Object</strong> to processing (Art. 21)</li>
            <li><strong>Withdraw consent</strong> at any time without affecting prior processing</li>
        </ul>
        <p>To exercise these rights, use the self-service options in Settings or contact us via the address in our <a href="#/legal/impressum">Impressum</a>.</p>
    </div>

    <div class="legal-section">
        <h2>7. Security Measures</h2>
        <ul>
            <li>Passwords hashed with bcrypt (cost factor 12)</li>
            <li>JWT-based session authentication (HS256)</li>
            <li>SHA-256 tamper-evident audit chain</li>
            <li>Automatic secret masking in command logs</li>
            <li>Rate limiting on authentication endpoints</li>
            <li>IP anonymization for consent records</li>
        </ul>
    </div>

    <div class="legal-section">
        <h2>8. Cookies and Local Storage</h2>
        <p>ShieldPilot does not use cookies. We store a single JWT authentication token (<code>sentinel_token</code>) in your browser's localStorage. This is strictly necessary for the Service to function and does not require separate consent.</p>
    </div>

    <div class="legal-section">
        <h2>9. Right to Lodge a Complaint</h2>
        <p>You have the right to lodge a complaint with a supervisory authority, in particular in the EU Member State of your habitual residence, place of work, or place of the alleged infringement.</p>
    </div>

    <div class="legal-section">
        <h2>10. Changes to This Policy</h2>
        <p>We will notify you of material changes to this Privacy Policy via email at least 14 days before they take effect.</p>
    </div>
</div>`;
}


async function renderLegalImpressum() {
    const page = getPageContent();
    page.innerHTML = `
<div class="legal-page">
    <a href="#/dashboard" class="legal-back-link">&larr; Back to Dashboard</a>
    <h1>Impressum</h1>
    <p class="legal-subtitle">Legal Notice pursuant to &sect; 5 DDG</p>
    <div id="impressum-content">${Spinner()}</div>
</div>`;

    const data = await api('/api/legal/impressum');

    const container = document.getElementById('impressum-content');
    if (!data || !data.company_name) {
        container.innerHTML = `
<div class="impressum-not-configured">
    <p>Impressum information has not been configured yet.</p>
    <p>Operators: Please set the <code>legal</code> section in <code>sentinel.yaml</code>.</p>
</div>`;
        return;
    }

    container.innerHTML = `
    <div class="legal-section">
        <h2>Provider</h2>
        <p>${escapeHtml(data.company_name)}</p>
        ${data.address_line1 ? '<p>' + escapeHtml(data.address_line1) + '</p>' : ''}
        ${data.address_line2 ? '<p>' + escapeHtml(data.address_line2) + '</p>' : ''}
        ${data.country ? '<p>' + escapeHtml(data.country) + '</p>' : ''}
    </div>

    ${data.managing_director ? '<div class="legal-section"><h2>Represented by</h2><p>' + escapeHtml(data.managing_director) + '</p></div>' : ''}

    <div class="legal-section">
        <h2>Contact</h2>
        ${data.contact_email ? '<p>Email: <a href="mailto:' + escapeHtml(data.contact_email) + '">' + escapeHtml(data.contact_email) + '</a></p>' : ''}
        ${data.contact_phone ? '<p>Phone: ' + escapeHtml(data.contact_phone) + '</p>' : ''}
    </div>

    ${data.registration_court || data.registration_number ? '<div class="legal-section"><h2>Commercial Register</h2>' +
        (data.registration_court ? '<p>Court: ' + escapeHtml(data.registration_court) + '</p>' : '') +
        (data.registration_number ? '<p>Registration: ' + escapeHtml(data.registration_number) + '</p>' : '') +
    '</div>' : ''}

    ${data.vat_id ? '<div class="legal-section"><h2>VAT Identification Number</h2><p>' + escapeHtml(data.vat_id) + '</p></div>' : ''}

    <div class="legal-section">
        <h2>EU Online Dispute Resolution</h2>
        <p>The European Commission provides an online dispute resolution platform at <a href="https://ec.europa.eu/consumers/odr" target="_blank" rel="noopener">https://ec.europa.eu/consumers/odr</a>.</p>
        <p>We are not obligated and generally not willing to participate in dispute resolution proceedings before a consumer arbitration board.</p>
    </div>`;
}


function renderLegalWithdrawal() {
    const page = getPageContent();
    page.innerHTML = `
<div class="legal-page">
    <a href="#/dashboard" class="legal-back-link">&larr; Back to Dashboard</a>
    <h1>Right of Withdrawal / Widerrufsbelehrung</h1>
    <p class="legal-subtitle">Last updated: February 1, 2026</p>

    <div class="legal-section">
        <h2>Right of Withdrawal (English)</h2>
        <p>You have the right to withdraw from this contract within <strong>14 days</strong> without giving any reason.</p>
        <p>The withdrawal period will expire 14 days from the day of the conclusion of the contract.</p>
        <p>To exercise the right of withdrawal, you must inform us of your decision to withdraw from this contract by an unequivocal statement (e.g., an email). You may use the model withdrawal form below, but it is not obligatory.</p>
        <p>To meet the withdrawal deadline, it is sufficient for you to send your communication concerning your exercise of the right of withdrawal before the withdrawal period has expired.</p>
    </div>

    <div class="legal-section">
        <h2>Effects of Withdrawal</h2>
        <p>If you withdraw from this contract, we shall reimburse to you all payments received from you, without undue delay and in any event not later than 14 days from the day on which we are informed about your decision to withdraw from this contract. We will carry out such reimbursement using the same means of payment as you used for the initial transaction.</p>
    </div>

    <div class="legal-section">
        <h2>Expiry for Digital Services</h2>
        <p>The right of withdrawal expires for contracts on the supply of digital content or digital services if the trader has begun performance after the consumer has expressly consented and acknowledged that the right of withdrawal is lost once performance has begun.</p>
        <p>By subscribing and beginning to use paid features, you acknowledge that the digital service begins immediately and that you lose your right of withdrawal upon commencement of the service.</p>
    </div>

    <div class="legal-section">
        <h2>Widerrufsbelehrung (Deutsch)</h2>
        <h3>Widerrufsrecht</h3>
        <p>Sie haben das Recht, binnen vierzehn Tagen ohne Angabe von Gr&uuml;nden diesen Vertrag zu widerrufen.</p>
        <p>Die Widerrufsfrist betr&auml;gt vierzehn Tage ab dem Tag des Vertragsabschlusses.</p>
        <p>Um Ihr Widerrufsrecht auszu&uuml;ben, m&uuml;ssen Sie uns mittels einer eindeutigen Erkl&auml;rung (z.B. per E-Mail) &uuml;ber Ihren Entschluss, diesen Vertrag zu widerrufen, informieren. Die Kontaktdaten finden Sie in unserem <a href="#/legal/impressum">Impressum</a>. Sie k&ouml;nnen daf&uuml;r das unten stehende Muster-Widerrufsformular verwenden, das jedoch nicht vorgeschrieben ist.</p>
        <p>Zur Wahrung der Widerrufsfrist reicht es aus, dass Sie die Mitteilung &uuml;ber die Aus&uuml;bung des Widerrufsrechts vor Ablauf der Widerrufsfrist absenden.</p>

        <h3>Folgen des Widerrufs</h3>
        <p>Wenn Sie diesen Vertrag widerrufen, haben wir Ihnen alle Zahlungen, die wir von Ihnen erhalten haben, unverz&uuml;glich und sp&auml;testens binnen vierzehn Tagen ab dem Tag zur&uuml;ckzuzahlen, an dem die Mitteilung &uuml;ber Ihren Widerruf bei uns eingegangen ist. F&uuml;r diese R&uuml;ckzahlung verwenden wir dasselbe Zahlungsmittel, das Sie bei der urspr&uuml;nglichen Transaktion eingesetzt haben.</p>

        <h3>Erl&ouml;schen des Widerrufsrechts bei digitalen Dienstleistungen</h3>
        <p>Das Widerrufsrecht erlischt bei einem Vertrag &uuml;ber die Erbringung von digitalen Dienstleistungen, wenn der Unternehmer mit der Vertragserf&uuml;llung begonnen hat, nachdem der Verbraucher ausdr&uuml;cklich zugestimmt hat und seine Kenntnis davon best&auml;tigt hat, dass er sein Widerrufsrecht verliert.</p>
    </div>

    <div class="legal-section">
        <h2>Model Withdrawal Form / Muster-Widerrufsformular</h2>
        <div class="withdrawal-form">
            <p><em>(If you want to withdraw from the contract, please fill in and return this form / Wenn Sie den Vertrag widerrufen wollen, f&uuml;llen Sie bitte dieses Formular aus und senden Sie es zur&uuml;ck)</em></p>
            <p>To / An: <em>[See Impressum for contact details / Kontaktdaten siehe Impressum]</em></p>
            <p>I/We hereby give notice that I/we withdraw from my/our contract for the provision of the following service:<br>
            Hiermit widerrufe(n) ich/wir den von mir/uns abgeschlossenen Vertrag &uuml;ber die Erbringung der folgenden Dienstleistung:</p>
            <p><strong>ShieldPilot Subscription</strong></p>
            <p>Ordered on / Bestellt am: <span class="form-field">&nbsp;</span></p>
            <p>Name of consumer / Name des Verbrauchers: <span class="form-field">&nbsp;</span></p>
            <p>Address of consumer / Anschrift des Verbrauchers: <span class="form-field">&nbsp;</span></p>
            <p>Date / Datum: <span class="form-field">&nbsp;</span></p>
        </div>
    </div>
</div>`;
}

// Run on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
