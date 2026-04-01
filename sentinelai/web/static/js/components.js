/**
 * ShieldPilot Dashboard - Reusable UI Components
 * Vanilla JS ES module. Each function returns an HTML string.
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Escape HTML entities to prevent XSS.
 * @param {string} str
 * @returns {string}
 */
export function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Truncate a string and append "..." when it exceeds max length.
 * @param {string} text
 * @param {number} max
 * @returns {string}
 */
export function truncate(text, max) {
    if (!text) return '';
    if (text.length <= max) return text;
    return text.slice(0, max) + '\u2026';
}

/**
 * Map a numeric risk score (0-100) to a severity level string.
 * @param {number} score
 * @returns {"none"|"low"|"medium"|"high"|"critical"}
 */
export function scoreLevel(score) {
    const n = Number(score);
    if (n >= 90) return 'critical';
    if (n >= 70) return 'high';
    if (n >= 40) return 'medium';
    if (n >= 10) return 'low';
    return 'none';
}

/**
 * Return a human-readable risk label for a numeric score.
 * @param {number} score  0-100
 * @returns {string} "Safe" | "Low Risk" | "Medium" | "High" | "Critical"
 */
export function scoreLabel(score) {
    const n = Number(score);
    if (n >= 90) return 'Critical';
    if (n >= 70) return 'High';
    if (n >= 40) return 'Medium';
    if (n >= 10) return 'Low Risk';
    return 'Safe';
}

/**
 * Return a human-readable relative time string from an ISO timestamp.
 * @param {string} isoString
 * @returns {string}
 */
export function relativeTimeString(isoString) {
    if (!isoString) return '';
    const now = Date.now();
    const then = new Date(isoString).getTime();
    const diffMs = now - then;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);

    if (diffSec < 60) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    if (diffDay < 30) return `${diffDay}d ago`;
    return new Date(isoString).toLocaleDateString();
}

// ---------------------------------------------------------------------------
// ApexCharts Registry
// ---------------------------------------------------------------------------

const _pendingCharts = [];
const _activeCharts = new Map();

function registerChart(id, options) {
    _pendingCharts.push({ id, options });
}

export function mountPendingCharts() {
    while (_pendingCharts.length > 0) {
        const { id, options } = _pendingCharts.shift();
        const el = document.getElementById(id);
        if (!el) continue;
        if (_activeCharts.has(id)) {
            try { _activeCharts.get(id).destroy(); } catch (_) {}
            _activeCharts.delete(id);
        }
        const chart = new window.ApexCharts(el, options);
        chart.render();
        _activeCharts.set(id, chart);
    }
}

export function destroyAllCharts() {
    for (const [, chart] of _activeCharts) {
        try { chart.destroy(); } catch (_) {}
    }
    _activeCharts.clear();
    _pendingCharts.length = 0;
}

function chartId(prefix) {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
}

function apexDarkTheme() {
    return {
        theme: { mode: 'dark' },
        chart: {
            background: 'transparent',
            fontFamily: "'Inter', -apple-system, sans-serif",
            toolbar: { show: false },
            animations: { enabled: true, easing: 'easeinout', speed: 600 },
        },
        grid: { borderColor: 'rgba(255, 255, 255, 0.05)', strokeDashArray: 4 },
        tooltip: { theme: 'dark', style: { fontSize: '12px' } },
        xaxis: {
            labels: { style: { colors: '#94a3b8', fontSize: '11px' } },
            axisBorder: { color: 'rgba(255, 255, 255, 0.05)' },
            axisTicks: { color: 'rgba(255, 255, 255, 0.05)' },
        },
        yaxis: { labels: { style: { colors: '#94a3b8', fontSize: '11px' } } },
    };
}

// ---------------------------------------------------------------------------
// Badge Components
// ---------------------------------------------------------------------------

/**
 * Action badge (allow / warn / block).
 * @param {string} action
 * @returns {string} HTML
 */
export function Badge(action) {
    const safe = escapeHtml(action);
    return `<span class="badge badge-${safe.toLowerCase()}">${safe.toUpperCase()}</span>`;
}

/**
 * Numeric risk-score badge coloured by level, with human-readable label.
 * @param {number} score
 * @returns {string} HTML
 */
export function ScoreBadge(score) {
    const level = scoreLevel(score);
    const label = scoreLabel(score);
    return `<span class="score" data-level="${level}">${escapeHtml(String(score))} <span class="score-label">${escapeHtml(label)}</span></span>`;
}

/**
 * Severity badge (info / low / medium / high / critical).
 * @param {string} severity
 * @returns {string} HTML
 */
export function SeverityBadge(severity) {
    const safe = escapeHtml(severity);
    return `<span class="badge badge-${safe.toLowerCase()}">${safe}</span>`;
}

/**
 * Type badge for event categories (CMD, NET, INC, FILE, SCAN).
 * @param {string} type
 * @returns {string} HTML
 */
export function TypeBadge(type) {
    const safe = escapeHtml(type);
    return `<span class="type-badge type-${safe.toLowerCase()}">${safe}</span>`;
}

// ---------------------------------------------------------------------------
// Stat Card
// ---------------------------------------------------------------------------

/**
 * Dashboard stat card showing a large number and label.
 * @param {string|number} number
 * @param {string} label
 * @param {string|null} color  Optional CSS colour for the number.
 * @param {string|null} icon   Optional icon character.
 * @param {string|null} accent Optional accent class (accent-block, accent-warn, accent-allow).
 * @param {string|null} sparkline Optional pre-rendered HTML string (e.g. from SparklineChart) shown below the number.
 * @param {string|null} navigateTo Optional hash route to navigate to on click (e.g. '#/commands').
 * @returns {string} HTML
 */
export function StatCard(number, label, color = null, icon = null, accent = null, sparkline = null, navigateTo = null) {
    const numStyle = color ? ` style="color:${escapeHtml(color)}"` : '';
    const iconHtml = icon ? `<span class="stat-icon"><i data-lucide="${escapeHtml(icon)}"></i></span>` : '';
    const accentClass = accent ? ` ${escapeHtml(accent)}` : '';
    const sparklineHtml = sparkline ? `<div class="stat-sparkline">${sparkline}</div>` : '';
    const navAttr = navigateTo ? ` data-navigate="${escapeHtml(navigateTo)}"` : '';
    const navClass = navigateTo ? ' stat-card--clickable' : '';
    return `<div class="stat-card${accentClass}${navClass}"${navAttr}>
    <div class="stat-header">
        ${iconHtml}
        <div class="stat-label">${escapeHtml(label)}</div>
    </div>
    <div class="stat-number"${numStyle}>${escapeHtml(String(number))}</div>
    ${sparklineHtml}
</div>`;
}

// ---------------------------------------------------------------------------
// Data Table
// ---------------------------------------------------------------------------

/**
 * Render a data table.
 * @param {Array<{key:string, label:string, width?:string, align?:string}>} headers
 * @param {Array<Object>} rows
 * @param {{expandable?:boolean, onRowClick?:string}} options
 * @returns {string} HTML
 */
export function DataTable(headers, rows, options = {}) {
    const { expandable = false, onRowClick = null } = options;

    // Add chevron column header if expandable
    const chevronTh = expandable ? '<th style="width:32px"></th>' : '';

    const ths = headers.map(h => {
        const style = [];
        if (h.width) style.push(`width:${escapeHtml(h.width)}`);
        if (h.align) style.push(`text-align:${escapeHtml(h.align)}`);
        const styleAttr = style.length ? ` style="${style.join(';')}"` : '';
        return `<th${styleAttr}>${escapeHtml(h.label)}</th>`;
    }).join('');

    const trs = rows.map((row, idx) => {
        // Add chevron icon cell if expandable (accessible button with ARIA)
        const chevronTd = expandable
            ? `<td class="expand-cell">
                <button type="button" class="expand-chevron" aria-expanded="false" aria-label="Expand row details" title="Expand/collapse details">
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" width="12" height="12" aria-hidden="true">
                        <path d="M6 4l4 4-4 4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
               </td>`
            : '';

        const tds = headers.map(h => {
            const alignStyle = h.align ? ` style="text-align:${escapeHtml(h.align)}"` : '';
            const value = row[h.key] !== undefined ? row[h.key] : '';
            // Allow pre-rendered HTML by convention: if value is an object with __html, use it raw
            const cellContent = (value && typeof value === 'object' && value.__html)
                ? value.__html
                : escapeHtml(String(value));
            return `<td${alignStyle}>${cellContent}</td>`;
        }).join('');

        const clickAttr = onRowClick
            ? ` onclick="${escapeHtml(onRowClick)}(${idx}, this)" style="cursor:pointer"`
            : '';
        const expandAttr = expandable ? ' data-expandable="true"' : '';

        const colCount = expandable ? headers.length + 1 : headers.length;
        let html = `<tr data-index="${idx}"${clickAttr}${expandAttr}>${chevronTd}${tds}</tr>`;
        if (expandable) {
            html += `<tr class="expand-row" data-expand-index="${idx}" style="display:none">` +
                `<td colspan="${colCount}"><div class="expand-content" id="expand-${idx}"></div></td></tr>`;
        }
        return html;
    }).join('');

    return `<table class="data-table">
    <thead><tr>${chevronTh}${ths}</tr></thead>
    <tbody>${trs}</tbody>
</table>`;
}

// ---------------------------------------------------------------------------
// Relative Time Element
// ---------------------------------------------------------------------------

/**
 * Render a <time> element with relative text and absolute title.
 * @param {string} isoString
 * @returns {string} HTML
 */
export function RelativeTime(isoString) {
    if (!isoString) return '<time>-</time>';
    const abs = new Date(isoString).toLocaleString();
    const rel = relativeTimeString(isoString);
    return `<time class="relative-time" datetime="${escapeHtml(isoString)}" title="${escapeHtml(abs)}">${escapeHtml(rel)}</time>`;
}

// ---------------------------------------------------------------------------
// Command Text
// ---------------------------------------------------------------------------

/**
 * Render a truncated command inside a <code> element.
 * @param {string} text
 * @param {number} maxLen
 * @returns {string} HTML
 */
export function CommandText(text, maxLen = 50) {
    const full = escapeHtml(text || '');
    const short = escapeHtml(truncate(text || '', maxLen));
    return `<code class="cmd" title="${full}">${short}</code>`;
}

// ---------------------------------------------------------------------------
// Signal List (command detail)
// ---------------------------------------------------------------------------

/**
 * Render a detailed list of analysis signals with evidence, analyzer, weight.
 * @param {Array<{category:string, description:string, score:number, weight?:number, evidence?:string, analyzer?:string}>} signals
 * @returns {string} HTML
 */
export function SignalList(signals) {
    if (!signals || signals.length === 0) {
        return '<div class="signal-list empty">No signals triggered &mdash; all analyzers returned clean.</div>';
    }
    const items = signals.map(s => {
        const weight = s.weight !== undefined ? s.weight : 1.0;
        const weighted = Math.round(s.score * weight);
        const evidence = s.evidence
            ? `<div class="signal-evidence"><span class="evidence-label">Evidence:</span> <code>${escapeHtml(s.evidence)}</code></div>`
            : '';
        const analyzerTag = s.analyzer
            ? `<span class="signal-analyzer">${escapeHtml(s.analyzer)}</span>`
            : '';
        return `<div class="signal-item">
    <div class="signal-header">
        <span class="signal-category">${Badge(s.category || 'info')}</span>
        ${analyzerTag}
        <span class="signal-scores">${ScoreBadge(s.score)} <span class="signal-weight">&times;${weight.toFixed(1)} = ${weighted}</span></span>
    </div>
    <div class="signal-body">
        <div class="signal-desc">${escapeHtml(s.description)}</div>
        ${evidence}
    </div>
</div>`;
    }).join('');
    return `<div class="signal-list">${items}</div>`;
}


/**
 * Render a full forensics panel for a command.
 * @param {Object} cmd - Full command object from API
 * @returns {string} HTML
 */
export function ForensicsPanel(cmd) {
    if (!cmd) return '<div class="forensics-panel empty">No data available</div>';

    const signals = cmd.signals || [];
    const signalRows = signals.map(s => {
        const weight = s.weight !== undefined ? s.weight : 1.0;
        const weighted = Math.round(s.score * weight);
        return `<tr>
            <td>${Badge(s.category || 'unknown')}</td>
            <td class="text-secondary">${escapeHtml(s.analyzer || '-')}</td>
            <td>${escapeHtml(s.description)}</td>
            <td class="text-mono">${s.score}</td>
            <td class="text-mono">&times;${weight.toFixed(1)}</td>
            <td class="text-mono">${weighted}</td>
            <td><code class="evidence-code">${escapeHtml(s.evidence || '-')}</code></td>
        </tr>`;
    }).join('');

    const signalTable = signals.length > 0
        ? `<table class="forensics-table">
            <thead><tr>
                <th>Category</th><th>Analyzer</th><th>Why it triggered</th>
                <th>Raw</th><th>Weight</th><th>Weighted</th><th>Evidence matched</th>
            </tr></thead>
            <tbody>${signalRows}</tbody>
        </table>`
        : '<p class="text-muted">No signals triggered &mdash; all 8 analyzers returned clean.</p>';

    const llmSection = cmd.llm_used && cmd.llm_reasoning
        ? `<div class="forensics-section">
            <h4 class="forensics-heading llm-heading">AI Analysis</h4>
            <blockquote class="llm-reasoning">${escapeHtml(cmd.llm_reasoning)}</blockquote>
        </div>`
        : '';

    const actionExplain = {
        block: 'Command was BLOCKED and did NOT execute. An incident was automatically created.',
        warn: 'Command was FLAGGED for manual review. Execution depended on user confirmation.',
        allow: 'Command was assessed as safe and allowed to execute normally.',
    };
    const actionText = actionExplain[(cmd.action_taken || '').toLowerCase()] || 'Unknown action.';
    const riskLevel = escapeHtml(cmd.risk_level || scoreLevel(cmd.risk_score || 0));
    const executedText = cmd.executed ? 'Yes' : 'No';
    const exitCodeText = cmd.exit_code !== null && cmd.exit_code !== undefined ? String(cmd.exit_code) : '-';
    const execTime = cmd.execution_time_ms !== undefined ? `${cmd.execution_time_ms.toFixed(1)}ms` : '-';

    return `<div class="forensics-panel">
    <div class="forensics-section">
        <h4 class="forensics-heading">Command</h4>
        <pre class="forensics-command">${escapeHtml(cmd.command || '')}</pre>
    </div>

    <div class="forensics-section">
        <h4 class="forensics-heading">Verdict</h4>
        <div class="forensics-verdict">
            <div class="verdict-row">
                <span class="verdict-label">Action</span>
                ${Badge(cmd.action_taken || 'unknown')}
                <span class="verdict-explain">${escapeHtml(actionText)}</span>
            </div>
            <div class="verdict-row">
                <span class="verdict-label">Risk Score</span>
                ${ScoreBadge(cmd.risk_score ?? 0)}
                <span class="verdict-level badge badge-${riskLevel}">${riskLevel}</span>
            </div>
        </div>
    </div>

    <div class="forensics-section">
        <h4 class="forensics-heading">Signal Breakdown <span class="text-muted">(${signals.length} analyzer${signals.length !== 1 ? 's' : ''} triggered)</span></h4>
        ${signalTable}
    </div>

    ${llmSection}

    <div class="forensics-section">
        <h4 class="forensics-heading">Execution</h4>
        <div class="forensics-meta-grid">
            <div class="meta-item"><span class="meta-label">Executed</span><span class="meta-value">${executedText}</span></div>
            <div class="meta-item"><span class="meta-label">Exit Code</span><span class="meta-value text-mono">${exitCodeText}</span></div>
            <div class="meta-item"><span class="meta-label">Analysis Time</span><span class="meta-value">${execTime}</span></div>
            <div class="meta-item"><span class="meta-label">LLM Used</span><span class="meta-value">${cmd.llm_used ? 'Yes' : 'No'}</span></div>
        </div>
    </div>

    ${cmd.output_snippet ? `<div class="forensics-section">
        <h4 class="forensics-heading">Output</h4>
        <pre class="forensics-output">${escapeHtml(cmd.output_snippet)}</pre>
    </div>` : ''}

    <div class="forensics-section forensics-chain">
        <h4 class="forensics-heading">Tamper-Proof Chain</h4>
        <div class="meta-item"><span class="meta-label">Chain Hash</span><code class="chain-hash">${escapeHtml(cmd.chain_hash || '-')}</code></div>
    </div>
</div>`;
}

// ---------------------------------------------------------------------------
// Threat List (scan detail)
// ---------------------------------------------------------------------------

/**
 * Render a numbered list of threats from a scan.
 * @param {Array<{severity:string, pattern:string, matched:string, mitigation:string}>} threats
 * @returns {string} HTML
 */
export function ThreatList(threats) {
    if (!threats || threats.length === 0) {
        return '<div class="threat-list empty">No threats detected</div>';
    }
    const items = threats.map((t, i) => `<div class="threat-item">
    <span class="threat-number">${i + 1}.</span>
    ${SeverityBadge(t.severity || 'info')}
    <strong class="threat-pattern">${escapeHtml(t.pattern)}</strong>
    <div class="threat-match"><code>${escapeHtml(t.matched)}</code></div>
    <div class="threat-mitigation">${escapeHtml(t.mitigation)}</div>
</div>`).join('');
    return `<div class="threat-list">${items}</div>`;
}

// ---------------------------------------------------------------------------
// Incident Card
// ---------------------------------------------------------------------------

/**
 * Human-readable category labels for non-technical users.
 */
const CATEGORY_LABELS = {
    destructive_filesystem: 'File Deletion',
    privilege_escalation: 'Privilege Escalation',
    network_exfiltration: 'Data Transfer',
    credential_access: 'Credential Access',
    persistence: 'Persistent Install',
    obfuscation: 'Obfuscated Code',
    malware_pattern: 'Malware Pattern',
    supply_chain: 'Supply Chain',
    injection: 'AI Manipulation',
};

/**
 * Return a human-readable label for a risk category.
 * @param {string} raw
 * @returns {string}
 */
function categoryLabel(raw) {
    return CATEGORY_LABELS[raw] || (raw || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

/**
 * Enhanced severity badge with icon prefix for incidents.
 * @param {string} severity - "critical" | "high" | "medium" | "low" | "info"
 * @returns {string} HTML
 */
export function EnhancedSeverityBadge(severity) {
    const s = (severity || 'info').toLowerCase();
    const icons = { critical: '\uD83D\uDD34', high: '\uD83D\uDFE0', medium: '\uD83D\uDFE1', low: '\uD83D\uDD35', info: '\u2139\uFE0F' };
    const icon = icons[s] || icons.info;
    return `<span class="badge badge-${escapeHtml(s)} enhanced-severity-badge">${icon} ${escapeHtml(severity || 'info')}</span>`;
}

/**
 * Incident status indicator (open with pulsing dot or resolved with checkmark).
 * @param {Object} incident
 * @returns {string} HTML
 */
export function IncidentStatus(incident) {
    if (incident.resolved) {
        const resolvedTime = incident.resolved_at ? ` ${relativeTimeString(incident.resolved_at)}` : '';
        return `<span class="incident-status incident-status--resolved" title="Resolved${escapeHtml(resolvedTime)}">
            <span class="incident-status-icon">&#10003;</span>
            <span class="incident-status-text">Resolved</span>
            ${incident.resolved_at ? `<span class="incident-status-time">${RelativeTime(incident.resolved_at)}</span>` : ''}
        </span>`;
    }
    return `<span class="incident-status incident-status--open" title="Open">
        <span class="incident-status-dot"></span>
        <span class="incident-status-text">Open</span>
    </span>`;
}

/**
 * Render a detailed incident card with description, evidence, and linked command.
 * @param {Object} incident - Full incident object from API
 * @returns {string} HTML
 */
export function IncidentCard(incident) {
    // W2: Action buttons — Resolve + Investigate (only for unresolved)
    const resolveBtn = incident.resolved
        ? `<div class="resolved-info">
            <span class="resolved-label">Resolved</span>
            ${incident.resolved_at ? `<span class="text-muted">${RelativeTime(incident.resolved_at)}</span>` : ''}
            ${incident.resolution_notes ? `<div class="resolution-notes">${escapeHtml(incident.resolution_notes)}</div>` : ''}
        </div>`
        : `<div class="incident-btn-group">
            <button class="btn btn-sm btn-investigate" data-incident-id="${escapeHtml(String(incident.id))}" title="Show technical details">&#128269; Investigate</button>
            <button class="btn btn-sm btn-resolve" data-incident-id="${escapeHtml(String(incident.id))}">Resolve</button>
        </div>`;

    const absTime = incident.timestamp ? new Date(incident.timestamp).toLocaleString() : '';
    const explanation = incident.explanation;
    const catLabel = categoryLabel(incident.category || 'unknown');

    // --- Display title (from explanation or category label) ---
    const displayTitle = explanation?.display_title
        ? `<h3 class="incident-title">${escapeHtml(explanation.display_title)}</h3>`
        : '';

    // --- Non-technical explanation section (default view) ---
    const explainSection = explanation ? `
        <div class="incident-explain">
            <div class="explain-field">
                <h4 class="explain-label">What happened</h4>
                <p class="explain-text">${escapeHtml(explanation.what_happened)}</p>
            </div>
            <div class="explain-field">
                <h4 class="explain-label">Why it was blocked</h4>
                <p class="explain-text">${escapeHtml(explanation.why_blocked)}</p>
            </div>
            <div class="explain-field">
                <h4 class="explain-label">Potential impact</h4>
                <p class="explain-text">${escapeHtml(explanation.severity_explanation)}</p>
            </div>
            ${explanation.action_guidance ? `<div class="explain-field">
                <h4 class="explain-label">What you should do</h4>
                <p class="explain-text explain-action-text">${escapeHtml(explanation.action_guidance)}</p>
            </div>` : ''}
            <div class="explain-field">
                <h4 class="explain-label">What could have happened</h4>
                <p class="explain-text explain-hypothetical-text">${escapeHtml(explanation.hypothetical)}</p>
            </div>
            <div class="explain-field">
                <div class="explain-impact-box ${(explanation.technical_details?.risk_score ?? 0) >= 70 ? 'impact-danger' : 'impact-safe'}">
                    ${escapeHtml(explanation.user_impact)}
                </div>
            </div>
        </div>` : (incident.description
            ? `<div class="incident-description">${escapeHtml(incident.description)}</div>`
            : '');

    // --- Technical details (collapsed by default) ---
    const techSignals = explanation?.technical_details?.signals;
    const techSection = explanation ? `
        <details class="incident-technical">
            <summary class="technical-toggle">
                <span class="toggle-icon">&#9654;</span>
                Technical Details
                <span class="tech-meta">${explanation.technical_details?.signals_count || 0} signal(s) &middot; score ${explanation.technical_details?.risk_score ?? 0}/100</span>
            </summary>
            <div class="technical-content">
                ${incident.evidence ? `<div class="tech-evidence"><span class="evidence-label">Evidence:</span> <code>${escapeHtml(incident.evidence)}</code></div>` : ''}
                ${incident.command_id ? `<div class="tech-command"><span class="evidence-label">Linked Command:</span> <a href="#" class="cmd-link" data-command-id="${escapeHtml(String(incident.command_id))}">#${escapeHtml(String(incident.command_id))}</a></div>` : ''}
                ${techSignals && techSignals.length > 0 ? `
                    <div class="tech-signals">
                        ${techSignals.map(s => `<div class="tech-signal-row">
                            <span class="tech-signal-category">${Badge(categoryLabel(s.category || 'unknown'))}</span>
                            <span class="tech-signal-desc">${escapeHtml(s.description || '')}</span>
                            <span class="tech-signal-score">${s.score || 0}</span>
                        </div>`).join('')}
                    </div>` : ''}
            </div>
        </details>` : `<div class="incident-details">
            <div class="incident-meta">
                <span class="incident-category">${Badge(catLabel)}</span>
                <span class="incident-time" title="${escapeHtml(absTime)}">${RelativeTime(incident.timestamp)}</span>
            </div>
            ${incident.evidence ? `<div class="incident-evidence"><span class="evidence-label">Evidence:</span> <code>${escapeHtml(incident.evidence)}</code></div>` : ''}
            ${incident.command_id ? `<div class="incident-command-link"><span class="evidence-label">Linked Command:</span> <a href="#" class="cmd-link" data-command-id="${escapeHtml(String(incident.command_id))}">#${escapeHtml(String(incident.command_id))}</a></div>` : ''}
        </div>`;

    return `<div class="incident-card severity-${escapeHtml((incident.severity || 'info').toLowerCase())}">
    <div class="incident-header">
        <div class="incident-header-left">
            ${EnhancedSeverityBadge(incident.severity || 'info')}
            <span class="incident-id text-muted">#${escapeHtml(String(incident.id))}</span>
            <span class="incident-category-label">${escapeHtml(catLabel)}</span>
            <span class="incident-time" title="${escapeHtml(absTime)}">${RelativeTime(incident.timestamp)}</span>
        </div>
        <div class="incident-header-right">
            ${IncidentStatus(incident)}
            <div class="incident-actions">${resolveBtn}</div>
        </div>
    </div>
    ${displayTitle}
    ${explainSection}
    ${techSection}
</div>`;
}

// ---------------------------------------------------------------------------
// Activity Item
// ---------------------------------------------------------------------------

/**
 * Status pill showing the action taken (BLOCKED / WARNED / ALLOWED).
 * @param {string} action - "block" | "warn" | "allow"
 * @returns {string} HTML
 */
export function StatusPill(action) {
    const a = (action || '').toLowerCase();
    const labels = { block: 'BLOCKED', warn: 'WARNED', allow: 'ALLOWED' };
    const label = labels[a] || escapeHtml((action || '').toUpperCase());
    return `<span class="status-pill status-pill--${escapeHtml(a)}">${label}</span>`;
}

/**
 * Render an activity feed item.
 * @param {{timestamp:string, type:string, summary:string, score?:number}} event
 * @returns {string} HTML
 */
export function ActivityItem(event) {
    const scoreHtml = (event.score !== undefined && event.score !== null)
        ? `<span class="activity-score">${ScoreBadge(event.score)}</span>`
        : '';

    // W1: Color-coded severity/action indicator (pulsing dot for block)
    let severityHtml = '';
    const action = (event.action || '').toLowerCase();
    const severity = (event.severity || '').toLowerCase();
    if (action === 'block' || severity === 'critical' || severity === 'high') {
        severityHtml = '<span class="activity-severity activity-severity--block" title="Blocked / High Severity"></span>';
    } else if (action === 'warn' || severity === 'medium') {
        severityHtml = '<span class="activity-severity activity-severity--warn" title="Warned / Medium Severity"></span>';
    } else if (action === 'allow' || severity === 'low' || severity === 'info') {
        severityHtml = '<span class="activity-severity activity-severity--allow" title="Allowed / Low Severity"></span>';
    }

    // W1: Status pill replaces the old Badge(action) for command events
    const statusPillHtml = action && (event.type === 'CMD' || event.type === 'SCAN')
        ? ` ${StatusPill(action)}`
        : '';

    // Add severity badge for incident events
    const sevBadgeHtml = severity && (event.type === 'INC' || event.type === 'INCIDENT')
        ? ` ${SeverityBadge(severity)}`
        : '';

    // W1: Determine row tint class based on action/severity
    let rowTintClass = '';
    if (action === 'block' || severity === 'critical' || severity === 'high') {
        rowTintClass = ' activity-item--block';
    } else if (action === 'warn' || severity === 'medium') {
        rowTintClass = ' activity-item--warn';
    }

    return `<div class="activity-item${rowTintClass}" data-id="${escapeHtml(String(event.id || ''))}" data-type="${escapeHtml(event.type || '')}">
    ${severityHtml}
    <span class="activity-time">${RelativeTime(event.timestamp)}</span>
    ${TypeBadge(event.type || 'CMD')}
    <span class="activity-summary">${escapeHtml(event.summary)}</span>
    ${statusPillHtml}${sevBadgeHtml}
    ${scoreHtml}
</div>`;
}

// ---------------------------------------------------------------------------
// Activity Filter Bar
// ---------------------------------------------------------------------------

/**
 * Render a filter bar for activity feed items.
 * Uses existing CSS classes: activity-filter-bar, activity-filter-group, activity-type-btn.
 * @param {string} activeFilter - Currently active filter type: '' (all), 'CMD', 'INC', 'SCAN', 'NET', 'FILE'
 * @returns {string} HTML
 */
export function ActivityFilterBar(activeFilter = '') {
    const types = [
        { value: '', label: 'All' },
        { value: 'CMD', label: 'Commands' },
        { value: 'INC', label: 'Incidents' },
        { value: 'SCAN', label: 'Scans' },
    ];
    const buttons = types.map(t => {
        const isActive = (activeFilter || '') === t.value;
        return `<button class="activity-type-btn${isActive ? ' active' : ''}" data-type="${escapeHtml(t.value)}" aria-pressed="${isActive ? 'true' : 'false'}">${escapeHtml(t.label)}</button>`;
    }).join('');

    return `<div class="activity-filter-bar" role="toolbar" aria-label="Activity feed filters">
    <div class="activity-filter-group" role="group" aria-label="Event type filter">
        ${buttons}
    </div>
</div>`;
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

/**
 * Render pagination controls.
 * @param {number} currentPage  1-based
 * @param {number} totalPages
 * @param {string} onPageChange  Global function name to call with page number.
 * @returns {string} HTML
 */
export function Pagination(currentPage, totalPages, onPageChange) {
    if (totalPages <= 1) return '';
    const pages = [];

    // Previous
    pages.push(currentPage > 1
        ? `<button class="page-btn" onclick="${escapeHtml(onPageChange)}(${currentPage - 1})">&laquo; Prev</button>`
        : `<button class="page-btn" disabled>&laquo; Prev</button>`);

    // Page numbers (show up to 7 with ellipsis)
    const start = Math.max(1, currentPage - 3);
    const end = Math.min(totalPages, currentPage + 3);

    if (start > 1) {
        pages.push(`<button class="page-btn" onclick="${escapeHtml(onPageChange)}(1)">1</button>`);
        if (start > 2) pages.push('<span class="page-ellipsis">&hellip;</span>');
    }

    for (let p = start; p <= end; p++) {
        const active = p === currentPage ? ' active' : '';
        pages.push(`<button class="page-btn${active}" onclick="${escapeHtml(onPageChange)}(${p})">${p}</button>`);
    }

    if (end < totalPages) {
        if (end < totalPages - 1) pages.push('<span class="page-ellipsis">&hellip;</span>');
        pages.push(`<button class="page-btn" onclick="${escapeHtml(onPageChange)}(${totalPages})">${totalPages}</button>`);
    }

    // Next
    pages.push(currentPage < totalPages
        ? `<button class="page-btn" onclick="${escapeHtml(onPageChange)}(${currentPage + 1})">Next &raquo;</button>`
        : `<button class="page-btn" disabled>Next &raquo;</button>`);

    return `<nav class="pagination">${pages.join('')}</nav>`;
}

// ---------------------------------------------------------------------------
// Command Filter Bar
// ---------------------------------------------------------------------------

/**
 * Render the filter bar for the commands page.
 * @returns {string} HTML
 */
export function CommandFilterBar() {
    return `<div class="filter-bar">
    <div class="filter-group filter-actions">
        <button class="filter-btn active" data-action="">All</button>
        <button class="filter-btn" data-action="allow">Allow</button>
        <button class="filter-btn" data-action="warn">Warn</button>
        <button class="filter-btn" data-action="block">Block</button>
    </div>
    <div class="filter-group cmd-category-filter">
        <select id="cmd-category" class="filter-input" aria-label="Filter by signal category">
            <option value="">All Categories</option>
            <option value="Filesystem Access">Filesystem Access</option>
            <option value="Network Exfiltration">Network Exfiltration</option>
            <option value="Credential Access">Credential Access</option>
            <option value="Supply Chain">Supply Chain</option>
            <option value="Privilege Escalation">Privilege Escalation</option>
            <option value="Prompt Injection">Prompt Injection</option>
            <option value="Resource Abuse">Resource Abuse</option>
            <option value="Data Destruction">Data Destruction</option>
        </select>
    </div>
    <div class="filter-group filter-risk" role="group" aria-label="Risk score range filter">
        <label id="risk-label">Risk:</label>
        <input type="number" id="risk-min" class="filter-input" placeholder="0" min="0" max="100" aria-label="Minimum risk score" aria-describedby="risk-label" />
        <span aria-hidden="true">&ndash;</span>
        <input type="number" id="risk-max" class="filter-input" placeholder="100" min="0" max="100" aria-label="Maximum risk score" aria-describedby="risk-label" />
    </div>
    <div class="filter-group cmd-date-filter" role="group" aria-label="Date range filter">
        <label id="date-label">Date:</label>
        <input type="date" id="cmd-since" class="filter-input" aria-label="Start date" aria-describedby="date-label" />
        <span aria-hidden="true">&ndash;</span>
        <input type="date" id="cmd-until" class="filter-input" aria-label="End date" aria-describedby="date-label" />
    </div>
    <div class="filter-group filter-search">
        <input type="text" id="cmd-search" class="filter-input search-input" placeholder="Search commands\u2026" aria-label="Search commands" />
    </div>
</div>`;
}

// ---------------------------------------------------------------------------
// Empty State / Spinner
// ---------------------------------------------------------------------------

/**
 * Render a centered empty state message.
 * @param {string} message
 * @param {string} hint
 * @returns {string} HTML
 */
export function EmptyState(message, hint = '', icon = 'inbox') {
    const hintHtml = hint ? `<p class="empty-hint">${escapeHtml(hint)}</p>` : '';
    return `<div class="empty-state">
    <div class="empty-icon"><i data-lucide="${escapeHtml(icon)}"></i></div>
    <p class="empty-message">${escapeHtml(message)}</p>
    ${hintHtml}
</div>`;
}

/**
 * Render a loading spinner.
 * @returns {string} HTML
 */
export function Spinner(type = 'ring') {
    if (type === 'skeleton-chart') return '<div class="skeleton skeleton-chart"></div>';
    if (type === 'skeleton-card') return '<div class="skeleton skeleton-card"></div>';
    if (type === 'skeleton-grid') return SkeletonGrid();
    return '<div class="spinner"><div class="spinner-ring"></div></div>';
}

/**
 * Render a grid of skeleton cards for dashboard-style loading.
 * @param {number} count - Number of skeleton cards to render
 * @returns {string} HTML
 */
export function SkeletonGrid(count = 4) {
    const cards = Array(count).fill(0).map(() => `<div class="skeleton-card-full">
        <div class="skeleton skeleton-text medium"></div>
        <div class="skeleton skeleton-text short"></div>
        <div class="skeleton skeleton-text full"></div>
    </div>`).join('');
    return `<div class="skeleton-grid">${cards}</div>`;
}

// ---------------------------------------------------------------------------
// Toast Notification
// ---------------------------------------------------------------------------

/**
 * Show a toast notification. Auto-removes after 3 seconds.
 * @param {string} message
 * @param {"success"|"error"|"warning"|"info"} type
 */
export function showToast(message, type = 'success') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${escapeHtml(type)}`;
    toast.textContent = message; // textContent is XSS-safe
    container.appendChild(toast);

    // Trigger entrance animation
    requestAnimationFrame(() => toast.classList.add('toast-visible'));

    setTimeout(() => {
        toast.classList.remove('toast-visible');
        toast.addEventListener('transitionend', () => toast.remove());
        // Fallback removal if transitionend doesn't fire
        setTimeout(() => { if (toast.parentNode) toast.remove(); }, 500);
    }, 3000);
}

// ---------------------------------------------------------------------------
// Modal Dialog
// ---------------------------------------------------------------------------

/**
 * Show a modal dialog.
 * @param {string} title
 * @param {string} bodyHTML  Pre-sanitised HTML for the body.
 * @param {Function|null} onConfirm  Called when Confirm is clicked. If null, only a Close button is shown.
 */
export function showModal(title, bodyHTML, onConfirm = null) {
    // Remove existing modal if any
    const existing = document.getElementById('sentinel-modal');
    if (existing) existing.remove();

    const confirmBtn = onConfirm
        ? '<button class="btn btn-primary" id="modal-confirm">Confirm</button>'
        : '';

    const overlay = document.createElement('div');
    overlay.id = 'sentinel-modal';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal">
    <div class="modal-header">
        <h2 class="modal-title">${escapeHtml(title)}</h2>
        <button class="modal-close" id="modal-close-btn">&times;</button>
    </div>
    <div class="modal-body">${bodyHTML}</div>
    <div class="modal-footer">
        <button class="btn btn-secondary" id="modal-cancel">Close</button>
        ${confirmBtn}
    </div>
</div>`;

    document.body.appendChild(overlay);

    const modal = overlay.querySelector('.modal');
    const close = () => {
        overlay.remove();
        document.removeEventListener('keydown', trapFocus);
    };
    overlay.querySelector('#modal-close-btn').addEventListener('click', close);
    overlay.querySelector('#modal-cancel').addEventListener('click', close);
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) close();
    });

    if (onConfirm) {
        overlay.querySelector('#modal-confirm').addEventListener('click', () => {
            onConfirm();
            close();
        });
    }

    // Focus trap: Tab cycles only through modal elements
    function trapFocus(e) {
        if (e.key === 'Escape') { close(); return; }
        if (e.key !== 'Tab') return;
        const focusable = modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey) {
            if (document.activeElement === first) { e.preventDefault(); last.focus(); }
        } else {
            if (document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
    }
    document.addEventListener('keydown', trapFocus);

    // Auto-focus first focusable element
    const firstFocusable = modal.querySelector('button, [href], input, select, textarea');
    if (firstFocusable) firstFocusable.focus();
}

/**
 * Show a paywall modal for admin-only features.
 * @param {string} feature  Feature name (for tracking/analytics)
 */
export function showPaywallModal(feature) {
    const existing = document.getElementById('paywall-modal');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'paywall-modal';
    overlay.className = 'paywall-modal-overlay';
    overlay.innerHTML = `<div class="paywall-modal">
    <div class="paywall-icon">🔒</div>
    <h3>Paid Feature</h3>
    <p>Unlock full blocked activity history and more with ShieldPilot Pro.</p>
    <p class="paywall-subtext">1,000 commands/day, CSV exports, and 30-day history.</p>
    <a href="#/pricing" class="btn btn-primary paywall-upgrade-btn" id="paywall-upgrade">View Plans</a>
    <button class="btn btn-sm btn-secondary" id="paywall-close" style="margin-top: 8px;">Not now</button>
</div>`;

    document.body.appendChild(overlay);

    const close = () => overlay.remove();
    overlay.querySelector('#paywall-close').addEventListener('click', close);
    overlay.querySelector('#paywall-upgrade').addEventListener('click', close);
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) close();
    });
}

// ---------------------------------------------------------------------------
// Chart: Risk Distribution (horizontal stacked bar)
// ---------------------------------------------------------------------------

/**
 * Render a vertical bar chart showing risk distribution.
 * @param {number} allowed
 * @param {number} warned
 * @param {number} blocked
 * @returns {string} HTML
 */
export function RiskDistributionChart(allowed, warned, blocked, emptyWindowLabel = '24 hours') {
    const total = allowed + warned + blocked;
    if (total === 0) {
        return `<div class="chart-empty">No commands in the last ${escapeHtml(emptyWindowLabel)}</div>`;
    }
    const id = chartId('risk-dist');
    registerChart(id, {
        ...apexDarkTheme(),
        chart: { ...apexDarkTheme().chart, type: 'bar', height: 200 },
        plotOptions: { bar: { horizontal: true, barHeight: '60%', borderRadius: 4 } },
        series: [{ name: 'Commands', data: [allowed, warned, blocked] }],
        colors: ['#22c55e', '#eab308', '#ef4444'],
        xaxis: { ...apexDarkTheme().xaxis, categories: ['Allowed', 'Warned', 'Blocked'] },
        dataLabels: {
            enabled: true,
            style: { fontSize: '12px', fontFamily: "'JetBrains Mono', monospace" },
            formatter: (val) => `${val} (${Math.round((val / total) * 100)}%)`,
        },
        legend: { show: false },
    });
    return `<div id="${id}" class="apex-chart-container"></div>`;
}

// ---------------------------------------------------------------------------
// Chart: Timeline (SVG bar chart for hourly data)
// ---------------------------------------------------------------------------

/**
 * Render an SVG bar chart for hourly command activity.
 * @param {Array<{hour:string|number, count:number, avgScore:number}>} data
 * @returns {string} SVG HTML
 */
export function TimelineChart(data) {
    if (!data || data.length === 0) {
        return '<div class="chart-empty">No timeline data</div>';
    }
    const id = chartId('timeline');
    registerChart(id, {
        ...apexDarkTheme(),
        chart: { ...apexDarkTheme().chart, type: 'area', height: 220 },
        series: [{ name: 'Commands', data: data.map(d => d.count) }],
        xaxis: { ...apexDarkTheme().xaxis, categories: data.map(d => `${d.hour}:00`), tickAmount: Math.min(data.length, 12) },
        colors: ['#3b82f6'],
        fill: { type: 'gradient', gradient: { shadeIntensity: 1, opacityFrom: 0.35, opacityTo: 0.05 } },
        stroke: { curve: 'smooth', width: 2 },
        dataLabels: { enabled: false },
    });
    return `<div id="${id}" class="apex-chart-container"></div>`;
}

// ---------------------------------------------------------------------------
// Chart: Score Histogram (K2)
// ---------------------------------------------------------------------------

/**
 * Render an SVG horizontal bar chart grouping risk scores into 10 buckets.
 * @param {number[]} scores - Array of risk scores (0-100)
 * @returns {string} HTML
 */
export function ScoreHistogramChart(scores) {
    if (!scores || scores.length === 0) {
        return '<div class="chart-empty">No score data available</div>';
    }
    const buckets = Array.from({ length: 10 }, () => 0);
    scores.forEach(s => { const idx = Math.min(9, Math.floor(Number(s) / 10)); buckets[idx]++; });
    const labels = ['0-9','10-19','20-29','30-39','40-49','50-59','60-69','70-79','80-89','90-100'];
    const id = chartId('score-hist');
    registerChart(id, {
        ...apexDarkTheme(),
        chart: { ...apexDarkTheme().chart, type: 'bar', height: 260 },
        plotOptions: { bar: { horizontal: true, borderRadius: 3, distributed: true } },
        series: [{ name: 'Commands', data: buckets }],
        colors: ['#22c55e','#22c55e','#22c55e','#22c55e','#eab308','#eab308','#eab308','#ef4444','#ef4444','#ef4444'],
        xaxis: { ...apexDarkTheme().xaxis, categories: labels },
        dataLabels: { enabled: true, style: { fontSize: '10px' } },
        legend: { show: false },
    });
    return `<div id="${id}" class="apex-chart-container"></div>`;
}

// ---------------------------------------------------------------------------
// Chart: Injection Timeline (K4)
// ---------------------------------------------------------------------------

/**
 * Render a vertical timeline of scan results with color-coded dots.
 * @param {Array<{timestamp:string, overall_score:number, threat_count:number, threats:Array}>} scans
 * @returns {string} HTML
 */
export function InjectionTimelineChart(scans) {
    if (!scans || scans.length === 0) {
        return '<div class="chart-empty">No scan data for timeline</div>';
    }

    function dotColor(score) {
        const n = Number(score) || 0;
        if (n >= 70) return 'var(--color-block)';
        if (n >= 40) return 'var(--color-warn)';
        return 'var(--color-allow)';
    }

    function dotLabel(score) {
        const n = Number(score) || 0;
        if (n >= 70) return 'high risk';
        if (n >= 40) return 'medium risk';
        return 'low risk';
    }

    const items = scans.map((scan, i) => {
        const ts = scan.timestamp ? new Date(scan.timestamp).toLocaleString() : '-';
        const relTime = relativeTimeString(scan.timestamp);
        const score = scan.overall_score ?? 0;
        const threatCount = scan.threat_count ?? (scan.threats ? scan.threats.length : 0);
        const firstCategory = scan.threats && scan.threats.length > 0
            ? (scan.threats[0].pattern || scan.threats[0].category || 'unknown')
            : '';
        const isLast = i === scans.length - 1;

        return `<div class="timeline-item" role="listitem" aria-label="Scan at ${escapeHtml(ts)}, score ${score}, ${threatCount} threats, ${dotLabel(score)}">
    <div class="timeline-marker">
        <div class="timeline-dot" style="background-color: ${dotColor(score)};"></div>
        ${!isLast ? '<div class="timeline-line"></div>' : ''}
    </div>
    <div class="timeline-content">
        <div class="timeline-header">
            <time class="timeline-time" datetime="${escapeHtml(scan.timestamp || '')}" title="${escapeHtml(ts)}">${escapeHtml(relTime)}</time>
            ${ScoreBadge(score)}
            <span class="timeline-threat-count">${threatCount} threat${threatCount !== 1 ? 's' : ''}</span>
        </div>
        ${firstCategory ? `<div class="timeline-category">${escapeHtml(firstCategory)}</div>` : ''}
    </div>
</div>`;
    }).join('');

    return `<div class="injection-timeline" role="list" aria-label="Injection scan timeline">${items}</div>`;
}


// ---------------------------------------------------------------------------
// Chart: Daily Commands Stacked Bar (K2 Enhancement)
// ---------------------------------------------------------------------------

/**
 * Render an SVG stacked bar chart showing daily commands broken down by action.
 * @param {Array<{date:string, commands:number, blocked:number, warned:number, scans?:number, incidents?:number}>} daily
 * @returns {string} HTML
 */
export function DailyCommandsChart(daily) {
    if (!daily || daily.length === 0) {
        return EmptyState('No daily command data available.', 'Check back after some activity.');
    }
    const dates = daily.map(d => d.date || '');
    const allowed = daily.map(d => Math.max(0, (d.commands || 0) - (d.blocked || 0) - (d.warned || 0)));
    const warned = daily.map(d => d.warned || 0);
    const blocked = daily.map(d => d.blocked || 0);
    const id = chartId('daily-cmd');
    registerChart(id, {
        ...apexDarkTheme(),
        chart: { ...apexDarkTheme().chart, type: 'area', height: 280, stacked: true },
        series: [
            { name: 'Allowed', data: allowed },
            { name: 'Warned', data: warned },
            { name: 'Blocked', data: blocked },
        ],
        colors: ['#22c55e', '#eab308', '#ef4444'],
        xaxis: { ...apexDarkTheme().xaxis, categories: dates, type: 'category' },
        fill: { type: 'gradient', gradient: { shadeIntensity: 1, opacityFrom: 0.4, opacityTo: 0.05 } },
        stroke: { curve: 'smooth', width: 2 },
        dataLabels: { enabled: false },
        legend: { position: 'top', labels: { colors: '#94a3b8' } },
    });
    return `<div id="${id}" class="apex-chart-container"></div>`;
}

// ---------------------------------------------------------------------------
// Health: Component Status Card (K6)
// ---------------------------------------------------------------------------

/**
 * Render a health component card with status dot, title, and body content.
 * @param {string} title
 * @param {string} status - "ok"|"healthy"|"degraded"|"error"|"unchecked"
 * @param {string} bodyHtml - Pre-sanitised HTML for the body
 * @returns {string} HTML
 */
export function HealthComponent(title, status, bodyHtml) {
    const statusNorm = (status || 'unknown').toLowerCase();
    const isOk = statusNorm === 'ok' || statusNorm === 'healthy';
    const isDegraded = statusNorm === 'degraded';
    const dotClass = isOk ? 'health-status-dot--ok'
        : isDegraded ? 'health-status-dot--degraded'
        : statusNorm === 'unchecked' ? 'health-status-dot--unchecked'
        : 'health-status-dot--error';
    const statusLabel = isOk ? 'Operational' : isDegraded ? 'Degraded' : statusNorm === 'unchecked' ? 'Unchecked' : 'Error';

    return `<div class="health-component" role="region" aria-label="${escapeHtml(title)} health status">
    <div class="health-component-header">
        <span class="health-status-dot ${dotClass}" aria-hidden="true"></span>
        <h3 class="health-component-title">${escapeHtml(title)}</h3>
        <span class="health-component-status">${escapeHtml(statusLabel)}</span>
    </div>
    <div class="health-component-body">${bodyHtml}</div>
</div>`;
}

/**
 * Render a progress bar for disk usage.
 * @param {number} pct - Percentage used (0-100)
 * @returns {string} HTML
 */
export function HealthProgressBar(pct) {
    const safePct = Math.max(0, Math.min(100, Number(pct) || 0));
    const colorClass = safePct >= 90 ? 'health-progress-bar--danger'
        : safePct >= 70 ? 'health-progress-bar--warn'
        : 'health-progress-bar--ok';
    return `<div class="health-progress-bar ${colorClass}" role="progressbar" aria-valuenow="${safePct}" aria-valuemin="0" aria-valuemax="100" aria-label="Disk usage ${safePct}%">
    <div class="health-progress-bar-fill" style="width:${safePct}%"></div>
    <span class="health-progress-bar-label">${escapeHtml(String(safePct.toFixed(1)))}%</span>
</div>`;
}

// ---------------------------------------------------------------------------
// Chart: Sparkline (K3) — ApexCharts sparkline
// ---------------------------------------------------------------------------

/**
 * Render an ApexCharts sparkline area chart (inline, tiny).
 * @param {number[]} data - Array of numeric values
 * @param {{width?:number, height?:number, color?:string, label?:string}} options
 * @returns {string} HTML
 */
export function SparklineChart(data, options = {}) {
    const {
        width = 120,
        height = 32,
        color = '#39D2C0',
        label = '',
    } = options;

    if (!data || data.length === 0) {
        return '<span class="sparkline-container sparkline-empty"></span>';
    }

    const values = data.map(v => Number(v) || 0);
    const id = chartId('spark');

    registerChart(id, {
        chart: {
            type: 'area',
            width,
            height,
            sparkline: { enabled: true },
            background: 'transparent',
            animations: { enabled: false },
        },
        series: [{ name: label || 'Value', data: values }],
        colors: [color],
        stroke: { width: 1.5, curve: 'smooth' },
        fill: {
            type: 'gradient',
            gradient: { shadeIntensity: 1, opacityFrom: 0.3, opacityTo: 0.02, stops: [0, 100] },
        },
        tooltip: { enabled: false },
        theme: { mode: 'dark' },
    });

    return `<div id="${id}" class="sparkline-container" role="img" aria-label="Sparkline chart${label ? ' for ' + escapeHtml(label) : ''}"></div>`;
}

// ---------------------------------------------------------------------------
// Chart: Block Rate Gauge (K3) — ApexCharts radialBar
// ---------------------------------------------------------------------------

/**
 * Render an ApexCharts radial bar gauge for block rate percentage.
 * @param {number} blockRate - Block rate 0-100
 * @returns {string} HTML
 */
export function BlockRateGauge(blockRate) {
    const rate = Math.max(0, Math.min(100, Number(blockRate) || 0));

    let gaugeColor;
    if (rate < 20) gaugeColor = '#22c55e';
    else if (rate <= 50) gaugeColor = '#eab308';
    else gaugeColor = '#ef4444';

    const id = chartId('gauge');

    registerChart(id, {
        chart: { type: 'radialBar', height: 180, background: 'transparent' },
        series: [Math.round(rate)],
        colors: [gaugeColor],
        plotOptions: {
            radialBar: {
                hollow: { size: '55%', background: 'transparent' },
                track: { background: 'rgba(255,255,255,0.06)', strokeWidth: '100%' },
                dataLabels: {
                    name: { show: true, fontSize: '11px', color: '#94a3b8', offsetY: 18 },
                    value: { show: true, fontSize: '22px', fontWeight: 700, color: gaugeColor, offsetY: -8, formatter: (v) => v + '%' },
                },
            },
        },
        labels: ['Block Rate'],
        theme: { mode: 'dark' },
    });

    return `<div id="${id}" class="apex-chart-container" role="img" aria-label="Block rate gauge: ${escapeHtml(String(rate.toFixed(1)))}%"></div>`;
}

// ---------------------------------------------------------------------------
// Table: Top Blocked Commands (K3)
// ---------------------------------------------------------------------------

/**
 * Render a compact table of top blocked commands.
 * @param {Array<{command:string, count:number}>} commands
 * @returns {string} HTML
 */
export function TopBlockedTable(commands) {
    if (!commands || commands.length === 0) {
        return EmptyState('No blocked commands.', 'All commands were allowed.');
    }

    const rows = commands.map(cmd => `<tr>
    <td class="top-blocked-cmd"><code>${escapeHtml(truncate(cmd.command || '', 60))}</code></td>
    <td class="top-blocked-count">${escapeHtml(String(cmd.count || 0))}</td>
</tr>`).join('');

    return `<table class="top-blocked-table" role="table" aria-label="Top blocked commands">
    <thead>
        <tr>
            <th>Command</th>
            <th class="top-blocked-count-header">Count</th>
        </tr>
    </thead>
    <tbody>${rows}</tbody>
</table>`;
}

// ---------------------------------------------------------------------------
// Chart: Score Distribution Bars (K3) — ApexCharts horizontal bar
// ---------------------------------------------------------------------------

/**
 * Render an ApexCharts horizontal bar chart for risk score distribution.
 * @param {Array<{range:string, count:number}>} buckets
 * @returns {string} HTML
 */
export function ScoreDistributionBars(buckets) {
    if (!buckets || buckets.length === 0) {
        return EmptyState('No score distribution data.', 'Check back after some commands are analyzed.');
    }

    function getColor(idx, total) {
        const ratio = idx / Math.max(1, total - 1);
        if (ratio < 0.25) return '#22c55e';
        if (ratio < 0.5) return '#3FB950';
        if (ratio < 0.75) return '#eab308';
        return '#ef4444';
    }

    const colors = buckets.map((_, i) => getColor(i, buckets.length));
    const id = chartId('score-dist');
    const base = apexDarkTheme();

    registerChart(id, {
        ...base,
        chart: { ...base.chart, type: 'bar', height: Math.max(160, buckets.length * 36) },
        series: [{ name: 'Commands', data: buckets.map(b => b.count || 0) }],
        plotOptions: {
            bar: { horizontal: true, barHeight: '60%', borderRadius: 3, distributed: true },
        },
        colors,
        xaxis: { ...base.xaxis, categories: buckets.map(b => b.range || '') },
        legend: { show: false },
        dataLabels: { enabled: true, style: { fontSize: '11px', colors: ['#e2e8f0'] } },
    });

    return `<div id="${id}" class="apex-chart-container" role="img" aria-label="Risk score distribution"></div>`;
}

// ---------------------------------------------------------------------------
// Chart: Donut Chart for Top Categories (K1) — ApexCharts donut
// ---------------------------------------------------------------------------

/**
 * Render an ApexCharts donut chart for top categories.
 * @param {Array<{name?:string, category?:string, count:number}>} categories
 * @param {string} [title='Top Categories']
 * @returns {string} HTML
 */
export function DonutChart(categories, title = 'Top Categories') {
    if (!categories || categories.length === 0) {
        return EmptyState('No category data.', 'Check back after some activity.');
    }

    const data = categories.slice(0, 6).map(c => ({
        name: c.name || c.category || 'Unknown',
        count: c.count || 0,
    }));

    const total = data.reduce((sum, d) => sum + d.count, 0);
    if (total === 0) {
        return EmptyState('No category data.', 'All counts are zero.');
    }

    const id = chartId('donut');

    registerChart(id, {
        chart: { type: 'donut', height: 260, background: 'transparent' },
        series: data.map(d => d.count),
        labels: data.map(d => d.name),
        colors: ['#39D2C0', '#eab308', '#ef4444', '#a855f7', '#3b82f6', '#22c55e'],
        plotOptions: {
            pie: {
                donut: {
                    size: '55%',
                    labels: {
                        show: true,
                        total: {
                            show: true,
                            label: 'Total',
                            fontSize: '12px',
                            color: '#94a3b8',
                            formatter: () => String(total),
                        },
                        value: { fontSize: '20px', fontWeight: 700, color: '#e2e8f0' },
                    },
                },
            },
        },
        legend: {
            position: 'bottom',
            fontSize: '11px',
            labels: { colors: '#94a3b8' },
            markers: { size: 6, offsetX: -2 },
        },
        dataLabels: { enabled: false },
        stroke: { show: false },
        tooltip: { theme: 'dark', style: { fontSize: '12px' } },
        theme: { mode: 'dark' },
    });

    return `<div id="${id}" class="apex-chart-container" role="img" aria-label="${escapeHtml(title)}"></div>`;
}

// ---------------------------------------------------------------------------
// Chart: Line Chart for Commands/Day (K1) — ApexCharts line
// ---------------------------------------------------------------------------

/**
 * Render an ApexCharts line chart with 3 series for daily command data.
 * @param {Array<{date:string, commands:number, blocked:number, warned:number}>} daily
 * @returns {string} HTML
 */
export function CommandsLineChart(daily) {
    if (!daily || daily.length === 0) {
        return EmptyState('No daily data available.', 'Check back after some activity.');
    }

    const entries = daily.map(d => ({
        date: d.date || '',
        total: d.commands || 0,
        blocked: d.blocked || 0,
        warned: d.warned || 0,
    }));

    const dates = entries.map(e => e.date);
    const id = chartId('cmd-line');
    const base = apexDarkTheme();

    registerChart(id, {
        ...base,
        chart: { ...base.chart, type: 'line', height: 260 },
        series: [
            { name: 'Total', data: entries.map(e => e.total) },
            { name: 'Blocked', data: entries.map(e => e.blocked) },
            { name: 'Warned', data: entries.map(e => e.warned) },
        ],
        colors: ['#39D2C0', '#ef4444', '#eab308'],
        stroke: {
            width: [2.5, 2, 2],
            curve: 'smooth',
            dashArray: [0, 5, 3],
        },
        xaxis: {
            ...base.xaxis,
            categories: dates,
            labels: {
                ...base.xaxis.labels,
                formatter: (val) => {
                    if (!val) return '';
                    const d = new Date(val + 'T00:00:00');
                    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                },
            },
        },
        markers: { size: [4, 0, 0], colors: ['#39D2C0'], strokeColors: '#0d1117', strokeWidth: 2 },
        legend: {
            position: 'top',
            horizontalAlign: 'right',
            fontSize: '11px',
            labels: { colors: '#94a3b8' },
            markers: { size: 6 },
        },
    });

    return `<div id="${id}" class="apex-chart-container" role="img" aria-label="Commands per day trend chart"></div>`;
}

// ---------------------------------------------------------------------------
// Chart: Risk Score Horizontal Bar (K1) — ApexCharts bar
// ---------------------------------------------------------------------------

/**
 * Render an ApexCharts horizontal bar chart for risk score buckets.
 * @param {Array<{range:string, count:number}>} buckets
 * @returns {string} HTML
 */
export function RiskScoreBarChart(buckets) {
    if (!buckets || buckets.length === 0) {
        return EmptyState('No risk score data.', 'Check back after some commands.');
    }

    function barColor(idx, total) {
        const ratio = idx / Math.max(1, total - 1);
        if (ratio < 0.25) return '#22c55e';
        if (ratio < 0.5) return '#eab308';
        if (ratio < 0.75) return '#E3B341';
        return '#ef4444';
    }

    const colors = buckets.map((_, i) => barColor(i, buckets.length));
    const id = chartId('risk-bar');
    const base = apexDarkTheme();

    registerChart(id, {
        ...base,
        chart: { ...base.chart, type: 'bar', height: Math.max(180, buckets.length * 38) },
        series: [{ name: 'Commands', data: buckets.map(b => b.count || 0) }],
        plotOptions: {
            bar: { horizontal: true, barHeight: '55%', borderRadius: 3, distributed: true },
        },
        colors,
        xaxis: { ...base.xaxis, categories: buckets.map(b => b.range || '') },
        legend: { show: false },
        dataLabels: { enabled: true, style: { fontSize: '11px', colors: ['#e2e8f0'] } },
    });

    return `<div id="${id}" class="apex-chart-container" role="img" aria-label="Risk score distribution by bucket"></div>`;
}

// ---------------------------------------------------------------------------
// Export Dropdown (K3)
// ---------------------------------------------------------------------------

/**
 * Render an export dropdown button with options.
 * @returns {string} HTML
 */
export function ExportDropdown() {
    return `<div class="export-btn-wrapper" style="position:relative;">
    <button class="btn btn-sm btn-secondary" id="export-toggle-btn" aria-haspopup="true" aria-expanded="false">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M2.75 14A1.75 1.75 0 011 12.25v-2.5a.75.75 0 011.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 00.25-.25v-2.5a.75.75 0 011.5 0v2.5A1.75 1.75 0 0113.25 14H2.75z"/>
            <path d="M7.25 7.689V2a.75.75 0 011.5 0v5.689l1.97-1.969a.749.749 0 111.06 1.06l-3.25 3.25a.749.749 0 01-1.06 0L4.22 6.78a.749.749 0 111.06-1.06l1.97 1.969z"/>
        </svg>
        Export
    </button>
    <div class="export-dropdown" id="export-dropdown-menu">
        <button class="export-option" data-export="commands">Commands (CSV)</button>
        <button class="export-option" data-export="incidents">Incidents (CSV)</button>
        <button class="export-option" data-export="scans">Scans (CSV)</button>
        <button class="export-option" data-export="report">Full Report (HTML)</button>
    </div>
</div>`;
}


// ---------------------------------------------------------------------------
// Trust Bar (W5)
// ---------------------------------------------------------------------------

/**
 * Trust/status indicator bar for the dashboard header.
 * Shows protection mode, version, and total events analyzed.
 * @param {Object} stats  Dashboard stats object.
 * @param {Object|null} config  Optional config with mode property.
 * @returns {string} HTML
 */
export function TrustBar(stats, config) {
    const mode = (config?.mode || 'enforce').toLowerCase();
    const modeLabel = mode === 'enforce' ? 'Active Protection' : mode === 'audit' ? 'Monitoring Only' : mode === 'monitor' ? 'Monitoring Only' : 'Disabled';
    const modeClass = mode === 'enforce' ? 'trust-active' : (mode === 'audit' || mode === 'monitor') ? 'trust-monitor' : 'trust-disabled';
    const totalEvents = (stats?.total_commands ?? 0) + (stats?.total_scans ?? 0);

    return `<div class="trust-bar">
        <span class="trust-item">
            <span class="trust-dot ${modeClass}"></span>
            <span class="trust-label">${escapeHtml(modeLabel)}</span>
        </span>
        <span class="trust-item">
            <span class="trust-label trust-muted">ShieldPilot v1.0</span>
        </span>
        <span class="trust-item">
            <span class="trust-label trust-muted">${escapeHtml(String(totalEvents))} events analyzed</span>
        </span>
    </div>`;
}

// ---------------------------------------------------------------------------
// Command Center Components (Lane V)
// ---------------------------------------------------------------------------

/**
 * Full-width Security Status Bar — the single most important dashboard element.
 * Shows system state (secure/warning/critical) with color coding, detail text,
 * mini-badges, and the security score.
 * @param {Object} data  SecurityStatusResponse from /api/dashboard/security-status
 * @returns {string} HTML
 */
export function SecurityStatusBar(data) {
    const state = data.state || 'secure';
    const dotClass = `dot-${state}`;
    const labelClass = `label-${state}`;
    const scoreVal = data.security_score ?? 100;
    const scoreClass = scoreVal >= 70 ? 'score-good' : scoreVal >= 40 ? 'score-mid' : 'score-bad';

    const badges = [];
    if (data.scanner_active) badges.push('Scanner Active');
    if (data.protection_mode) badges.push(`Mode: ${escapeHtml(data.protection_mode)}`);
    if (data.threats_blocked_today > 0) badges.push(`${data.threats_blocked_today} blocked today`);
    if (data.unresolved_incidents > 0) badges.push(`${data.unresolved_incidents} open incident${data.unresolved_incidents > 1 ? 's' : ''}`);

    const badgesHtml = badges.map(b => `<span class="status-mini-badge">${escapeHtml(b)}</span>`).join('');

    const lastThreat = data.last_threat_at
        ? `<span class="status-mini-badge">Last threat: ${escapeHtml(relativeTimeString(data.last_threat_at))}</span>`
        : '';

    return `<div class="security-status-bar state-${escapeHtml(state)}">
    <div class="status-bar-left">
        <div class="status-dot ${dotClass}"></div>
        <div class="status-bar-info">
            <div class="status-bar-label ${labelClass}">${escapeHtml(data.state_label || state)}</div>
            <div class="status-bar-detail">${escapeHtml(data.state_detail || '')}</div>
            <div class="status-bar-badges">${badgesHtml}${lastThreat}</div>
        </div>
    </div>
    <div class="status-bar-right">
        <div class="status-bar-score">
            <div class="cc-score-number ${scoreClass}">${scoreVal}</div>
            <div class="cc-score-of">/ 100</div>
        </div>
    </div>
</div>`;
}

/**
 * Single Operations Card with a main KPI and secondary grid of sub-KPIs.
 * @param {string} title   Card title (e.g. "Threats Blocked")
 * @param {string|number} mainValue  The big number
 * @param {string} mainTone  CSS tone class: tone-good|tone-warn|tone-bad|tone-neutral
 * @param {Array<{label:string, value:string|number, sub?:string}>} kpis  Sub-KPIs (max 4)
 * @param {string|null} trendHtml  Optional trend indicator HTML
 * @returns {string} HTML
 */
export function OpsCard(title, mainValue, mainTone, kpis = [], trendHtml = null) {
    const trend = trendHtml || '';
    const kpiCells = kpis.map(k => `<div>
        <div class="ops-kpi-label">${escapeHtml(k.label)}</div>
        <div class="ops-kpi-value tone-neutral">${escapeHtml(String(k.value))}</div>
        ${k.sub ? `<div class="ops-kpi-sub">${escapeHtml(k.sub)}</div>` : ''}
    </div>`).join('');

    return `<div class="ops-card">
    <div class="ops-card-header">
        <div class="ops-card-title">${escapeHtml(title)}</div>
        ${trend}
    </div>
    <div class="ops-kpi-value ${escapeHtml(mainTone)}" style="font-size:1.8rem;margin-bottom:var(--space-sm)">${escapeHtml(String(mainValue))}</div>
    ${kpis.length ? `<div class="ops-kpi-grid">${kpiCells}</div>` : ''}
</div>`;
}

/**
 * Security Score card with progress bar.
 * @param {number} score  0-100
 * @returns {string} HTML
 */
export function OpsScoreCard(score) {
    const s = Number(score);
    const strokeColor = s >= 70 ? 'var(--color-allow)' : s >= 40 ? 'var(--color-warn)' : 'var(--color-block)';
    const label = s >= 80 ? 'Excellent' : s >= 60 ? 'Good' : s >= 40 ? 'Needs Attention' : 'Critical';
    const tone = s >= 70 ? 'tone-good' : s >= 40 ? 'tone-warn' : 'tone-bad';

    // SVG circle gauge: radius=40, circumference=2*PI*40≈251.33
    const r = 40;
    const circ = 2 * Math.PI * r;
    const offset = circ * (1 - s / 100);

    return `<div class="ops-card ops-score-ring-card">
    <div class="ops-card-header">
        <div class="ops-card-title">Security Score</div>
    </div>
    <div class="score-ring-container">
        <svg class="score-ring-svg" viewBox="0 0 96 96" width="96" height="96">
            <circle cx="48" cy="48" r="${r}" stroke="rgba(255,255,255,0.08)" stroke-width="7" fill="transparent"/>
            <circle cx="48" cy="48" r="${r}" stroke="${strokeColor}" stroke-width="7" fill="transparent"
                stroke-dasharray="${circ.toFixed(2)}"
                stroke-dashoffset="${offset.toFixed(2)}"
                stroke-linecap="round"
                class="score-ring-progress"
                transform="rotate(-90 48 48)"/>
        </svg>
        <div class="score-ring-value">
            <span class="score-ring-number ${tone}">${s}</span>
        </div>
    </div>
    <div class="score-ring-label">${escapeHtml(label)}</div>
</div>`;
}

/**
 * Stacked bar chart for threat timeline (blocked/warned/safe per day).
 * Pure CSS/HTML, no canvas.
 * @param {Array<{date:string, blocked:number, warned:number, safe:number}>} timeline
 * @returns {string} HTML
 */
export function ThreatTimelineChart(timeline) {
    if (!timeline || !timeline.length) {
        return EmptyState('No threat data', 'Check back after commands are analyzed.');
    }

    const dates = timeline.map(d => d.date ? d.date.slice(5) : '');
    const id = chartId('threat-tl');
    const base = apexDarkTheme();

    registerChart(id, {
        ...base,
        chart: { ...base.chart, type: 'bar', height: 240, stacked: true },
        series: [
            { name: 'Safe', data: timeline.map(d => d.safe || 0) },
            { name: 'Warned', data: timeline.map(d => d.warned || 0) },
            { name: 'Blocked', data: timeline.map(d => d.blocked || 0) },
        ],
        colors: ['#22c55e', '#eab308', '#ef4444'],
        plotOptions: { bar: { borderRadius: 2, columnWidth: '60%' } },
        xaxis: { ...base.xaxis, categories: dates },
        legend: {
            position: 'top',
            horizontalAlign: 'right',
            fontSize: '11px',
            labels: { colors: '#94a3b8' },
            markers: { size: 6 },
        },
        dataLabels: { enabled: false },
    });

    return `<div id="${id}" class="apex-chart-container" role="img" aria-label="Threat timeline chart"></div>`;
}

/**
 * Ranked list of top threat types.
 * @param {Array<{type:string, count:number}>} types
 * @returns {string} HTML
 */
export function ThreatTypesList(types) {
    if (!types || !types.length) {
        return EmptyState('No threats detected', 'Your system is clean.');
    }
    const rows = types.slice(0, 8).map(t =>
        `<div class="threat-type-row">
    <span class="threat-type-name">${escapeHtml(t.type)}</span>
    <span class="threat-type-count">${t.count}</span>
</div>`
    ).join('');
    return `<div class="threat-types-list">${rows}</div>`;
}

/**
 * Period selector buttons (24h / 7d / 30d).
 * Free-tier users are locked to 24h; 7d and 30d show a lock icon.
 * @param {string} activePeriod  "24h" | "7d" | "30d"
 * @param {boolean} isFree  true if the user is on the free tier
 * @returns {string} HTML
 */
export function PeriodSelector(activePeriod = '7d', isFree = false) {
    const periods = ['24h', '7d', '30d'];
    const btns = periods.map(p => {
        const locked = isFree && p !== '24h';
        const activeClass = p === activePeriod ? ' active' : '';
        const lockedClass = locked ? ' locked' : '';
        const lockIcon = locked ? ' <span class="lock-icon" title="Pro feature">🔒</span>' : '';
        return `<button class="period-btn${activeClass}${lockedClass}" data-period="${p}">${p}${lockIcon}</button>`;
    }).join('');
    return `<div class="period-selector">${btns}</div>`;
}

/**
 * Live indicator dot with label.
 * @returns {string} HTML
 */
export function LiveIndicator() {
    return `<div class="live-indicator"><div class="live-dot"></div>Live</div>`;
}

/**
 * Command Center header bar with title, meta info, period selector and live dot.
 * @param {string} activePeriod
 * @param {boolean} isFree  true if the user is on the free tier
 * @returns {string} HTML
 */
export function CCHeader(activePeriod = '7d', isFree = false) {
    return `<div class="cc-header">
    <div class="cc-header-left">
        <h1>Command Center</h1>
        <div class="cc-header-meta">Real-time security overview</div>
    </div>
    <div class="cc-header-right">
        ${ExportDropdown()}
        ${PeriodSelector(activePeriod, isFree)}
        ${LiveIndicator()}
    </div>
</div>`;
}

/**
 * Value banner shown at bottom of dashboard for users with no/few threats.
 * @param {number} blockedTotal
 * @returns {string} HTML
 */
export function ValueBanner(blockedTotal) {
    if (blockedTotal > 0) {
        return `<div class="value-banner">ShieldPilot has blocked <strong>${blockedTotal}</strong> potentially dangerous command${blockedTotal > 1 ? 's' : ''} from your AI agents.</div>`;
    }
    return `<div class="value-banner">ShieldPilot is actively monitoring your AI agents. <strong>All clear</strong> &mdash; no threats detected.</div>`;
}

/**
 * Lock overlay for Pro-only features.
 * @param {string} featureName
 * @returns {string} HTML
 */
export function ProFeatureLock(featureName) {
    const safe = escapeHtml(featureName);
    return `<div class="pro-feature-lock">
    <svg class="pro-feature-lock-icon" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#8b949e" stroke-width="1.5">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
    <p class="pro-feature-lock-text">${safe} is a paid feature</p>
    <a href="#/pricing" class="btn btn-primary btn-sm">View Plans</a>
</div>`;
}

/**
 * Small inline lock SVG icon for nav items.
 * @returns {string} HTML
 */
export function NavLockIcon() {
    return `<span class="nav-lock-icon" aria-label="Pro feature"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#8b949e" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>`;
}

/**
 * Upgrade CTA card for the dashboard ops-grid (free tier only).
 * @returns {string} HTML
 */
/**
 * Renders an SVG donut-style score circle for scan results.
 * The ring fill color is based on score thresholds:
 *   0-39 green (allow), 40-79 yellow (warn), 80+ red (block).
 * @param {number} score - Risk score 0-100
 * @returns {string} HTML string containing the SVG score circle
 */
export function ScanScoreCircle(score) {
    const n = Math.max(0, Math.min(100, Number(score) || 0));
    let color;
    let label;
    if (n >= 80) {
        color = 'var(--color-block)';
        label = 'Blocked';
    } else if (n >= 40) {
        color = 'var(--color-warn)';
        label = 'Warning';
    } else {
        color = 'var(--color-allow)';
        label = 'Clean';
    }
    // SVG circle math: radius=52, circumference=2*pi*52 ~= 326.73
    const radius = 52;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (n / 100) * circumference;
    return `<div class="scan-score-circle" aria-label="Risk score ${escapeHtml(String(n))} out of 100">
    <svg width="120" height="120" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="${radius}" fill="none" stroke="var(--border-default)" stroke-width="8"/>
        <circle cx="60" cy="60" r="${radius}" fill="none" stroke="${color}" stroke-width="8"
            stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
            stroke-linecap="round" transform="rotate(-90 60 60)"/>
    </svg>
    <div class="scan-score-circle-text">
        <span class="scan-score-circle-number" style="color:${color}">${escapeHtml(String(n))}</span>
        <span class="scan-score-circle-label">${escapeHtml(label)}</span>
    </div>
</div>`;
}

/**
 * Renders the enhanced scan result display with score circle, threats, and recommendation.
 * @param {object} result - Scan API result with overall_score, threats, recommendation
 * @returns {string} HTML string
 */
export function ScanResultDisplay(result) {
    const score = result.overall_score ?? 0;
    const threats = result.threats || [];
    const recommendation = result.recommendation || '';
    return `<div class="scan-result-enhanced">
    <div class="scan-result-enhanced-left">
        ${ScanScoreCircle(score)}
    </div>
    <div class="scan-result-enhanced-right">
        <div class="scan-result-enhanced-header">
            <span class="scan-result-enhanced-count">${escapeHtml(String(threats.length))} threat${threats.length !== 1 ? 's' : ''} detected</span>
        </div>
        ${threats.length > 0 ? ThreatList(threats) : '<p class="text-muted">No threats detected. The input appears safe.</p>'}
        ${recommendation ? `<div class="scan-result-recommendation">
            <strong>Recommendation:</strong> ${escapeHtml(recommendation)}
        </div>` : ''}
    </div>
</div>`;
}

/**
 * Renders a scan statistics mini-header bar.
 * @param {object} stats - { scansToday, threatsDetected, blocked }
 * @returns {string} HTML string
 */
export function ScanStatsBar(stats) {
    return `<div class="scan-stats-bar" role="region" aria-label="Scan statistics">
    <div class="scan-stats-item">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
        <span>${escapeHtml(String(stats.scansToday))} scans today</span>
    </div>
    <div class="scan-stats-divider"></div>
    <div class="scan-stats-item">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-warn)" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <span>${escapeHtml(String(stats.threatsDetected))} threats detected</span>
    </div>
    <div class="scan-stats-divider"></div>
    <div class="scan-stats-item">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-block)" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>${escapeHtml(String(stats.blocked))} blocked</span>
    </div>
</div>`;
}

/**
 * Renders a scan status badge based on score.
 * @param {number} score - Risk score 0-100
 * @returns {string} HTML string
 */
export function ScanStatusBadge(score) {
    const n = Number(score) || 0;
    if (n >= 80) return '<span class="badge badge-block">Blocked</span>';
    if (n >= 40) return '<span class="badge badge-warn">Warning</span>';
    return '<span class="badge badge-allow">Clean</span>';
}

/**
 * Renders an empty state for scans with a magnifying glass icon.
 * @returns {string} HTML string
 */
export function ScanEmptyState() {
    return `<div class="empty-state scan-empty-state">
    <svg class="scan-empty-icon" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="11" cy="11" r="8"/>
        <path d="M21 21l-4.35-4.35"/>
    </svg>
    <p class="empty-state-text">No scans yet</p>
    <p class="empty-state-hint">Try scanning some text above to detect prompt injection patterns.</p>
</div>`;
}

export function UpgradeCTACard(tier = 'free') {
    if (tier === 'pro') {
        return `<div class="ops-card ops-card-upgrade">
    <div class="ops-card-header">
        <span class="ops-card-title">Go Pro+</span>
    </div>
    <ul class="upgrade-benefits">
        <li>Unlimited commands &amp; scans</li>
        <li>AI-powered threat analysis</li>
        <li>90-day activity history</li>
        <li>Priority support</li>
    </ul>
    <a href="#/pricing" class="btn btn-primary btn-sm upgrade-cta-btn">Upgrade to Pro+ &mdash; just &euro;10 more/mo &rarr;</a>
</div>`;
    }
    return `<div class="ops-card ops-card-upgrade">
    <div class="ops-card-header">
        <span class="ops-card-title">Unlock Pro Features</span>
    </div>
    <ul class="upgrade-benefits">
        <li>1,000 commands &amp; 100 scans/day</li>
        <li>Export CSV / JSON reports</li>
        <li>30-day activity history</li>
    </ul>
    <a href="#/pricing" class="btn btn-primary btn-sm upgrade-cta-btn">Upgrade to Pro &mdash; &euro;19.99/mo &rarr;</a>
</div>`;
}
