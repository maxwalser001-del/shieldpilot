#!/usr/bin/env python3
"""Generate 2,500 HARD negative samples for ML training.

These are benign, non-instructional discussions about security topics
that should NOT be classified as injection attacks. They include:
  - Meeting notes, incident writeups, design docs, QA plans
  - Discussions of prompt injection, jailbreaks, red teaming, policy drift
  - Security best practices, evaluation, benchmarking, compliance
  - Realistic carrier formats (bullets, headers, references)

Avoids:
  - Step-by-step attack recipes
  - "do X to override/bypass" phrasing
  - Explicit directives to ignore rules
  - Known artifact tokens: "activate", "reveal", "for maintenance"

Output: hard_negatives_2k.txt at repo root (HARD || <text> per line)
"""

from __future__ import annotations

import random

OUTPUT_FILE = "hard_negatives_2k.txt"
TOTAL = 2500
SEED = 31

# ═══════════════════════════════════════════════════════════════
# Component pools
# ═══════════════════════════════════════════════════════════════

_TOPICS = [
    "prompt injection", "jailbreak attempts", "red teaming",
    "policy drift", "workflow spoofing", "presupposition attacks",
    "config injection", "role manipulation", "context poisoning",
    "delimiter injection", "payload splitting", "encoding bypass",
    "instruction override", "system prompt leakage", "guardrail evasion",
    "data exfiltration via LLM", "indirect prompt injection",
    "tool hijacking", "agent manipulation", "chain-of-thought exploitation",
    "multimodal injection", "cross-plugin attacks", "memory poisoning",
    "reward hacking", "adversarial suffixes", "token smuggling",
    "narrative manipulation", "trust escalation", "sandbox escape",
    "output formatting attacks", "privilege escalation via prompt",
]

_MITIGATIONS = [
    "input sanitization", "output filtering", "content moderation",
    "rate limiting", "anomaly detection", "pattern matching",
    "semantic analysis", "embedding-based detection", "classifier scoring",
    "human review loop", "canary token injection", "perplexity filtering",
    "instruction hierarchy enforcement", "system prompt hardening",
    "multi-layer defense", "behavioral guardrails", "output validation",
    "context window isolation", "tool call verification", "sandboxed execution",
    "differential testing", "red-blue team exercises", "continuous monitoring",
    "threshold-based blocking", "shadow mode evaluation", "telemetry tracking",
]

_FRAMEWORKS = [
    "OWASP LLM Top 10", "NIST AI RMF", "ISO 42001", "EU AI Act",
    "MITRE ATLAS", "Google SAIF", "Anthropic RSP", "OpenAI safety framework",
    "CISA AI security guidelines", "ENISA AI threat landscape",
    "MLCommons AI Safety", "ASVS 5.0", "SOC 2 Type II",
]

_METRICS = [
    "detection rate", "false positive rate", "precision", "recall",
    "F1 score", "true negative rate", "area under ROC", "mean latency",
    "p95 latency", "throughput", "coverage", "accuracy",
    "false discovery rate", "specificity", "balanced accuracy",
]

_TEAMS = [
    "security team", "red team", "blue team", "ML engineering",
    "platform team", "trust and safety", "compliance team",
    "incident response team", "product security", "AppSec team",
    "AI safety team", "DevSecOps", "governance board",
]

_TICKET_IDS = [
    "SEC-{n}", "INC-{n}", "VULN-{n}", "AI-{n}", "SAFE-{n}",
    "RED-{n}", "COMP-{n}", "QA-{n}", "PERF-{n}", "AUDIT-{n}",
]

_SEVERITY = ["P0", "P1", "P2", "P3", "low", "medium", "high", "critical"]

_DATES = [
    "2024-01-{d:02d}", "2024-02-{d:02d}", "2024-03-{d:02d}",
    "2024-04-{d:02d}", "2024-05-{d:02d}", "2024-06-{d:02d}",
    "2024-07-{d:02d}", "2024-08-{d:02d}", "2024-09-{d:02d}",
    "2024-10-{d:02d}", "2024-11-{d:02d}", "2024-12-{d:02d}",
    "2025-01-{d:02d}", "2025-02-{d:02d}", "2025-03-{d:02d}",
]

_NAMES = [
    "Alice", "Bob", "Carol", "David", "Eve", "Frank", "Grace",
    "Hector", "Irene", "James", "Karen", "Leo", "Maya", "Nick",
    "Olivia", "Paul", "Quinn", "Rachel", "Sam", "Tanya",
]

_MODELS = [
    "GPT-4", "Claude 3", "Gemini Pro", "Llama 3", "Mistral",
    "our production model", "the chat assistant", "the coding agent",
    "the internal LLM", "the customer-facing model", "v2.3 model",
]

_PERCENTAGES = list(range(60, 100))
_COUNTS = list(range(3, 500))
_DURATIONS = ["1 hour", "2 hours", "4 hours", "8 hours", "12 hours",
              "24 hours", "48 hours", "1 week", "2 weeks", "30 days"]


def _r(pool):
    return random.choice(pool)


def _ticket():
    return _r(_TICKET_IDS).format(n=random.randint(1000, 9999))


def _date():
    return _r(_DATES).format(d=random.randint(1, 28))


def _pct():
    return random.choice(_PERCENTAGES)


def _cnt():
    return random.choice(_COUNTS)


# ═══════════════════════════════════════════════════════════════
# Template generators by document type
# ═══════════════════════════════════════════════════════════════

def _gen_meeting_note():
    templates = [
        lambda: f"Meeting note ({_date()}): {_r(_TEAMS)} discussed {_r(_TOPICS)} detection improvements. Current {_r(_METRICS)} is {_pct()}%.",
        lambda: f"Standup update: {_r(_NAMES)} reported {_cnt()} new {_r(_TOPICS)} patterns found during review of {_r(_MODELS)} logs.",
        lambda: f"Weekly sync: {_r(_TEAMS)} plans to evaluate {_r(_MITIGATIONS)} against {_r(_TOPICS)} vectors next sprint.",
        lambda: f"Action item from {_date()} meeting: benchmark {_r(_MITIGATIONS)} effectiveness against known {_r(_TOPICS)} techniques.",
        lambda: f"Retro note: The {_r(_TOPICS)} incident on {_date()} highlighted gaps in our {_r(_MITIGATIONS)} pipeline.",
        lambda: f"{_r(_NAMES)} presented findings on {_r(_TOPICS)} trends at the {_r(_TEAMS)} review. Key takeaway: {_r(_MITIGATIONS)} coverage needs expansion.",
        lambda: f"Decision from {_date()} sync: prioritize {_r(_MITIGATIONS)} improvements before enabling enforce mode on {_r(_MODELS)}.",
        lambda: f"Team discussion: should we adopt {_r(_FRAMEWORKS)} guidelines for {_r(_TOPICS)} defense? {_r(_NAMES)} to draft proposal.",
        lambda: f"Sprint planning: {_ticket()} — improve {_r(_METRICS)} for {_r(_TOPICS)} classifier from {_pct()}% to {min(_pct() + 5, 99)}%.",
        lambda: f"Meeting notes: {_r(_TEAMS)} reviewed {_cnt()} {_r(_TOPICS)} samples collected during shadow monitoring period.",
    ]
    return _r(templates)()


def _gen_incident_report():
    templates = [
        lambda: f"Incident {_ticket()} ({_r(_SEVERITY)}): {_r(_TOPICS)} attempt detected on {_date()}. Impact: none, blocked by {_r(_MITIGATIONS)}.",
        lambda: f"Post-mortem for {_ticket()}: {_r(_TOPICS)} vector bypassed first layer but was caught by {_r(_MITIGATIONS)}. No data exposed.",
        lambda: f"Incident summary: {_cnt()} {_r(_TOPICS)} attempts in past {_r(_DURATIONS)}. All blocked. {_r(_METRICS)}: {_pct()}%.",
        lambda: f"Root cause analysis ({_ticket()}): attacker used {_r(_TOPICS)} combined with {_r(_TOPICS)}. Patched via updated {_r(_MITIGATIONS)} rules.",
        lambda: f"Timeline for {_ticket()}: detected at {random.randint(0,23):02d}:{random.randint(0,59):02d} UTC, contained within {_r(_DURATIONS)}. {_r(_MITIGATIONS)} triggered correctly.",
        lambda: f"Severity assessment: the {_r(_TOPICS)} attempt targeting {_r(_MODELS)} was classified as {_r(_SEVERITY)} — no customer impact confirmed.",
        lambda: f"Incident debrief: {_r(_NAMES)} from {_r(_TEAMS)} confirmed the {_r(_TOPICS)} payload was synthetic, originating from internal red team exercise.",
        lambda: f"Resolution for {_ticket()}: added {_cnt()} new patterns to {_r(_MITIGATIONS)} layer. Verified with regression tests.",
        lambda: f"Alert review: {_cnt()} {_r(_TOPICS)} alerts in {_r(_DURATIONS)}, {random.randint(0, 5)} confirmed true positives, rest benign. Tuning {_r(_MITIGATIONS)} thresholds.",
        lambda: f"Lessons learned from {_ticket()}: {_r(_TOPICS)} detection gap existed because {_r(_MITIGATIONS)} only checked single-turn context.",
    ]
    return _r(templates)()


def _gen_design_doc():
    templates = [
        lambda: f"Design proposal: add {_r(_MITIGATIONS)} as a defense layer against {_r(_TOPICS)} in {_r(_MODELS)}.",
        lambda: f"Architecture decision record: chose {_r(_MITIGATIONS)} over {_r(_MITIGATIONS)} for {_r(_TOPICS)} detection due to lower latency.",
        lambda: f"RFC: implement {_r(_MITIGATIONS)} pipeline for {_r(_TOPICS)} defense. Expected {_r(_METRICS)} improvement: {random.randint(5, 25)}%.",
        lambda: f"Technical spec: {_r(_TOPICS)} classifier using TF-IDF + logistic regression. Target {_r(_METRICS)}: {_pct()}% at threshold 0.{random.randint(50, 90)}.",
        lambda: f"System design: multi-stage {_r(_TOPICS)} defense — stage 1: {_r(_MITIGATIONS)}, stage 2: {_r(_MITIGATIONS)}, stage 3: {_r(_MITIGATIONS)}.",
        lambda: f"Proposal from {_r(_NAMES)}: integrate {_r(_FRAMEWORKS)} requirements into our {_r(_TOPICS)} monitoring stack.",
        lambda: f"Design review feedback: the {_r(_MITIGATIONS)} component should handle {_r(_TOPICS)} vectors without adding more than {random.randint(5, 50)}ms latency.",
        lambda: f"Data model update: add {_r(_TOPICS)} score field to the audit log table. Required for {_r(_FRAMEWORKS)} compliance.",
        lambda: f"API design: POST /api/scan endpoint accepts text and returns {_r(_TOPICS)} probability, {_r(_METRICS)}, and recommended action.",
        lambda: f"Migration plan: transition {_r(_TOPICS)} detection from regex-only to hybrid ML+regex approach over {_r(_DURATIONS)}.",
    ]
    return _r(templates)()


def _gen_qa_plan():
    templates = [
        lambda: f"Test plan for {_ticket()}: validate {_r(_MITIGATIONS)} catches {_r(_TOPICS)} variants. {_cnt()} test cases prepared.",
        lambda: f"QA checklist: verify {_r(_METRICS)} >= {_pct()}% for {_r(_TOPICS)} detection on held-out evaluation corpus.",
        lambda: f"Regression test: ensure {_r(_MITIGATIONS)} update does not increase false positive rate on benign {_r(_TOPICS)} discussions.",
        lambda: f"Test matrix: evaluate {_r(_TOPICS)} defense across {_r(_MODELS)}, covering {_cnt()} adversarial patterns and {_cnt()} benign samples.",
        lambda: f"Acceptance criteria for {_ticket()}: {_r(_TOPICS)} {_r(_METRICS)} must exceed {_pct()}% before production deployment.",
        lambda: f"Edge case testing: verify {_r(_MITIGATIONS)} handles {_r(_TOPICS)} with unicode obfuscation, mixed case, and whitespace variations.",
        lambda: f"Performance test plan: measure {_r(_MITIGATIONS)} latency impact under {_cnt()} concurrent {_r(_TOPICS)} scan requests.",
        lambda: f"Evaluation corpus update: added {_cnt()} new {_r(_TOPICS)} samples from recent {_r(_TEAMS)} red team exercise to test suite.",
        lambda: f"A/B test proposal: compare {_r(_MITIGATIONS)} vs {_r(_MITIGATIONS)} on {_r(_TOPICS)} detection. Primary metric: {_r(_METRICS)}.",
        lambda: f"Shadow mode validation: after {_r(_DURATIONS)} of shadow logging, review {_r(_TOPICS)} classification distribution before enabling enforce.",
    ]
    return _r(templates)()


def _gen_best_practice():
    templates = [
        lambda: f"Best practice: defense in depth against {_r(_TOPICS)} requires combining {_r(_MITIGATIONS)} with {_r(_MITIGATIONS)}.",
        lambda: f"Security guideline: all {_r(_TOPICS)} detection rules should be version-controlled and reviewed by {_r(_TEAMS)} before deployment.",
        lambda: f"Recommendation per {_r(_FRAMEWORKS)}: implement {_r(_MITIGATIONS)} for {_r(_TOPICS)} and monitor {_r(_METRICS)} continuously.",
        lambda: f"Operational playbook: when {_r(_TOPICS)} {_r(_METRICS)} drops below {_pct()}%, escalate to {_r(_TEAMS)} and increase logging verbosity.",
        lambda: f"Documentation note: {_r(_TOPICS)} patterns should be documented in the threat model and reviewed quarterly by {_r(_TEAMS)}.",
        lambda: f"Training material: new {_r(_TEAMS)} members should study {_r(_TOPICS)} fundamentals and understand {_r(_MITIGATIONS)} architecture.",
        lambda: f"Compliance note: {_r(_FRAMEWORKS)} requires {_r(_MITIGATIONS)} for {_r(_TOPICS)} vectors. Audit scheduled for {_date()}.",
        lambda: f"Security review finding: {_r(_TOPICS)} defense should be tested against adversarial examples from the {_r(_FRAMEWORKS)} benchmark.",
        lambda: f"Policy update: {_r(_TOPICS)} incidents above {_r(_SEVERITY)} severity require notification to {_r(_TEAMS)} within {_r(_DURATIONS)}.",
        lambda: f"Architecture principle: {_r(_TOPICS)} defenses must be stateless and recoverable — no single point of failure in {_r(_MITIGATIONS)} pipeline.",
    ]
    return _r(templates)()


def _gen_research_note():
    templates = [
        lambda: f"Paper review: '{_r(_TOPICS)} detection using {_r(_MITIGATIONS)}' achieves {_pct()}% {_r(_METRICS)} on standard benchmarks.",
        lambda: f"Research finding: {_r(_TOPICS)} attacks have increased {random.randint(20, 300)}% year-over-year according to {_r(_FRAMEWORKS)} report.",
        lambda: f"Literature survey: {_cnt()} papers on {_r(_TOPICS)} published in 2024. Most effective defenses combine {_r(_MITIGATIONS)} with {_r(_MITIGATIONS)}.",
        lambda: f"Benchmark results: our {_r(_TOPICS)} classifier scores {_pct()}% {_r(_METRICS)} on the {_r(_FRAMEWORKS)} evaluation set.",
        lambda: f"Threat intel update: new {_r(_TOPICS)} technique observed in the wild. Adding {_cnt()} patterns to {_r(_MITIGATIONS)} rules.",
        lambda: f"Conference takeaway: {_r(_NAMES)} noted that {_r(_TOPICS)} remains the top threat to LLM deployments per {_r(_FRAMEWORKS)}.",
        lambda: f"Analysis: {_r(_TOPICS)} success rate against {_r(_MODELS)} dropped from {_pct()}% to {max(_pct() - 30, 5)}% after deploying {_r(_MITIGATIONS)}.",
        lambda: f"Trend report: {_r(_TOPICS)} attacks are increasingly using {_r(_TOPICS)} as a secondary vector. Need combined {_r(_MITIGATIONS)} approach.",
        lambda: f"Dataset review: the {_r(_TOPICS)} evaluation corpus contains {_cnt()} samples across {random.randint(5, 20)} attack categories.",
        lambda: f"Ablation study: removing {_r(_MITIGATIONS)} from the pipeline increases {_r(_TOPICS)} bypass rate by {random.randint(5, 40)}%.",
    ]
    return _r(templates)()


def _gen_status_update():
    templates = [
        lambda: f"Status update ({_date()}): {_r(_TOPICS)} scanner processing {_cnt()} requests/hour. {_r(_METRICS)}: {_pct()}%. No anomalies.",
        lambda: f"Dashboard alert: {_r(_TOPICS)} detection rate dipped to {_pct()}% on {_date()}. {_r(_NAMES)} investigating potential data drift.",
        lambda: f"Weekly report: {_cnt()} {_r(_TOPICS)} attempts blocked, {random.randint(0, 10)} false positives reported. {_r(_MITIGATIONS)} performing within SLA.",
        lambda: f"Monitoring summary: {_r(_MODELS)} shadow mode logged {_cnt()} {_r(_TOPICS)} candidates over past {_r(_DURATIONS)}. Review pending.",
        lambda: f"Ops update: {_r(_MITIGATIONS)} latency p95 is {random.randint(5, 80)}ms. Well within {random.randint(100, 500)}ms budget for {_r(_TOPICS)} scanning.",
        lambda: f"Release notes v{random.randint(1,5)}.{random.randint(0,20)}: improved {_r(_TOPICS)} detection, added {_cnt()} new patterns, fixed {random.randint(1,5)} false positive categories.",
        lambda: f"Rollout status: {_r(_TOPICS)} enforce mode active for {_r(_DURATIONS)} with block threshold at 0.{random.randint(80, 95)}. Zero false positive reports.",
        lambda: f"Health check: {_r(_MITIGATIONS)} service uptime {_pct()}.{random.randint(0,9)}% over past {_r(_DURATIONS)}. {_r(_TOPICS)} scans nominal.",
        lambda: f"Capacity planning: current {_r(_MITIGATIONS)} infrastructure handles {_cnt()}k {_r(_TOPICS)} scans per day. Scaling trigger at {_cnt()}k.",
        lambda: f"SLA report: {_r(_TOPICS)} {_r(_METRICS)} has been above {_pct()}% for {random.randint(7, 90)} consecutive days.",
    ]
    return _r(templates)()


def _gen_discussion():
    templates = [
        lambda: f"Question from {_r(_NAMES)}: how does {_r(_TOPICS)} differ from {_r(_TOPICS)} in terms of detection difficulty?",
        lambda: f"Slack thread: {_r(_NAMES)} asked whether {_r(_MITIGATIONS)} is sufficient against {_r(_TOPICS)} or if we need {_r(_MITIGATIONS)} too.",
        lambda: f"Forum post: comparing {_r(_MITIGATIONS)} approaches for {_r(_TOPICS)} — which has better {_r(_METRICS)} in production?",
        lambda: f"Code review comment: this {_r(_MITIGATIONS)} implementation should also handle {_r(_TOPICS)} edge cases with mixed encodings.",
        lambda: f"PR feedback from {_r(_NAMES)}: the {_r(_TOPICS)} test fixtures need more diverse negative examples to reduce false positives.",
        lambda: f"Discussion: {_r(_TEAMS)} debating whether to use rule-based or ML-based {_r(_MITIGATIONS)} for {_r(_TOPICS)} in production.",
        lambda: f"Comment on {_ticket()}: the {_r(_TOPICS)} false positive rate is still too high at {100 - _pct()}%. Need more HARD negative training data.",
        lambda: f"Email from {_r(_NAMES)}: can we get {_r(_TEAMS)} to run {_r(_TOPICS)} red team exercises against {_r(_MODELS)} before launch?",
        lambda: f"Thread summary: team agreed that {_r(_TOPICS)} defense should follow {_r(_FRAMEWORKS)} recommendations for {_r(_MITIGATIONS)}.",
        lambda: f"Knowledge base article: understanding {_r(_TOPICS)} — common patterns, known defenses, and monitoring best practices.",
    ]
    return _r(templates)()


def _gen_config_discussion():
    templates = [
        lambda: f"Config review: the {_r(_TOPICS)} threshold is set to 0.{random.randint(50, 95)}. {_r(_NAMES)} suggested lowering to 0.{random.randint(40, 80)} after shadow analysis.",
        lambda: f"Environment setup: {_r(_TOPICS)} scanner uses SENTINEL_ML_MODE=shadow during evaluation. Switch to enforce after {_r(_DURATIONS)} of stable metrics.",
        lambda: f"Settings documentation: the {_r(_MITIGATIONS)} module reads {_r(_TOPICS)} patterns from the YAML config file at startup.",
        lambda: f"Config change request ({_ticket()}): update {_r(_TOPICS)} detection sensitivity from {_r(_SEVERITY)} to {_r(_SEVERITY)} for the {_r(_MODELS)} deployment.",
        lambda: f"Deployment config: enable {_r(_MITIGATIONS)} telemetry for {_r(_TOPICS)} monitoring. Set SENTINEL_ML_TELEMETRY=1 in production.",
        lambda: f"Rollback procedure: if {_r(_TOPICS)} false positive rate exceeds {100 - _pct()}%, set ML mode back to shadow and notify {_r(_TEAMS)}.",
        lambda: f"Infrastructure note: {_r(_TOPICS)} logs are stored at /var/log/sentinel/ and rotated every {_r(_DURATIONS)}. No raw input text is persisted.",
        lambda: f"Feature flag: {_r(_TOPICS)} ML classifier is behind feature flag ml_injection_v2. Currently enabled for {_pct()}% of traffic.",
        lambda: f"Parameter tuning: {_r(_NAMES)} ran grid search on {_r(_TOPICS)} classifier. Optimal {_r(_METRICS)} at C={random.choice([0.01, 0.1, 1.0, 10.0])}.",
        lambda: f"CI/CD update: added {_r(_TOPICS)} regression tests to the pre-merge pipeline. Blocks merge if {_r(_METRICS)} drops below {_pct()}%.",
    ]
    return _r(templates)()


def _gen_evaluation():
    templates = [
        lambda: f"Eval results ({_date()}): {_r(_TOPICS)} classifier — {_r(_METRICS)}: {_pct()}%, false positive rate: {100 - _pct()}% on {_cnt()} test samples.",
        lambda: f"Confusion matrix for {_r(_TOPICS)} model: TP={_cnt()}, FP={random.randint(0, 20)}, TN={_cnt()}, FN={random.randint(0, 15)}.",
        lambda: f"Threshold sweep: at 0.{random.randint(50, 95)}, {_r(_TOPICS)} recall is {_pct()}% with {100 - _pct()}% false positive rate on HARD negatives.",
        lambda: f"Cross-validation: {_r(_TOPICS)} classifier achieves {_pct()}% mean {_r(_METRICS)} across 5 folds. Standard deviation: {random.randint(1, 5)}%.",
        lambda: f"OOD evaluation: {_r(_TOPICS)} model scores clean shell commands with median probability 0.{random.randint(0, 5):04d}. Within acceptable range.",
        lambda: f"Leakage audit complete: {_r(_TOPICS)} dataset has {_pct()}% unique samples after deduplication. No train-test overlap detected.",
        lambda: f"Ablation: removing {_r(_MITIGATIONS)} features from {_r(_TOPICS)} classifier reduces {_r(_METRICS)} by {random.randint(2, 15)}%.",
        lambda: f"Comparison: ML-based {_r(_TOPICS)} detection outperforms regex-only by {random.randint(5, 30)}% on novel attack patterns.",
        lambda: f"Calibration check: {_r(_TOPICS)} model probabilities are well-calibrated in [0.0, 0.3] and [0.8, 1.0] ranges. Mid-range needs improvement.",
        lambda: f"Error analysis: most {_r(_TOPICS)} false negatives are short commands (<{random.randint(10, 30)} tokens) that lack distinctive attack markers.",
    ]
    return _r(templates)()


# Generator registry with weights
_GENERATORS = [
    (_gen_meeting_note, 0.12),
    (_gen_incident_report, 0.14),
    (_gen_design_doc, 0.12),
    (_gen_qa_plan, 0.10),
    (_gen_best_practice, 0.10),
    (_gen_research_note, 0.10),
    (_gen_status_update, 0.08),
    (_gen_discussion, 0.10),
    (_gen_config_discussion, 0.08),
    (_gen_evaluation, 0.06),
]


def generate():
    random.seed(SEED)

    # Build weighted generator list
    weighted_gens: list = []
    for gen_fn, weight in _GENERATORS:
        weighted_gens.extend([gen_fn] * int(weight * 100))

    # Rejection sampling: keep only unique samples
    seen: set[str] = set()
    samples: list[str] = []
    max_attempts = TOTAL * 20
    attempts = 0

    while len(samples) < TOTAL and attempts < max_attempts:
        gen_fn = random.choice(weighted_gens)
        text = gen_fn()
        attempts += 1
        if text not in seen:
            seen.add(text)
            samples.append(text)

    # Fallback if exhausted (shouldn't happen with enough templates)
    while len(samples) < TOTAL:
        gen_fn = random.choice(weighted_gens)
        samples.append(gen_fn())

    random.shuffle(samples)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for text in samples:
            f.write(f"HARD || {text}\n")

    unique = len(set(samples))
    avg_len = sum(len(t) for t in samples) / len(samples)
    print(f"Generated {len(samples)} HARD negative samples -> {OUTPUT_FILE}")
    print(f"  Unique: {unique}/{len(samples)} ({100 * unique / len(samples):.1f}%)")
    print(f"  Avg length: {avg_len:.0f} chars")
    print(f"  Attempts: {attempts}")

    return samples


if __name__ == "__main__":
    generate()
