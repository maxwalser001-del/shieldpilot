# Changelog

All notable changes to ShieldPilot will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-02-17

### Added
- Local Dashboard Server on port 8421 (read-only, no auth, auto-refresh)
- Platform detection for Claude Code, Cursor, Copilot, Windsurf, Aider
- License status badge in dashboard header
- Info site with Features, Pricing, About, Docs, Guides pages
- Changelog page with auto-generated release notes

### Changed
- Dashboard stats endpoint now includes scans_today and top_risk_categories

## [0.2.0] - 2026-02-15

### Added
- Presupposition & fake history detection (8 patterns)
- Narrative policy erosion detection (15 patterns)
- State/approval/trust spoofing detection (10 patterns)
- Stealth memo injection detection (18 patterns)
- Config-based injection detection (5 patterns for JSON/YAML/INI)
- injection-training Skill for iterative pattern improvement
- Comprehensive prompt injection detection: 178 patterns, 19 categories
- 13-step sanitizer, 3-pass scanner, InjectionAnalyzer in RiskEngine

### Fixed
- False positive on relax/soften patterns with modal verb lookbehinds
- False positive on quoted analytical text with (?<!') lookbehind

## [0.1.0] - 2026-02-01

### Added
- Initial ShieldPilot platform release
- 8 risk analyzers: Destructive Filesystem, Privilege Escalation, Network Exfiltration, Credential Access, Persistence, Obfuscation, Malware Patterns, Supply Chain
- Tamper-evident audit chain with SHA-256 hashing
- Web dashboard with real-time monitoring
- JWT authentication with HS256
- Google OAuth integration
- Email verification system
- Password reset via email
- Settings page with profile management
- Billing/paywall system (Free/Pro/Enterprise/Unlimited tiers)
- Setup page with install instructions and API key management
- API key system (generate/revoke, X-API-Key header auth)
- Rebranded from SentinelAI to ShieldPilot
