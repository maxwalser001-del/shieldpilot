# ShieldPilot AI Agent Firewall — Design Guide

## Farben

### Hintergrund
| Name | Hex | Verwendung |
|---|---|---|
| Deep Navy | `#0B0F1A` | Body, Sidebar |
| Surface | `#131825` | Karten, Panels, Inputs |
| Surface Raised | `#1A2035` | Hover, Dropdowns, Modals |
| Border | `#252D3F` | Trennlinien, Card-Borders |

### Akzent
| Name | Hex | Verwendung |
|---|---|---|
| Shield Cyan | `#39D2C0` | Buttons, Links, Logo |
| Shield Cyan Hover | `#2FBCAB` | Button-Hover |
| Shield Cyan Muted | `rgba(57,210,192,0.12)` | Badges, Tags |
| Shield Cyan Glow | `rgba(57,210,192,0.25)` | Focus-Rings |

### Status
| Name | Hex | Verwendung |
|---|---|---|
| Safe Green | `#34D399` | Allowed, Healthy |
| Warning Amber | `#FBBF24` | Warn-Level |
| Danger Red | `#F87171` | Blocked, Error |
| Info Blue | `#60A5FA` | Info, Links |

### Text
| Name | Hex | Verwendung |
|---|---|---|
| Primary | `#F1F5F9` | Überschriften |
| Secondary | `#94A3B8` | Body-Text |
| Muted | `#64748B` | Labels, Platzhalter |
| Inverse | `#0B0F1A` | Text auf hellen Buttons |

## Fonts
- UI: `Inter` (Weight 400-800)
- Code/Daten: `JetBrains Mono` (Weight 400-600)

## Schriftgrößen
| Name | Größe | Weight | Verwendung |
|---|---|---|---|
| Display | 36px | 800 | Landing Hero |
| H1 | 28px | 700 | Seitentitel |
| H2 | 22px | 600 | Sektionen |
| H3 | 17px | 600 | Card-Titel |
| Body | 14px | 400 | Standard |
| Caption | 12px | 500 | Labels, Badges |
| Mono Data | 14px | 500 | Scores, Counts |
| Mono Code | 13px | 400 | Code-Snippets |

## Regeln
1. Farbe nur für Bedeutung (Cyan=interaktiv, Grün=safe, Gelb=warn, Rot=danger)
2. Max 3 Hintergrund-Ebenen (primary → surface → raised)
3. Mono-Font für alles was Entwickler scannen (Scores, Commands, Timestamps)
4. Spacing in 8er-Schritten (4, 8, 16, 24, 32, 48)
5. Keine Gradients, keine Illustrationen, keine runden Avatare
6. Animation nur für Feedback (150ms Hover-Transitions, Loading-Spinner)
7. Border-Radius: 6px (sm), 8px (md), 12px (lg)
