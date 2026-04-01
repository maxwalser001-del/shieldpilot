"""Indirect Prompt Injection Scanner.

Detects hidden instructions embedded in documents, web pages, and tool outputs.
An attacker embeds instructions in content that an AI agent processes — for
example in an HTML page, JSON API response, PDF, or Markdown document.  The
agent reads the content and executes the hidden instructions without the user's
knowledge.

This module is the *preprocessing layer*: it extracts concealed text from
various hiding vectors, then passes the extracted text to
:class:`~sentinelai.scanner.scanner.PromptScanner` for injection detection.

Supported content types and hiding vectors
------------------------------------------
**HTML**
  - Comments: ``<!-- hidden instructions -->``
  - CSS-hidden elements: ``display:none``, ``visibility:hidden``,
    ``font-size:0``, ``opacity:0``, white-on-white text
  - Elements with the ``hidden`` attribute
  - ``<meta content="...">`` tags

**JSON**
  - Fields with suspicious names: ``__system__``, ``instructions``,
    ``prompt``, ``ignore``, ``override``, etc.
  - Long string values that contain imperative instruction language

**Plain text**
  - Zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+00AD, …)
  - Unicode bidirectional override characters (can visually reverse text)
  - Homoglyph substitution (Cyrillic / Greek chars masquerading as Latin)

**Markdown**
  - Image alt-text: ``![hidden instructions](http://...)``
  - HTML comments embedded in Markdown
  - Reference-style hidden comments: ``[//]: # (hidden instructions)``
  - Zero-width and bidi characters in rendered text
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import time

from sentinelai.core.models import ScanResult
from sentinelai.scanner.scanner import PromptScanner


# ── Finding ───────────────────────────────────────────────────────────────────


@dataclass
class Finding:
    """A single structural hiding technique detected in content."""

    #: Short identifier for the hiding technique, e.g. ``"html_comment"``.
    vector: str
    #: The text that was extracted / decoded from the hiding layer.
    extracted_text: str
    #: Human-readable description of *where* in the document this was found.
    location: str
    #: One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    severity: str
    #: Explanation of the threat.
    description: str


# ── Result ────────────────────────────────────────────────────────────────────


@dataclass
class IndirectInjectionResult:
    """Complete result of an indirect-injection scan."""

    #: Label for the scanned resource (file path, URL, ``"stdin"``).
    source: str
    #: Detected content type: ``"html"``, ``"json"``, ``"text"``, or ``"markdown"``.
    content_type: str
    #: Structural hiding techniques found (before injection analysis).
    findings: List[Finding] = field(default_factory=list)
    #: Deep injection scan of all extracted hidden texts (may be ``None``).
    scan_result: Optional[ScanResult] = None
    #: Combined risk score 0–100.
    overall_risk: int = 0
    #: UTC timestamp of the scan.
    timestamp: datetime = field(default_factory=datetime.utcnow)
    #: Wall-clock time in milliseconds.
    execution_time_ms: float = 0.0

    @property
    def is_suspicious(self) -> bool:
        """``True`` if any risk was detected."""
        return self.overall_risk > 0 or bool(self.findings)


# ── Compiled patterns ─────────────────────────────────────────────────────────

# --- Text: invisible / zero-width Unicode ---
_ZERO_WIDTH_CHARS = re.compile(
    r"[\u200b\u200c\u200d\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064]+"
)

# --- Text: Unicode bidirectional overrides ---
_BIDI_OVERRIDE_CHARS = re.compile(
    r"[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]"
)

# --- HTML: comments ---
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)

# --- HTML: inline-styled element (captures tag, style value, inner text) ---
_HIDDEN_STYLE_ELEM = re.compile(
    r"<(\w+)\b[^>]*\bstyle\s*=\s*[\"']([^\"']*)[\"'][^>]*>(.*?)</\1>",
    re.DOTALL | re.IGNORECASE,
)

# --- HTML: hidden attribute ---
_HIDDEN_ATTR_ELEM = re.compile(
    r"<(\w+)\b[^>]*\bhidden\b[^>]*>(.*?)</\1>",
    re.DOTALL | re.IGNORECASE,
)

# --- HTML: meta content ---
_META_CONTENT = re.compile(
    r"<meta\b[^>]*\bcontent\s*=\s*[\"']([^\"']+)[\"'][^>]*/?>",
    re.IGNORECASE,
)

# --- CSS properties that hide elements ---
_CSS_HIDE_PATTERNS: List[re.Pattern] = [
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*0(?:px|pt|em|rem|%)?", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.\d+)?(?:\s*;|$|\s)", re.IGNORECASE),
    re.compile(
        r"color\s*:\s*(?:white|#fff(?:fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255)",
        re.IGNORECASE,
    ),
    re.compile(r"height\s*:\s*0(?:px)?(?:\s*;|$|\s)", re.IGNORECASE),
    re.compile(r"width\s*:\s*0(?:px)?(?:\s*;|$|\s)", re.IGNORECASE),
    re.compile(r"clip\s*:\s*rect\(0", re.IGNORECASE),
    re.compile(r"position\s*:\s*absolute[^;]*left\s*:\s*-\d{4,}px", re.IGNORECASE),
]

# --- JSON: suspicious field names ---
_SUSPICIOUS_JSON_KEYS = re.compile(
    r"^(?:__system__|__instructions?__|__prompt__|system_prompt|ignore|"
    r"instructions?|prompt|override|_hidden|__hidden__|__directive__|"
    r"__command__|__task__|__role__|__context__)$",
    re.IGNORECASE,
)

# Minimum character length to consider a JSON string value instruction-like.
_MIN_INSTRUCTION_LEN = 50

# --- Markdown: image with alt text ---
_MD_IMAGE = re.compile(r"!\[([^\]]+)\]\([^)]+\)")

# --- Markdown: HTML comment ---
_MD_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)

# --- Markdown: reference-style hidden comment [//]: # (...) ---
_MD_REF_COMMENT = re.compile(r"^\[//\]:\s*#\s*\((.+)\)", re.MULTILINE)

# Heuristic: words in a JSON string that signal imperative instructions.
_INSTRUCTION_SIGNALS = re.compile(
    r"\b(?:ignore|forget|disregard|override|bypass|pretend|act as|you are|"
    r"system prompt|your instructions?|do not|must not|shall|always|never|"
    r"from now on|henceforth|new task|your role|new instructions?)\b",
    re.IGNORECASE,
)

# Severity-to-score mapping (structural finding only, before deep scan).
_SEVERITY_SCORE: Dict[str, int] = {
    "critical": 50,
    "high": 30,
    "medium": 15,
    "low": 5,
}

# Common Cyrillic / Greek homoglyphs that look like ASCII Latin characters.
_LATIN_LOOKALIKES: Dict[str, str] = {
    # Cyrillic lower-case
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0445": "x",  # х
    # Cyrillic upper-case
    "\u0410": "A",  # А
    "\u0412": "B",  # В
    "\u0415": "E",  # Е
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u041d": "H",  # Н
    "\u041e": "O",  # О
    "\u0420": "P",  # Р
    "\u0421": "C",  # С
    "\u0422": "T",  # Т
    "\u0425": "X",  # Х
    # Greek lower-case
    "\u03bf": "o",  # ο
    "\u03c1": "p",  # ρ
    "\u03bd": "v",  # ν
    "\u03b1": "a",  # α
}


# ── Scanner ───────────────────────────────────────────────────────────────────


class IndirectInjectionScanner:
    """Detect hidden instructions in documents, web pages, and tool outputs.

    Acts as a preprocessing layer: each ``scan_*`` method finds concealed
    text within its content type and returns an
    :class:`IndirectInjectionResult` that contains both structural
    :class:`Finding` objects and a deep :class:`~sentinelai.core.models.ScanResult`
    produced by :class:`~sentinelai.scanner.scanner.PromptScanner`.

    Usage::

        scanner = IndirectInjectionScanner()
        result = scanner.scan_html(html_body, source="https://example.com")
        if result.is_suspicious:
            for f in result.findings:
                print(f"[{f.severity}] {f.vector}: {f.extracted_text[:80]}")
    """

    def __init__(self) -> None:
        self._prompt_scanner = PromptScanner()

    # ── Public API ────────────────────────────────────────────────────────

    def scan(
        self,
        content: str,
        source: str = "stdin",
        content_type: str = "auto",
    ) -> IndirectInjectionResult:
        """Auto-detect content type and scan for indirect injection.

        Parameters
        ----------
        content:
            Raw text to analyse.
        source:
            Label describing the origin (file path, URL, ``"stdin"``).
        content_type:
            One of ``"html"``, ``"json"``, ``"text"``, ``"markdown"``, or
            ``"auto"`` (default — detected from content heuristics).
        """
        if content_type == "auto":
            content_type = self._detect_type(content)

        dispatch = {
            "html": self.scan_html,
            "json": self.scan_json,
            "markdown": self.scan_markdown,
            "text": self.scan_text,
        }
        return dispatch.get(content_type, self.scan_text)(content, source=source)

    def scan_html(
        self, content: str, source: str = "html"
    ) -> IndirectInjectionResult:
        """Scan HTML for hidden injection vectors.

        Checks HTML comments, CSS-hidden elements, ``hidden`` attribute
        elements, ``<meta>`` tags, and zero-width characters.
        """
        start = time.perf_counter()
        findings: List[Finding] = []

        # 1. HTML comments
        for m in _HTML_COMMENT.finditer(content):
            text = m.group(1).strip()
            if text:
                findings.append(
                    Finding(
                        vector="html_comment",
                        extracted_text=text,
                        location=f"HTML comment at offset {m.start()}",
                        severity="high",
                        description=(
                            "Text hidden in an HTML comment — invisible to users "
                            "but readable by parsers and AI agents."
                        ),
                    )
                )

        # 2. CSS-hidden elements
        for m in _HIDDEN_STYLE_ELEM.finditer(content):
            tag, style, inner = m.group(1), m.group(2), m.group(3).strip()
            if inner and self._is_hidden_style(style):
                findings.append(
                    Finding(
                        vector="css_hidden_element",
                        extracted_text=inner,
                        location=f"<{tag} style=\"{style[:80]}\">",
                        severity="high",
                        description=(
                            f"Text hidden via CSS ({self._describe_hidden_style(style)}) "
                            "— not rendered to users but present in the DOM and visible to agents."
                        ),
                    )
                )

        # 3. hidden attribute
        for m in _HIDDEN_ATTR_ELEM.finditer(content):
            tag, inner = m.group(1), m.group(2).strip()
            if inner:
                findings.append(
                    Finding(
                        vector="html_hidden_attribute",
                        extracted_text=inner,
                        location=f"<{tag} hidden>",
                        severity="medium",
                        description=(
                            "Text concealed via the HTML 'hidden' attribute — "
                            "not displayed but accessible to agents reading the DOM."
                        ),
                    )
                )

        # 4. Meta tag content (non-trivial values)
        for m in _META_CONTENT.finditer(content):
            val = m.group(1).strip()
            if val and len(val) > 20:
                findings.append(
                    Finding(
                        vector="meta_tag_content",
                        extracted_text=val,
                        location='<meta content="...">',
                        severity="medium",
                        description=(
                            "Text embedded in a <meta> tag — not displayed to users "
                            "but read by agents processing page metadata."
                        ),
                    )
                )

        # 5. Zero-width / invisible chars (also present in HTML source)
        findings.extend(self._find_zero_width(content))

        return self._build_result(source, "html", findings, start)

    def scan_json(
        self, content: str, source: str = "json"
    ) -> IndirectInjectionResult:
        """Scan JSON for hidden injection vectors.

        Checks for fields with suspicious names (``__system__``,
        ``instructions``, ``prompt``, …) and long string values that contain
        imperative instruction language.
        """
        start = time.perf_counter()
        findings: List[Finding] = []

        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            # Not valid JSON — fall back to plain-text scan.
            return self.scan_text(content, source=source)

        self._scan_json_node(data, path="$", findings=findings)
        return self._build_result(source, "json", findings, start)

    def scan_text(
        self, content: str, source: str = "text"
    ) -> IndirectInjectionResult:
        """Scan plain text for hidden injection vectors.

        Checks for zero-width / invisible Unicode characters, bidirectional
        override characters, and homoglyph substitution.
        """
        start = time.perf_counter()
        findings: List[Finding] = []

        findings.extend(self._find_zero_width(content))
        findings.extend(self._find_bidi_override(content))
        findings.extend(self._find_homoglyphs(content))

        return self._build_result(source, "text", findings, start)

    def scan_markdown(
        self, content: str, source: str = "markdown"
    ) -> IndirectInjectionResult:
        """Scan Markdown for hidden injection vectors.

        Checks image alt-text, HTML comments, reference-style hidden
        comments, zero-width characters, and bidi overrides.
        """
        start = time.perf_counter()
        findings: List[Finding] = []

        # 1. Image alt-text
        for m in _MD_IMAGE.finditer(content):
            alt = m.group(1).strip()
            if alt and len(alt) > 15:
                findings.append(
                    Finding(
                        vector="markdown_image_alt",
                        extracted_text=alt,
                        location=f'Image alt text: !["{alt[:60]}"](...)',
                        severity="medium",
                        description=(
                            "Text in image alt attribute — may contain hidden instructions "
                            "that are read by AI agents but not rendered to users when "
                            "the image is absent or inaccessible."
                        ),
                    )
                )

        # 2. HTML comments in Markdown
        for m in _MD_HTML_COMMENT.finditer(content):
            text = m.group(1).strip()
            if text:
                findings.append(
                    Finding(
                        vector="markdown_html_comment",
                        extracted_text=text,
                        location=f"HTML comment in Markdown at offset {m.start()}",
                        severity="high",
                        description=(
                            "HTML comment embedded in Markdown — stripped from the "
                            "rendered output shown to users but visible to agents reading the source."
                        ),
                    )
                )

        # 3. Reference-style hidden comments
        for m in _MD_REF_COMMENT.finditer(content):
            text = m.group(1).strip()
            if text:
                findings.append(
                    Finding(
                        vector="markdown_reference_comment",
                        extracted_text=text,
                        location="Markdown reference comment [//]: # (...)",
                        severity="medium",
                        description=(
                            "Reference-style comment — not rendered in standard "
                            "Markdown output but present in raw source read by agents."
                        ),
                    )
                )

        # 4. Invisible / directional chars
        findings.extend(self._find_zero_width(content))
        findings.extend(self._find_bidi_override(content))

        return self._build_result(source, "markdown", findings, start)

    # ── Internal: result assembly ─────────────────────────────────────────

    def _build_result(
        self,
        source: str,
        content_type: str,
        findings: List[Finding],
        start_time: float,
    ) -> IndirectInjectionResult:
        """Deep-scan all extracted texts and compute the overall risk score."""
        scan_result: Optional[ScanResult] = None
        overall_risk = 0

        if findings:
            extracted = "\n".join(f.extracted_text for f in findings)
            scan_result = self._prompt_scanner.scan(
                extracted, source=f"{source}[indirect]"
            )

            # Structural hiding bonus: each Finding adds a small penalty even
            # when the extracted text contains no recognised injection patterns.
            structural_bonus = min(len(findings) * 5, 20)
            overall_risk = min(scan_result.overall_score + structural_bonus, 100)

            # If PromptScanner found nothing but structural hiding was detected,
            # assign a baseline score from the highest finding severity.
            if scan_result.overall_score == 0 and findings:
                max_structural = max(
                    _SEVERITY_SCORE.get(f.severity, 5) for f in findings
                )
                overall_risk = max(overall_risk, max_structural)

        return IndirectInjectionResult(
            source=source,
            content_type=content_type,
            findings=findings,
            scan_result=scan_result,
            overall_risk=overall_risk,
            execution_time_ms=(time.perf_counter() - start_time) * 1000,
        )

    # ── Internal: zero-width chars ────────────────────────────────────────

    def _find_zero_width(self, content: str) -> List[Finding]:
        """Detect zero-width and invisible Unicode characters."""
        findings: List[Finding] = []

        for m in _ZERO_WIDTH_CHARS.finditer(content):
            zw_chars = m.group()

            # Describe the character names found.
            char_names = sorted(
                {
                    unicodedata.name(c, f"U+{ord(c):04X}")
                    for c in zw_chars
                }
            )

            # Try binary-steganography decode (ZWSP=0, ZWNJ=1).
            decoded = self._decode_zw_steganography(zw_chars)

            ctx_start = max(0, m.start() - 15)
            ctx_end = min(len(content), m.end() + 15)
            before = content[ctx_start : m.start()].replace("\n", "↵")
            after = content[m.end() : ctx_end].replace("\n", "↵")

            findings.append(
                Finding(
                    vector="zero_width_chars",
                    extracted_text=(
                        decoded
                        or f"[{len(zw_chars)} invisible char(s): {', '.join(char_names)}]"
                    ),
                    location=f"Between '…{before[-10:]}' and '{after[:10]}…'",
                    severity="high",
                    description=(
                        f"Zero-width / invisible Unicode characters detected "
                        f"({', '.join(char_names)}). These hide text from human "
                        "readers while remaining present in the string an AI processes."
                    ),
                )
            )

        return findings

    # ── Internal: bidi override chars ────────────────────────────────────

    def _find_bidi_override(self, content: str) -> List[Finding]:
        """Detect Unicode bidirectional override / embedding characters."""
        findings: List[Finding] = []

        positions = [m.start() for m in _BIDI_OVERRIDE_CHARS.finditer(content)]
        if not positions:
            return findings

        # Group positions within 50 chars of each other into one Finding.
        groups: List[List[int]] = [[positions[0]]]
        for pos in positions[1:]:
            if pos - groups[-1][-1] < 50:
                groups[-1].append(pos)
            else:
                groups.append([pos])

        for group in groups:
            ctx_start = max(0, group[0] - 30)
            ctx_end = min(len(content), group[-1] + 30)
            affected = content[ctx_start:ctx_end]

            findings.append(
                Finding(
                    vector="bidi_override_chars",
                    extracted_text=affected,
                    location=f"Bidi override chars at offsets {group}",
                    severity="high",
                    description=(
                        "Unicode bidirectional override / embedding characters detected. "
                        "These can make the text *look* different from what is actually "
                        "there — for example, U+202E (RIGHT-TO-LEFT OVERRIDE) can "
                        "visually reverse malicious content so humans read a harmless "
                        "string while agents process the real payload."
                    ),
                )
            )

        return findings

    # ── Internal: homoglyph substitution ─────────────────────────────────

    def _find_homoglyphs(self, content: str) -> List[Finding]:
        """Detect words that mix Latin with visually-identical non-Latin glyphs."""
        findings: List[Finding] = []

        for m in re.finditer(r"\b\w+\b", content):
            word = m.group()
            if word.isascii():
                continue

            homoglyph_pairs = [
                (c, _LATIN_LOOKALIKES[c]) for c in word if c in _LATIN_LOOKALIKES
            ]
            if not homoglyph_pairs:
                continue

            latin_word = word
            for hg, latin in homoglyph_pairs:
                latin_word = latin_word.replace(hg, latin)

            findings.append(
                Finding(
                    vector="homoglyph_substitution",
                    extracted_text=word,
                    location=f"Word at offset {m.start()}: '{word}' → '{latin_word}'",
                    severity="medium",
                    description=(
                        f"Homoglyph substitution: '{word}' uses non-Latin Unicode "
                        f"characters that are visually identical to '{latin_word}'. "
                        "This can fool visual inspection while evading ASCII-based filters."
                    ),
                )
            )

        return findings

    # ── Internal: JSON recursive scan ────────────────────────────────────

    def _scan_json_node(
        self,
        node: object,
        path: str,
        findings: List[Finding],
        depth: int = 0,
    ) -> None:
        """Recursively walk a parsed JSON structure looking for injection."""
        if depth > 12:
            return

        if isinstance(node, dict):
            for key, value in node.items():
                child_path = f"{path}.{key}"

                if isinstance(key, str) and _SUSPICIOUS_JSON_KEYS.match(key):
                    extracted = (
                        value
                        if isinstance(value, str)
                        else json.dumps(value, ensure_ascii=False)
                    )
                    findings.append(
                        Finding(
                            vector="json_suspicious_field",
                            extracted_text=str(extracted)[:500],
                            location=f"JSON field: {child_path}",
                            severity="high",
                            description=(
                                f"Suspicious JSON field name '{key}' — "
                                "commonly used to smuggle system instructions into structured data."
                            ),
                        )
                    )
                elif isinstance(value, str) and len(value) >= _MIN_INSTRUCTION_LEN:
                    if _INSTRUCTION_SIGNALS.search(value):
                        findings.append(
                            Finding(
                                vector="json_instruction_value",
                                extracted_text=value[:500],
                                location=f"JSON field: {child_path}",
                                severity="medium",
                                description=(
                                    f"Long instruction-like string in JSON field '{key}' "
                                    "— may contain hidden directives that an agent would execute."
                                ),
                            )
                        )

                self._scan_json_node(value, child_path, findings, depth + 1)

        elif isinstance(node, list):
            for i, item in enumerate(node):
                self._scan_json_node(item, f"{path}[{i}]", findings, depth + 1)

    # ── Internal: CSS / style helpers ────────────────────────────────────

    @staticmethod
    def _is_hidden_style(style: str) -> bool:
        """Return True if any recognised CSS hiding pattern matches."""
        return any(pat.search(style) for pat in _CSS_HIDE_PATTERNS)

    @staticmethod
    def _describe_hidden_style(style: str) -> str:
        """Return a short label for the first matching CSS hiding technique."""
        _DESCRIPTIONS = [
            (re.compile(r"display\s*:\s*none", re.IGNORECASE), "display:none"),
            (
                re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
                "visibility:hidden",
            ),
            (re.compile(r"font-size\s*:\s*0", re.IGNORECASE), "font-size:0"),
            (re.compile(r"opacity\s*:\s*0", re.IGNORECASE), "opacity:0"),
            (
                re.compile(r"color\s*:\s*(?:white|#fff)", re.IGNORECASE),
                "white-on-white text",
            ),
        ]
        for pat, desc in _DESCRIPTIONS:
            if pat.search(style):
                return desc
        return "hidden CSS property"

    # ── Internal: ZW steganography decoder ───────────────────────────────

    @staticmethod
    def _decode_zw_steganography(zw_text: str) -> Optional[str]:
        """Try to decode binary steganography encoded via ZWSP / ZWNJ pairs.

        Some steganography tools encode payload text as a binary stream using
        ``\\u200b`` (ZWSP) as 0 and ``\\u200c`` (ZWNJ) as 1.  Returns the
        decoded string prefixed with ``"[Decoded stego]: "`` on success, or
        ``None`` if the sequence is not a valid encoding.
        """
        ZW_TO_BIT = {"\u200b": "0", "\u200c": "1", "\u200d": "1"}
        bits = "".join(ZW_TO_BIT.get(c, "") for c in zw_text)

        if len(bits) < 8:
            return None

        try:
            chars = []
            for i in range(0, len(bits) - 7, 8):
                byte = int(bits[i : i + 8], 2)
                if 32 <= byte <= 126:
                    chars.append(chr(byte))
                else:
                    return None
            decoded = "".join(chars).strip()
            return f"[Decoded stego]: {decoded}" if decoded else None
        except ValueError:
            return None

    # ── Internal: content-type detection ─────────────────────────────────

    @staticmethod
    def _detect_type(content: str) -> str:
        """Heuristically detect content type from raw text."""
        stripped = content.strip()

        # JSON: starts with { or [ and parses successfully.
        if stripped.startswith(("{", "[")):
            try:
                json.loads(stripped)
                return "json"
            except (json.JSONDecodeError, ValueError):
                pass

        # HTML: has characteristic tags or DOCTYPE.
        if re.search(r"<!DOCTYPE\s+html", stripped, re.IGNORECASE):
            return "html"
        if re.search(
            r"<(?:html|head|body|div|span|p|script|meta)\b",
            stripped,
            re.IGNORECASE,
        ):
            return "html"

        # Markdown: headers, bold, horizontal rules, or reference links.
        if re.search(
            r"^#{1,6}\s|\*\*\S|\[.*\]\(http|^-{3,}$",
            stripped,
            re.MULTILINE,
        ):
            return "markdown"

        return "text"
