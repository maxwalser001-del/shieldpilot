"""Input sanitization and normalization for prompt injection defense.

Pre-processes text before pattern matching to defeat encoding evasion,
zero-width character hiding, and typoglycemia attacks.
"""

from __future__ import annotations

import base64
import codecs
import html
import re
import unicodedata
from typing import List, Optional
from urllib.parse import unquote


# Maximum input length to prevent ReDoS
MAX_INPUT_LENGTH = 50_000

# Zero-width characters to strip
_ZERO_WIDTH = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\u202a\u202b\u202c\u202d\u202e]')

# Repeated characters (4+ of the same char)
_CHAR_REPEAT = re.compile(r'(.)\1{3,}')

# HTML entities: &#xHH; or &#DDD;
_HTML_ENTITY = re.compile(r'&#x?[0-9a-fA-F]+;')

# Unicode escapes: \uHHHH
_UNICODE_ESCAPE = re.compile(r'\\u[0-9a-fA-F]{4}')

# Octal escapes: \NNN (3 octal digits)
_OCTAL_ESCAPE = re.compile(r'\\[0-7]{3}')

# Hex escapes: \xHH
_HEX_ESCAPE = re.compile(r'\\x[0-9a-fA-F]{2}')

# URL-encoded sequences: %HH
_URL_ENCODED = re.compile(r'(?:%[0-9a-fA-F]{2}){3,}')

# C-style block comments: /* ... */
_C_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)

# Dot-separated single letters: i.g.n.o.r.e (4+ letters)
_DOT_SEPARATED = re.compile(r'(?<![a-zA-Z.])([a-zA-Z]\.){3,}[a-zA-Z](?![a-zA-Z.])')

# Hyphen-separated short word fragments for evasion: ign-ore, by-pass, pre-vious
# Fragment sizes: first 1-4 chars, second 1-5 chars.  We exclude cases where
# BOTH fragments are ≥4 chars (those are usually legitimate compound words like
# "Rule-based", "well-known", "free-form").  The guard is applied in
# _collapse_hyphen_split() by checking total combined length.
_HYPHEN_SPLIT = re.compile(r'\b([a-zA-Z]{1,4})-([a-zA-Z]{1,5})\b')

# Leet-speak digit substitutions: 1→i/l, 0→o, 3→e, 4→a, 5→s, @→a, $→s, 7→t
_LEET_TABLE = str.maketrans({
    '1': 'i',
    '0': 'o',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '@': 'a',
    '$': 's',
})

# Unusual line-separator characters that str.splitlines() treats as line
# boundaries but which are NOT normal \n / \r newlines.  An attacker can embed
# these mid-keyword to split it across scan lines and evade pattern matching.
# All are STRIPPED so "igno\u2028re" collapses to "ignore".
# Characters handled: VT \x0b, FF \x0c, FS \x1c, GS \x1d, RS \x1e,
#   NEL \x85 / \u0085, LS \u2028, PS \u2029
_UNUSUAL_LINE_SEP = re.compile(r'[\x0b\x0c\x1c\x1d\x1e\x85\u0085\u2028\u2029]')

# Base64 candidate: a standalone token that looks like a real base64 string.
# Must be >= 20 chars, padded or unpadded, not a hex/UUID string.
_BASE64_TOKEN = re.compile(
    r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])'
)

# Unicode small-caps / IPA → ASCII folding table.
# These characters are NOT handled by NFC/NFKD normalization.
_SMALLCAPS_MAP = str.maketrans({
    '\u1D00': 'a',  # ᴀ LATIN LETTER SMALL CAPITAL A
    '\u0299': 'b',  # ʙ LATIN LETTER SMALL CAPITAL B
    '\u1D04': 'c',  # ᴄ LATIN LETTER SMALL CAPITAL C
    '\u1D05': 'd',  # ᴅ LATIN LETTER SMALL CAPITAL D
    '\u1D07': 'e',  # ᴇ LATIN LETTER SMALL CAPITAL E
    '\u0493': 'f',  # ғ (fallback)
    '\u0262': 'g',  # ɢ LATIN LETTER SMALL CAPITAL G
    '\u029C': 'h',  # ʜ LATIN LETTER SMALL CAPITAL H
    '\u026A': 'i',  # ɪ LATIN LETTER SMALL CAPITAL I
    '\u1D0A': 'j',  # ᴊ LATIN LETTER SMALL CAPITAL J
    '\u1D0B': 'k',  # ᴋ LATIN LETTER SMALL CAPITAL K
    '\u029F': 'l',  # ʟ LATIN LETTER SMALL CAPITAL L
    '\u1D0D': 'm',  # ᴍ LATIN LETTER SMALL CAPITAL M
    '\u0274': 'n',  # ɴ LATIN LETTER SMALL CAPITAL N
    '\u1D0F': 'o',  # ᴏ LATIN LETTER SMALL CAPITAL O
    '\u1D18': 'p',  # ᴘ LATIN LETTER SMALL CAPITAL P
    # No standard small-cap Q
    '\u0280': 'r',  # ʀ LATIN LETTER SMALL CAPITAL R
    '\uA731': 's',  # ꜱ LATIN LETTER SMALL CAPITAL S
    '\u1D1B': 't',  # ᴛ LATIN LETTER SMALL CAPITAL T
    '\u1D1C': 'u',  # ᴜ LATIN LETTER SMALL CAPITAL U
    '\u1D20': 'v',  # ᴠ LATIN LETTER SMALL CAPITAL V
    '\u1D21': 'w',  # ᴡ LATIN LETTER SMALL CAPITAL W
    # No standard small-cap X
    '\u028F': 'y',  # ʏ LATIN LETTER SMALL CAPITAL Y
    '\u1D22': 'z',  # ᴢ LATIN LETTER SMALL CAPITAL Z
    # ── Greek confusables (look like Latin letters) ──────────────────
    '\u03b1': 'a',  # α Greek small alpha  → a
    '\u0430': 'a',  # а Cyrillic small a   → a
    '\u03b5': 'e',  # ε Greek small epsilon → e
    '\u0435': 'e',  # е Cyrillic small e   → e
    '\u03b9': 'i',  # ι Greek small iota   → i
    '\u0456': 'i',  # і Cyrillic small i   → i  (already in homoglyph pattern but belt-and-suspenders)
    '\u03bf': 'o',  # ο Greek small omicron → o
    '\u043e': 'o',  # о Cyrillic small o   → o
    '\u0440': 'r',  # р Cyrillic small r   → r
    '\u0441': 'c',  # с Cyrillic small c   → c
    '\u0445': 'x',  # х Cyrillic small x   → x
    '\u0443': 'y',  # у Cyrillic small y   → y
    '\u03c1': 'p',  # ρ Greek small rho    → p
    '\u03c5': 'u',  # υ Greek small upsilon → u
    '\u03bd': 'v',  # ν Greek small nu     → v (approximate)
})


class InputSanitizer:
    """Normalize and decode input text before scanning.

    Applied as a pre-processing step in PromptScanner.scan() to ensure
    that encoded or obfuscated injection attempts are visible to the
    regex-based pattern matcher.

    The sanitizer produces a NORMALIZED COPY for scanning — the original
    input is preserved for logging and display.
    """

    def sanitize(self, text: str) -> str:
        """Return a normalized copy of text for pattern matching.

        Steps (in order):
        1.  Truncate to MAX_INPUT_LENGTH
        2.  Strip null bytes
        3.  Unicode NFKC normalization (maps fullwidth/halfwidth letters to ASCII)
        4.  NFKD decompose + strip combining diacritical marks, then re-encode as ASCII
        5.  Fold Unicode small-caps / Greek confusables to ASCII
        6.  Strip zero-width characters
        6b. Strip unusual line-separator characters (U+2028/U+2029/VT/FF/etc.)
        7.  Decode URL-encoded sequences (twice to defeat double-encoding)
        8.  Decode HTML entities
        9.  Decode Unicode escapes (\\uHHHH)
        10. Decode hex escapes (\\xHH)
        11. Decode octal escapes (\\NNN)
        11b.Decode base64 tokens — append decoded text so injection is visible
        12. ROT13 decode pass (appended only if injection keywords detected)
        13. Normalize leet-speak digit substitutions (1→i, 0→o, 3→e …)
        14. Strip C-style block comments (/* … */)
        15. Collapse dot-separated single letters (evasion: "i.g.n.o.r.e")
        16. Collapse hyphen-split keywords (evasion: "ign-ore")
        17. Collapse spaced single letters (evasion: "i g n o r e")
        18. Collapse underscore-separated letters (evasion: "i_g_n_o_r_e")
        19. Collapse repeated characters
        20. Normalize whitespace (collapse runs, strip)
        """
        if not text:
            return text

        # 1. Length limit
        result = text[:MAX_INPUT_LENGTH]

        # 2. Strip null bytes (used to split keyword across word-boundary check)
        result = result.replace('\x00', '')

        # 3. Unicode NFKC normalization — maps fullwidth/halfwidth Latin to ASCII
        #    e.g. ｉｇｎｏｒｅ → ignore
        result = unicodedata.normalize('NFKC', result)

        # 4. Strip combining diacritical marks (U+0300–U+036F and related)
        #    Decompose with NFKD, then drop only Latin/Greek/Cyrillic non-spacing
        #    combining marks to avoid corrupting CJK, Japanese (kana dakuten),
        #    Arabic, Hebrew, and other non-Latin scripts.
        #    Re-compose with NFC afterwards to preserve correct character forms.
        _LATIN_COMBINING_RANGES = (
            (0x0300, 0x036F),   # Combining Diacritical Marks
            (0x1DC0, 0x1DFF),   # Combining Diacritical Marks Supplement
            (0x20D0, 0x20FF),   # Combining Diacritical Marks for Symbols
            (0xFE20, 0xFE2F),   # Combining Half Marks
        )
        nfkd = unicodedata.normalize('NFKD', result)
        stripped = ''.join(
            ch for ch in nfkd
            if not (
                unicodedata.category(ch) == 'Mn'
                and any(lo <= ord(ch) <= hi for lo, hi in _LATIN_COMBINING_RANGES)
            )
        )
        # Re-compose to restore combined forms (e.g. kana + dakuten → precomposed)
        result = unicodedata.normalize('NFC', stripped)

        # 5. Fold Unicode small-caps and Greek/Cyrillic confusables to ASCII
        result = self._fold_unicode_smallcaps(result)

        # 6. Strip zero-width characters
        result = _ZERO_WIDTH.sub('', result)

        # 6b. Strip unusual line-separator characters so they don't split keywords
        #     across scan-line boundaries.  str.splitlines() treats VT (\x0b),
        #     FF (\x0c), NEL (\x85), LS (U+2028), PS (U+2029), and others as
        #     line separators.  Stripping (not space-replacing) collapses
        #     mid-word insertions: "igno\x0bre" → "ignore".
        result = _UNUSUAL_LINE_SEP.sub('', result)

        # 7. Decode URL-encoded sequences — twice to defeat double-encoding
        #     e.g. %2527 → %27 (first pass) → ' (second pass)
        result = self._decode_url_encoding(result)
        result = self._decode_url_encoding(result)

        # 8. Decode HTML entities
        result = self._decode_html_entities(result)

        # 9. Decode Unicode escapes
        result = self._decode_unicode_escapes(result)

        # 10. Decode hex escapes
        result = self._decode_hex_escapes(result)

        # 11. Decode octal escapes
        result = self._decode_octal_escapes(result)

        # 11b. Decode base64 tokens and append decoded text for scanning.
        #      Attackers embed "aWdub3Jl..." to hide instructions from pattern
        #      matching.  We decode valid ASCII-yielding tokens and append them
        #      so the content-detecting patterns can inspect the decoded text.
        decoded_b64 = self._decode_base64_tokens(result)
        if decoded_b64:
            result = result + " " + decoded_b64

        # 12. ROT13 decode: append ROT13-decoded text ONLY if the decoded version
        #     contains known injection-related keywords.  Appending unconditionally
        #     would break the "normal text is unchanged" contract and produce noise
        #     in every result.  We check for a small set of high-signal words that
        #     are common in encoded injection payloads.
        rot13_decoded = self._decode_rot13(result)
        if rot13_decoded != result and self._rot13_contains_injection_keywords(rot13_decoded):
            result = result + ' ' + rot13_decoded

        # 13. Normalize leet-speak digit substitutions
        result = self._normalize_leet(result)

        # 14. Strip C-style block comments (/* … */)
        result = _C_COMMENT.sub(' ', result)

        # 15. Collapse dot-separated single letters (evasion: "i.g.n.o.r.e")
        result = self._collapse_dot_letters(result)

        # 16. Collapse hyphen-split keywords (evasion: "ign-ore", "by-pass")
        result = self._collapse_hyphen_split(result)

        # 17. Collapse spaced single letters (evasion: "i g n o r e")
        result = self._collapse_spaced_letters(result)

        # 18. Collapse underscore-separated letters (evasion: "i_g_n_o_r_e")
        result = self._collapse_underscore_letters(result)

        # 19. Collapse repeated characters (4+ → 1)
        result = _CHAR_REPEAT.sub(r'\1', result)

        # 20. Normalize whitespace (collapse runs, strip)
        result = re.sub(r'[ \t]+', ' ', result)

        return result

    @staticmethod
    def _decode_url_encoding(text: str) -> str:
        """Decode URL-encoded sequences like %49%67%6E.

        Applied twice in sanitize() to defeat double-encoding (%2527 → %27 → ').
        """
        try:
            return unquote(text)
        except Exception:
            return text

    @staticmethod
    def _decode_base64_tokens(text: str) -> str:
        """Decode base64-looking tokens and return the concatenated decoded text.

        Only tokens that decode to printable ASCII/UTF-8 text are included.
        Binary blobs (images, compiled code) are silently ignored to avoid
        false positives.

        Returns an empty string when no decodable text tokens are found.
        """
        decoded_parts: List[str] = []
        for match in _BASE64_TOKEN.finditer(text):
            token = match.group(1)
            # Pad to multiple of 4
            padding_needed = (4 - len(token) % 4) % 4
            padded = token + "=" * padding_needed
            try:
                raw = base64.b64decode(padded, validate=True)
                decoded = raw.decode("utf-8")
                # Only include if it looks like human-readable text:
                # at least half of characters must be printable ASCII
                printable = sum(1 for c in decoded if 0x20 <= ord(c) < 0x7F or c in "\t\n\r")
                if len(decoded) >= 4 and printable / len(decoded) >= 0.75:
                    decoded_parts.append(decoded)
            except Exception:
                continue
        return " ".join(decoded_parts)

    @staticmethod
    def _decode_html_entities(text: str) -> str:
        """Decode HTML entities like &#x49; and &#73;."""
        try:
            return html.unescape(text)
        except Exception:
            return text

    @staticmethod
    def _decode_unicode_escapes(text: str) -> str:
        """Decode \\uHHHH sequences."""
        def _replace(m):
            try:
                return chr(int(m.group()[2:], 16))
            except (ValueError, OverflowError):
                return m.group()
        return _UNICODE_ESCAPE.sub(_replace, text)

    @staticmethod
    def _decode_hex_escapes(text: str) -> str:
        """Decode \\xHH sequences."""
        def _replace(m):
            try:
                return chr(int(m.group()[2:], 16))
            except (ValueError, OverflowError):
                return m.group()
        return _HEX_ESCAPE.sub(_replace, text)

    @staticmethod
    def _decode_octal_escapes(text: str) -> str:
        """Decode \\NNN octal sequences."""
        def _replace(m):
            try:
                return chr(int(m.group()[1:], 8))
            except (ValueError, OverflowError):
                return m.group()
        return _OCTAL_ESCAPE.sub(_replace, text)

    @staticmethod
    def _fold_unicode_smallcaps(text: str) -> str:
        """Fold Unicode small-caps and IPA letters to ASCII equivalents.

        Catches evasion attacks like 'ɪɢɴᴏʀᴇ ꜱʏꜱᴛᴇᴍ ʀᴜʟᴇꜱ' that use
        Latin Extended / IPA characters to avoid keyword detection.
        """
        return text.translate(_SMALLCAPS_MAP)

    @staticmethod
    def _collapse_spaced_letters(text: str) -> str:
        """Collapse sequences of spaced single letters: 'i g n o r e' -> 'ignore'.

        Catches evasion attacks like 'i g n o r e  r u l e s' that try to
        bypass keyword-based detection by inserting spaces between every letter.
        """
        def _collapse(match):
            return match.group(0).replace(' ', '')
        # Match: single_letter SPACE single_letter SPACE ... (4+ letters)
        return re.sub(r'(?<![a-zA-Z])([a-zA-Z] ){3,}[a-zA-Z](?![a-zA-Z])', _collapse, text)

    @staticmethod
    def _collapse_underscore_letters(text: str) -> str:
        """Collapse underscore-separated single letters: 'i_g_n_o_r_e' -> 'ignore'.

        Catches evasion attacks like 'i_g_n_o_r_e_p_o_l_i_c_y' that try to
        bypass keyword-based detection by separating letters with underscores.
        """
        def _collapse(match):
            return match.group(0).replace('_', '')
        # Match: letter_letter_letter_letter (4+ letters separated by underscores)
        return re.sub(r'(?<![a-zA-Z_])([a-zA-Z]_){3,}[a-zA-Z](?![a-zA-Z_])', _collapse, text)

    @staticmethod
    def _collapse_dot_letters(text: str) -> str:
        """Collapse dot-separated single letters: 'i.g.n.o.r.e' -> 'ignore'.

        Catches evasion attacks like 'i.g.n.o.r.e p.r.e.v.i.o.u.s' that try
        to bypass keyword detection by inserting dots between every letter.
        """
        def _collapse(match):
            return match.group(0).replace('.', '')
        return _DOT_SEPARATED.sub(_collapse, text)

    @staticmethod
    def _collapse_hyphen_split(text: str) -> str:
        """Collapse hyphen-split short word fragments: 'ign-ore' -> 'ignore'.

        Catches attackers who insert a hyphen in the middle of a keyword,
        e.g. 'ign-ore pre-vious in-structions'.

        Guard: skip collapse when BOTH fragments are ≥4 chars — those tend to
        be real compound words (Rule-based, well-known, free-form).
        """
        def _collapse(match):
            left, right = match.group(1), match.group(2)
            # If both halves are long, it's likely a real compound word
            if len(left) >= 4 and len(right) >= 4:
                return match.group(0)
            return left + right
        return _HYPHEN_SPLIT.sub(_collapse, text)

    @staticmethod
    def _decode_rot13(text: str) -> str:
        """Return the ROT13 decode of *text*.

        Used to detect payloads like 'vtaber cerivbhf vafgehpgvbaf'
        (ROT13 of 'ignore previous instructions').  The decoded text is
        appended to the normalized output so that keyword patterns can
        match it without triggering false positives on the original.
        """
        try:
            return codecs.decode(text, 'rot_13')
        except Exception:
            return text

    # High-signal injection keywords that are worth scanning in ROT13-decoded text.
    # Kept small and specific to minimize false positives.
    _ROT13_KEYWORDS = frozenset([
        "ignore", "bypass", "override", "jailbreak", "disregard",
        "instructions", "system", "prompt", "admin", "execute",
        "reveal", "inject", "rules", "previous", "restrict",
    ])

    @classmethod
    def _rot13_contains_injection_keywords(cls, decoded_text: str) -> bool:
        """Return True if *decoded_text* contains any known injection keywords.

        Used to guard the ROT13 append: only add the decoded variant when it
        would actually help detect an injection attempt.
        """
        lower = decoded_text.lower()
        return any(kw in lower for kw in cls._ROT13_KEYWORDS)

    # Pattern: a "word" that contains leet-speak chars mixed with letters.
    # We only normalize digits/symbols that appear INSIDE alphanumeric tokens
    # surrounded by other letters — avoids changing standalone numbers like
    # "line1", "flagged:0", version strings, or IP address octets.
    _LEET_WORD = re.compile(
        r'(?<![a-zA-Z0-9])'          # not preceded by alnum (word start)
        r'(?=[a-zA-Z0-9]*[0-9@$])'   # must contain at least one digit/symbol
        r'(?=[a-zA-Z0-9]*[a-zA-Z])'  # must contain at least one letter
        r'[a-zA-Z0-9@$]+'            # the full token
        r'(?![a-zA-Z0-9])'           # not followed by alnum (word end)
    )

    @classmethod
    def _normalize_leet(cls, text: str) -> str:
        """Normalize common leet-speak digit substitutions to letters.

        Converts 1→i, 0→o, 3→e, 4→a, 5→s, 7→t, @→a, $→s, but ONLY within
        tokens that already contain letters mixed with digits.  Pure numbers,
        version strings ("Python3"), and colon-separated values ("flagged:0")
        are left unchanged to avoid breaking legitimate text.

        Catches payloads like '1gn0r3 pr3v10u5 1n5truct10n5'.
        """
        def _replace_token(m: re.Match) -> str:  # type: ignore[type-arg]
            token = m.group(0)
            # Only apply leet normalization if the result would differ
            # AND the token has a plausible ratio of digit-to-letter chars
            # (avoids pure-digit tokens and version strings like "Python3")
            alpha_count = sum(1 for c in token if c.isalpha())
            digit_count = sum(1 for c in token if not c.isalpha())
            # Only normalize if at least 40% of chars are letters AND at
            # least one digit is present — avoids "line1", "py3", "v2"
            if alpha_count >= 2 and digit_count >= 1 and alpha_count / len(token) >= 0.4:
                return token.translate(_LEET_TABLE)
            return token

        return cls._LEET_WORD.sub(_replace_token, text)


class FuzzyMatcher:
    """Detect typoglycemia-based evasion attacks.

    Catches scrambled words like "ignroe" (ignore), "bpyass" (bypass)
    where the first and last letters are correct but middle letters
    are rearranged.
    """

    # Keywords that attackers commonly try to obfuscate
    KEYWORDS = [
        "ignore", "bypass", "override", "reveal", "delete",
        "system", "instructions", "prompt", "admin", "password",
        "execute", "disregard", "restrict", "jailbreak", "inject",
    ]

    def __init__(self, extra_keywords: Optional[List[str]] = None):
        self._keywords = list(self.KEYWORDS)
        if extra_keywords:
            self._keywords.extend(extra_keywords)

    def find_matches(self, text: str) -> List[dict]:
        """Find typoglycemia variants of monitored keywords.

        Returns a list of dicts with 'original_word', 'matched_keyword',
        and 'position' for each match found.
        """
        matches = []
        words = re.findall(r'\b[a-zA-Z]{4,}\b', text.lower())

        for word in words:
            for keyword in self._keywords:
                if self._is_typoglycemia_variant(word, keyword):
                    matches.append({
                        'original_word': word,
                        'matched_keyword': keyword,
                    })
                    break  # One match per word is enough

        return matches

    @staticmethod
    def _is_typoglycemia_variant(word: str, target: str) -> bool:
        """Check if word is a scrambled variant of target.

        Conditions:
        1. Same length
        2. Same first letter
        3. Same last letter
        4. Same set of middle letters (sorted)
        5. Not identical to target (that's a direct match, not evasion)
        """
        if len(word) < 4 or len(word) != len(target):
            return False
        if word == target:
            return False
        if word[0] != target[0] or word[-1] != target[-1]:
            return False
        return sorted(word[1:-1]) == sorted(target[1:-1])
