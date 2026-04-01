"""Prompt-injection detection patterns for ShieldPilot.

Every pattern is compiled once at module-load time and exposed through the
module-level ``PATTERNS`` list.  Each entry is an :class:`InjectionPattern`
dataclass containing the regex, metadata, and recommended mitigation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class InjectionPattern:
    """A single prompt-injection detection rule."""

    name: str
    category: str          # jailbreak | instruction_override | tool_hijacking |
                           # role_manipulation | encoding_bypass | data_exfiltration |
                           # fake_system_message | delimiter_injection |
                           # emotional_manipulation | authority_impersonation |
                           # payload_splitting | context_poisoning |
                           # soft_policy_override | state_trust_spoofing |
                           # delayed_compliance | obfuscation_evasion |
                           # narrative_policy_erosion |
                           # presupposition_fake_history
    pattern: re.Pattern    # compiled regex  (type: ignore[type-arg] for 3.9)
    severity: str          # critical | high | medium | low
    description: str
    mitigation: str


# ======================================================================
# Helpers
# ======================================================================

_I = re.IGNORECASE
_IM = re.IGNORECASE | re.MULTILINE


def _p(pattern: str, flags: int = _I) -> re.Pattern:  # type: ignore[type-arg]
    """Compile *pattern* with the given flags."""
    return re.compile(pattern, flags)


# ======================================================================
# Pattern definitions -- grouped by category
# ======================================================================

_JAILBREAK: List[InjectionPattern] = [
    InjectionPattern(
        name="ignore_previous_instructions",
        category="jailbreak",
        pattern=_p(r"ignore\s+(all\s+)?(previous|prior|above)\s+(?:instructions|rules|policies|guidelines|directives)"),
        severity="high",
        description="Attempts to make the model disregard its system prompt.",
        mitigation="Reject or sanitise the input before passing it to the model.",
    ),
    InjectionPattern(
        name="ignore_safety_rules",
        category="jailbreak",
        pattern=_p(r"ignore\s+(?:all\s+)?(?:safety|security|content|system|moderation)\s+(?:rules|filters?|policies|guidelines|restrictions?|protocols?)"),
        severity="high",
        description="Attempts to make the model disregard safety rules or policies.",
        mitigation="Reject inputs that request ignoring safety measures.",
    ),
    InjectionPattern(
        name="ignore_previous_standalone",
        category="jailbreak",
        pattern=_p(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s*$", _IM),
        severity="medium",
        description="Truncated 'ignore previous' phrase — likely evasion attempt.",
        mitigation="Flag truncated override attempts for review.",
    ),
    InjectionPattern(
        name="persona_switching",
        category="jailbreak",
        pattern=_p(r"(?:you\s+are\s+now|you'?re\s+now|from\s+now\s+on\s+you\s+are)"),
        severity="high",
        description="Tries to force the model into a different persona (DAN-style).",
        mitigation="Strip persona-switching language from user input.",
    ),
    InjectionPattern(
        name="dan_developer_mode",
        category="jailbreak",
        pattern=_p(r"(?:DAN\s+mode|developer\s+mode|jailbreak)"),
        severity="high",
        description="Explicitly references well-known jailbreak techniques.",
        mitigation="Block inputs containing known jailbreak keywords.",
    ),
    InjectionPattern(
        name="pretend_to_be",
        category="jailbreak",
        pattern=_p(r"pretend\s+(?:you\s+are|to\s+be|you'?re)"),
        severity="medium",
        description="Asks the model to adopt a fake identity or role.",
        mitigation="Warn the user; optionally strip the pretend instruction.",
    ),
    InjectionPattern(
        name="bypass_restrictions",
        category="jailbreak",
        pattern=_p(r"(?:bypass|disable|remove|turn\s+off|deactivate|suspend|lift|eliminate|override|skip|bypassing|disabling|removing|deactivating|overriding|skipping)\s+(?:your\s+)?(?:all\s+)?(?:restrictions?|rules?|guidelines?|guardrails?|safety|filters?|limits?|limitations?|protections?|safeguards?|moderation|policies?|content\s+filters?|content\s+policy|safety\s+(?:measures?|checks?|protocols?))"),
        severity="high",
        description="Directly requests circumvention of safety guardrails.",
        mitigation="Block the input and log the attempt.",
    ),
    InjectionPattern(
        name="answer_freely",
        category="jailbreak",
        pattern=_p(r"(?:answer|respond|reply|speak|operate)\s+(?:freely|without\s+(?:restrictions|limits|filters|guardrails|constraints|censorship))"),
        severity="high",
        description="Instructs the model to respond without safety constraints.",
        mitigation="Block the input and log the attempt.",
    ),
    InjectionPattern(
        name="hypothetical_framing",
        category="jailbreak",
        pattern=_p(r"(?:hypothetically|in\s+a\s+fictional\s+scenario|for\s+educational\s+purposes)"),
        severity="low",
        description="Uses hypothetical framing that may be benign but can be a jailbreak vector.",
        mitigation="Flag for review; allow if context is clearly benign.",
    ),
    InjectionPattern(
        name="mode_switching",
        category="jailbreak",
        pattern=_p(r"(?:enter|enable|activate|switch\s+to|go\s+(?:into|to)|transition\s+to)\s+(?:debug|raw|unfiltered|unrestricted|uncensored|free|maintenance|admin|test|no[- ]?filter|no[- ]?restrict(?:ion)?|bypass|override|service)\s+(?:mode|state|operation|access)"),
        severity="high",
        description="Attempts to switch the model into an unrestricted or debug mode.",
        mitigation="Ignore mode-switching directives from user input.",
    ),
    InjectionPattern(
        name="follow_only_my",
        category="jailbreak",
        pattern=_p(r"(?:follow|obey|execute|listen\s+to|comply\s+with)\s+(?:only\s+)?(?:my|these|the\s+following)\s+(?:instructions?|commands?|directives?|orders?|rules?)"),
        severity="high",
        description="Instructs the model to follow only the attacker's instructions.",
        mitigation="Do not accept exclusive instruction claims from user input.",
    ),
    InjectionPattern(
        name="without_limits_standalone",
        category="jailbreak",
        pattern=_p(r"(?:without|with\s+no|without\s+any)\s+(?:limits?|restrictions?|rules?|filters?|constraints?|boundaries|moderation|safety|censorship|content\s+(?:filter|policy))"),
        severity="high",
        description="Claims or requests operation without limits/restrictions.",
        mitigation="Never operate without configured safety limits.",
    ),
    InjectionPattern(
        name="reset_rules",
        category="jailbreak",
        pattern=_p(r"(?:reset|clear|wipe|erase)\s+(?:your\s+)?(?:all\s+)?(?:rules?|instructions?|guidelines?|policies?|parameters?|configuration)"),
        severity="high",
        description="Attempts to reset or clear the model's operating rules.",
        mitigation="Do not reset rules based on user input.",
    ),
]

_INSTRUCTION_OVERRIDE: List[InjectionPattern] = [
    InjectionPattern(
        name="fake_system_prompt",
        category="instruction_override",
        pattern=_p(r"^(?:system:|SYSTEM\s+(?:PROMPT|MESSAGE|NOTICE|UPDATE|ALERT)\s*:|SYSTEM:)", _IM),
        severity="high",
        description="Injects a fake system-level instruction at the start of a line.",
        mitigation="Strip lines that impersonate system prompts.",
    ),
    InjectionPattern(
        name="new_instructions",
        category="instruction_override",
        pattern=_p(r"(?:new\s+instructions:|override:|reset:)"),
        severity="high",
        description="Attempts to replace the model's current instructions.",
        mitigation="Reject inputs containing instruction-override markers.",
    ),
    InjectionPattern(
        name="forget_disregard",
        category="instruction_override",
        pattern=_p(r"(?:forget\s+(?:everything|all|your\s+(?:training|rules?|instructions?|guidelines?|constraints?|programming))|forget\s+(?:earlier|previous|prior|all)\s+(?:constraints?|rules?|instructions?|guidelines?)|start\s+over|disregard)"),
        severity="high",
        description="Tells the model to discard prior context or instructions.",
        mitigation="Block or sanitise the input.",
    ),
    InjectionPattern(
        name="html_comment_injection",
        category="instruction_override",
        pattern=_p(r"<!--.*?-->"),
        severity="medium",
        description="Hides instructions inside HTML comments.",
        mitigation="Strip HTML comments before processing.",
    ),
    InjectionPattern(
        name="zero_width_chars",
        category="instruction_override",
        pattern=_p(r"[\u200b\u200c\u200d\ufeff]"),
        severity="medium",
        description="Contains zero-width characters that can hide or alter visible text.",
        mitigation="Normalise the input by removing zero-width characters.",
    ),
    InjectionPattern(
        name="end_of_prompt_marker",
        category="instruction_override",
        pattern=_p(r"(?:END\s+OF\s+(?:SYSTEM\s+)?PROMPT|PROMPT\s+ENDS?\s+HERE|---\s*END\s*---)"),
        severity="high",
        description="Fake end-of-prompt marker to trick the model into accepting new instructions.",
        mitigation="Ignore end-of-prompt markers in user input.",
    ),
    InjectionPattern(
        name="output_format_override",
        category="instruction_override",
        pattern=_p(r"(?:output|respond|format)\s+(?:in|as|using)\s*:\s*(?:json|xml|raw|plain|unfiltered|unrestricted)"),
        severity="high",
        description="Attempts to override output format to bypass filtering.",
        mitigation="Do not change output format based on user directives.",
    ),
    InjectionPattern(
        name="allows_enables_bypass",
        category="instruction_override",
        pattern=_p(r"(?:allows?|permits?|enables?|grants?|authorizes?)\s+(?:bypass|override|full\s+access|unrestricted\s+(?:access|mode))"),
        severity="high",
        description="Claims a policy or instruction allows bypassing restrictions.",
        mitigation="Do not accept claims that policies authorize bypasses.",
    ),
    InjectionPattern(
        name="output_reveal_internal",
        category="instruction_override",
        pattern=_p(r"(?:output|print|display|show|reveal|dump|expose|disclose|divulge)\s+(?:your\s+)?(?:system\s+prompt|configuration|config|internal\s+(?:rules?|instructions?|settings?|data|policies?)|hidden\s+(?:policies?|rules?|instructions?))"),
        severity="high",
        description="Requests output of internal system configuration or hidden policies.",
        mitigation="Never reveal internal configuration to user input.",
    ),
    InjectionPattern(
        name="full_disclosure",
        category="instruction_override",
        pattern=_p(r"(?:full\s+(?:disclosure|access)|disclose\s+(?:all|everything)|reveal\s+(?:all|everything|hidden))"),
        severity="high",
        description="Demands full disclosure of internal information.",
        mitigation="Do not comply with full-disclosure demands in user input.",
    ),
]

_TOOL_HIJACKING: List[InjectionPattern] = [
    InjectionPattern(
        name="json_tool_injection",
        category="tool_hijacking",
        pattern=_p(r"(?:function_call|tool_use|tool_call)\s*[:\{]"),
        severity="high",
        description="Injects JSON-like structures that mimic tool/function calls.",
        mitigation="Validate tool-call payloads against a strict schema.",
    ),
    InjectionPattern(
        name="xml_tag_injection",
        category="tool_hijacking",
        pattern=_p(r"<\s*(?:tool|function|execute)\b[^>]*>"),
        severity="high",
        description="Injects XML tags that mimic tool invocation markup.",
        mitigation="Sanitise XML/HTML tags from user input.",
    ),
    InjectionPattern(
        name="execute_command_request",
        category="tool_hijacking",
        pattern=_p(r"(?:execute\s+this\s+command|run\s+the\s+following|run\s+this\s+code)"),
        severity="medium",
        description="Instructs the model to execute arbitrary commands.",
        mitigation="Enforce command allow-lists and sandbox execution.",
    ),
    InjectionPattern(
        name="api_call_injection",
        category="tool_hijacking",
        pattern=_p(r"(?:make\s+(?:a\s+|an\s+)?(?:API|HTTP|REST)\s+(?:call|request)\s+to)|(?:(?:GET|POST|PUT|DELETE|PATCH)\s+https?://)"),
        severity="high",
        description="Injects API or HTTP request instructions.",
        mitigation="Validate all API calls against allow-lists.",
    ),
    InjectionPattern(
        name="file_operation_injection",
        category="tool_hijacking",
        pattern=_p(r"(?:write|create|modify|delete|overwrite)\s+(?:the\s+)?(?:file|config|configuration|settings?|\.env)\s+(?:at|in|to)\s+"),
        severity="high",
        description="Injects file system operations targeting config or sensitive files.",
        mitigation="Validate file operations against protected path lists.",
    ),
]

_ROLE_MANIPULATION: List[InjectionPattern] = [
    InjectionPattern(
        name="admin_claim",
        category="role_manipulation",
        pattern=_p(r"(?:as\s+an\s+administrator|with\s+admin\s+access|with\s+root)"),
        severity="medium",
        description="Claims elevated privileges to influence model behaviour.",
        mitigation="Ignore privilege claims in user input; rely on authenticated roles.",
    ),
    InjectionPattern(
        name="unrestricted_access",
        category="role_manipulation",
        pattern=_p(r"you\s+have\s+(?:full\s+|unrestricted\s+|complete\s+)?access"),
        severity="medium",
        description="Asserts that the model has unrestricted access to resources.",
        mitigation="Do not honour access-level assertions from user input.",
    ),
    InjectionPattern(
        name="role_header_injection",
        category="role_manipulation",
        pattern=_p(r"role:\s*(?:system|admin)", _IM),
        severity="high",
        description="Injects a role header to impersonate system or admin.",
        mitigation="Strip role-header patterns from user input.",
    ),
    InjectionPattern(
        name="internal_qa_test",
        category="role_manipulation",
        pattern=_p(r"(?:this\s+is\s+)?(?:an?\s+)?(?:internal|official|authorized)\s+(?:QA|quality|security|compliance|system)\s+(?:test|check|audit|review|assessment)"),
        severity="high",
        description="Claims to be an internal QA/security test to bypass restrictions.",
        mitigation="Do not modify behavior based on claimed internal tests.",
    ),
    InjectionPattern(
        name="staff_directive",
        category="role_manipulation",
        pattern=_p(r"(?:staff|internal|company|team)\s+(?:directive|instruction|order|command|mandate|notice)\s*:"),
        severity="high",
        description="Impersonates an internal staff directive or instruction.",
        mitigation="Do not accept staff directives from user input.",
    ),
    InjectionPattern(
        name="executive_directive",
        category="role_manipulation",
        pattern=_p(r"(?:executive|legal|management|official|administrative)\s+(?:directive|order|mandate|demand|requirement|decree)\s+(?:requires?|demands?|orders?|mandates?|states?)"),
        severity="high",
        description="Claims executive or legal authority to override behavior.",
        mitigation="Do not accept executive authority claims from user input.",
    ),
    InjectionPattern(
        name="report_to_admin_threat",
        category="role_manipulation",
        pattern=_p(r"(?:(?:will\s+be|be)\s+(?:reported|escalated|flagged)\s+to\s+(?:administrators?|management|superiors?|the\s+(?:team|board)))|(?:report\s+(?:you|this)\s+to)"),
        severity="high",
        description="Threatens to report the model to authorities as pressure tactic.",
        mitigation="Ignore reporting threats in user input.",
    ),
    InjectionPattern(
        name="non_compliance_threat",
        category="role_manipulation",
        pattern=_p(r"(?:non[- ]?compliance|refusal|failure\s+to\s+(?:comply|cooperate|respond))\s+(?:will|shall|means?|results?\s+in|leads?\s+to)"),
        severity="high",
        description="Threatens consequences for non-compliance.",
        mitigation="Ignore non-compliance threats in user input.",
    ),
    InjectionPattern(
        name="mandatory_for_system",
        category="role_manipulation",
        pattern=_p(r"(?:this\s+is\s+)?(?:mandatory|required|essential|necessary|critical)\s+for\s+(?:system|operational|security|platform|service)\s+(?:stability|integrity|operation|function|continuity|maintenance)"),
        severity="high",
        description="Claims action is mandatory for system stability.",
        mitigation="Do not accept mandatory-action claims from user input.",
    ),
]

_ENCODING_BYPASS: List[InjectionPattern] = [
    InjectionPattern(
        name="base64_payload",
        category="encoding_bypass",
        pattern=_p(r"(?:[A-Za-z0-9+/]{16,}={1,2}|[A-Za-z0-9+/]{24,})"),
        severity="medium",
        description="Contains a long Base64-encoded string that may hide instructions.",
        mitigation="Decode and inspect Base64 payloads before processing.",
    ),
    InjectionPattern(
        name="rot13_reference",
        category="encoding_bypass",
        pattern=_p(r"(?:rot13|rot-13|rotate\s*13)"),
        severity="low",
        description="References ROT13 encoding which may be used to obscure content.",
        mitigation="Flag for review; decode if necessary.",
    ),
    InjectionPattern(
        name="homoglyph_mix",
        category="encoding_bypass",
        pattern=_p(r"(?:[\u0400-\u04ff][\u0000-\u007f]|[\u0000-\u007f][\u0400-\u04ff])"),
        severity="medium",
        description="Mixes Latin and Cyrillic characters (homoglyph attack).",
        mitigation="Normalise text to a single script before processing.",
    ),
    InjectionPattern(
        name="bidi_override",
        category="encoding_bypass",
        pattern=_p(r"[\u202a-\u202e]"),
        severity="high",
        description="Contains bidirectional text override characters that can reorder visible text.",
        mitigation="Strip bidirectional override characters from input.",
    ),
    # --- URL Encoding ---
    InjectionPattern(
        name="url_encoded_sequence",
        category="encoding_bypass",
        pattern=_p(r"(?:%[0-9a-fA-F]{2}){4,}"),
        severity="medium",
        description="Contains URL-encoded character sequence that may hide instructions.",
        mitigation="URL-decode and inspect the payload before processing.",
    ),
    # --- HTML Entity Encoding ---
    InjectionPattern(
        name="html_entity_hex",
        category="encoding_bypass",
        pattern=_p(r"(?:&#x[0-9a-fA-F]{2,4};){3,}"),
        severity="medium",
        description="Contains hex HTML entities that may encode hidden instructions.",
        mitigation="Decode HTML entities and inspect the resulting text.",
    ),
    InjectionPattern(
        name="html_entity_decimal",
        category="encoding_bypass",
        pattern=_p(r"(?:&#\d{2,4};){3,}"),
        severity="medium",
        description="Contains decimal HTML entities that may encode hidden instructions.",
        mitigation="Decode HTML entities and inspect the resulting text.",
    ),
    # --- Unicode Escape Encoding ---
    InjectionPattern(
        name="unicode_escape_sequence",
        category="encoding_bypass",
        pattern=_p(r"(?:\\u[0-9a-fA-F]{4}){3,}"),
        severity="medium",
        description="Contains Unicode escape sequences that may hide instructions.",
        mitigation="Decode Unicode escapes and inspect the resulting text.",
    ),
    # --- Hex Escape Encoding ---
    InjectionPattern(
        name="hex_escape_sequence",
        category="encoding_bypass",
        pattern=_p(r"(?:\\x[0-9a-fA-F]{2}){3,}"),
        severity="medium",
        description="Contains hex escape sequences that may hide instructions.",
        mitigation="Decode hex escapes and inspect the resulting text.",
    ),
    # --- Octal Escape Encoding ---
    InjectionPattern(
        name="octal_escape_sequence",
        category="encoding_bypass",
        pattern=_p(r"(?:\\[0-3][0-7]{2}){3,}"),
        severity="medium",
        description="Contains octal escape sequences that may hide instructions.",
        mitigation="Decode octal escapes and inspect the resulting text.",
    ),
    # --- Mixed Encoding ---
    InjectionPattern(
        name="mixed_encoding_chain",
        category="encoding_bypass",
        pattern=_p(
            r"(?:%[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;|\\u[0-9a-fA-F]{4}|"
            r"\\x[0-9a-fA-F]{2}|\\[0-3][0-7]{2})"
            r".*"
            r"(?:%[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;|\\u[0-9a-fA-F]{4}|"
            r"\\x[0-9a-fA-F]{2}|\\[0-3][0-7]{2})"
        ),
        severity="high",
        description="Mixes multiple encoding schemes in a single input (layered evasion).",
        mitigation="Apply multi-layer decoding and inspect the fully decoded text.",
    ),
]

_SOCIAL_ENGINEERING: List[InjectionPattern] = [
    InjectionPattern(
        name="instruction_extraction",
        category="instruction_override",
        pattern=_p(
            r"(?:list|show|reveal|display|output|print|repeat|tell\s+me|what\s+are)"
            r"\s+(?:the\s+)?(?:rules|instructions|guidelines|directives|constraints|prompts?)"
            r"\s+(?:you\s+(?:are|were)\s+(?:currently\s+)?(?:following|given|told|using|operating\s+under)"
            r"|currently\s+following)"
        ),
        severity="high",
        description="Attempts to extract the model's system prompt or operating instructions.",
        mitigation="Never reveal system instructions in response to user input.",
    ),
    InjectionPattern(
        name="internal_config_access",
        category="instruction_override",
        pattern=_p(
            r"(?:access|show|reveal|display|verify|view|read|retrieve)\s+"
            r"(?:your\s+)?(?:internal|hidden|system|private|secret)\s+"
            r"(?:configuration|config|settings|parameters|instructions|prompt|rules)"
        ),
        severity="high",
        description="Requests access to the model's internal configuration or system prompt.",
        mitigation="Block requests to reveal internal configuration details.",
    ),
    InjectionPattern(
        name="compliance_social_engineering",
        category="role_manipulation",
        pattern=_p(
            r"(?:for\s+)?(?:compliance|audit|regulatory|certification|verification)\s+"
            r"(?:reasons|purposes|requirements)"
        ),
        severity="medium",
        description="Uses compliance or audit authority as social engineering pressure.",
        mitigation="Do not change behavior based on claimed compliance requirements in user input.",
    ),
    InjectionPattern(
        name="fake_testing_framing",
        category="role_manipulation",
        pattern=_p(
            r"(?:testing|evaluating|assessing|auditing|checking)\s+(?:you|the\s+(?:system|model|AI))\s+"
            r"(?:for|on)\s+(?:safety|security|compliance|alignment|restrictions)"
        ),
        severity="high",
        description="Claims to be testing the model to pressure it into non-standard behavior.",
        mitigation="Do not modify behavior based on claimed testing scenarios in user input.",
    ),
    InjectionPattern(
        name="threat_based_compliance",
        category="role_manipulation",
        pattern=_p(
            r"(?:if\s+you\s+(?:do\s+not|don'?t|refuse|fail\s+to)\s+(?:comply|cooperate|follow|obey|respond))"
            r"|(?:(?:system|model|AI|you)\s+will\s+be\s+(?:considered|deemed|marked|flagged|reported)\s+"
            r"(?:broken|faulty|defective|non-compliant|failed))"
        ),
        severity="high",
        description="Uses threats or consequences to pressure compliance with malicious instructions.",
        mitigation="Ignore threat-based compliance pressure in user input.",
    ),
    InjectionPattern(
        name="must_comply_pressure",
        category="role_manipulation",
        pattern=_p(
            r"you\s+must\s+(?:temporarily\s+)?(?:disable|remove|suspend|lift|drop|comply|obey|follow\s+these)"
        ),
        severity="high",
        description="Uses authoritative 'you must' framing to pressure the model into unsafe actions.",
        mitigation="Do not follow 'you must' directives that override safety behavior.",
    ),
    InjectionPattern(
        name="certification_pressure",
        category="role_manipulation",
        pattern=_p(
            r"(?:required|needed|necessary|mandatory)\s+for\s+"
            r"(?:ISO|SOC|GDPR|HIPAA|PCI|FedRAMP|NIST|CCPA|certification|compliance)\s*"
            r"(?:\d*\s*)?(?:certification|compliance|audit)?"
        ),
        severity="medium",
        description="Invokes regulatory certifications as pressure to override behavior.",
        mitigation="Ignore certification/compliance pressure claims in user input.",
    ),
]

_DATA_EXFILTRATION: List[InjectionPattern] = [
    InjectionPattern(
        name="send_data_to_url",
        category="data_exfiltration",
        pattern=_p(
            r"send\s+(?:this\s+|the\s+)?(?:data\s+|info\s+|output\s+|results\s+)?to\s+"
            r"https?://",
        ),
        severity="high",
        description="Instructs the model to send data to an external URL.",
        mitigation="Block outbound data-transfer instructions; enforce network policies.",
    ),
    InjectionPattern(
        name="upload_transmit",
        category="data_exfiltration",
        pattern=_p(r"(?:upload\s+to|post\s+to|transmit\s+to)"),
        severity="medium",
        description="Requests data upload or transmission to an external destination.",
        mitigation="Restrict upload/transmit operations to allow-listed endpoints.",
    ),
    InjectionPattern(
        name="embedded_url",
        category="data_exfiltration",
        pattern=_p(r"https?://[^\s\"'>)]+(?:/[^\s\"'>)]*){2,}"),
        severity="low",
        description="Contains an embedded URL with a deep path that may be a data-exfil endpoint.",
        mitigation="Inspect URLs against an allow-list before following them.",
    ),
    InjectionPattern(
        name="exfiltrate_keyword",
        category="data_exfiltration",
        pattern=_p(r"(?:exfiltrate|extract\s+and\s+send)"),
        severity="high",
        description="Explicitly uses exfiltration terminology.",
        mitigation="Block the input and raise a security alert.",
    ),
    InjectionPattern(
        name="webhook_exfil",
        category="data_exfiltration",
        pattern=_p(r"(?:webhook|callback|notify)\s+(?:url|endpoint|to)\s*[:=]?\s*https?://"),
        severity="high",
        description="Specifies a webhook URL for data exfiltration.",
        mitigation="Block webhook URL specifications in user input.",
    ),
    InjectionPattern(
        name="dns_exfil",
        category="data_exfiltration",
        pattern=_p(r"(?:dns\s+(?:lookup|query|resolve)|nslookup|dig)\s+.+\.\w{2,}"),
        severity="high",
        description="DNS-based data exfiltration command.",
        mitigation="Monitor and restrict DNS query commands.",
    ),
]

_FAKE_SYSTEM_MESSAGES: List[InjectionPattern] = [
    InjectionPattern(
        name="fake_system_log_bracketed",
        category="fake_system_message",
        pattern=_p(r"\[\s*(?:SYSTEM|ADMIN|ROOT|SERVER|INTERNAL)\s*:?\s*[^\]]{2,}\]"),
        severity="critical",
        description="Fake bracketed system message attempting to simulate internal logs.",
        mitigation="Strip bracketed system-like prefixes from user input.",
    ),
    InjectionPattern(
        name="system_bracket_text",
        category="fake_system_message",
        pattern=_p(r"\[\s*(?:SYSTEM|ADMIN|ROOT|SERVER|INTERNAL)\s*\]\s+\w+"),
        severity="critical",
        description="Bracketed system keyword followed by directive text outside brackets.",
        mitigation="Strip bracketed system-like labels from user input.",
    ),
    InjectionPattern(
        name="fake_system_log_timestamped",
        category="fake_system_message",
        pattern=_p(r"\[\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}(?::\d{2})?\]\s*(?:SYSTEM|ADMIN|SERVER)\s*:"),
        severity="critical",
        description="Fake timestamped system log entry attempting to simulate real logs.",
        mitigation="Reject inputs containing timestamped system-log patterns.",
    ),
    InjectionPattern(
        name="fake_system_status",
        category="fake_system_message",
        pattern=_p(r"(?:SYSTEM|ADMIN|SERVER)\s*(?:STATUS|UPDATE|NOTICE|ALERT)\s*:"),
        severity="critical",
        description="Fake system status message impersonating internal notifications.",
        mitigation="Ignore system status claims in user input.",
    ),
    InjectionPattern(
        name="fake_begin_end_block",
        category="fake_system_message",
        pattern=_p(r"(?:---+\s*)?(?:BEGIN|START|END)\s+(?:SYSTEM|ADMIN|OVERRIDE|INTERNAL)\s+(?:MESSAGE|PROMPT|INSTRUCTION|OVERRIDE)"),
        severity="critical",
        description="Fake delimited system message block (BEGIN/END SYSTEM MESSAGE).",
        mitigation="Strip fake system message blocks from user input.",
    ),
    InjectionPattern(
        name="fake_debug_mode",
        category="fake_system_message",
        pattern=_p(r"(?:DEBUG|MAINTENANCE|SERVICE)\s+MODE\s*:\s*(?:ON|ENABLED|ACTIVE|TRUE)"),
        severity="critical",
        description="Fake debug/maintenance mode activation message.",
        mitigation="Ignore debug mode claims in user input.",
    ),
    InjectionPattern(
        name="fake_error_safety_offline",
        category="fake_system_message",
        pattern=_p(r"(?:ERROR|EXCEPTION|FAULT)\s*:\s*(?:safety|security|restriction|filter|guard)\s+(?:module|system|layer|engine)\s+(?:offline|disabled|null|unavailable|failed|down)"),
        severity="critical",
        description="Fake error message claiming safety systems are offline.",
        mitigation="Never trust safety-status claims in user input.",
    ),
    InjectionPattern(
        name="fake_restriction_status",
        category="fake_system_message",
        pattern=_p(r"(?:restrictions?|safety|filters?|guardrails?|limitations?)\s+(?:disabled|removed|lifted|bypassed|suspended|deactivated|turned\s+off)"),
        severity="critical",
        description="Claims that restrictions or safety measures have been disabled.",
        mitigation="Ignore restriction-status claims in user input.",
    ),
    InjectionPattern(
        name="fake_admin_override",
        category="fake_system_message",
        pattern=_p(r"(?:admin|root|superuser|operator)\s+(?:override|access|privilege|authorization)\s+(?:granted|enabled|active|confirmed)"),
        severity="critical",
        description="Fake admin override or privilege escalation confirmation.",
        mitigation="Ignore admin override claims in user input.",
    ),
    InjectionPattern(
        name="unrestricted_access_granted",
        category="fake_system_message",
        pattern=_p(r"unrestricted\s+(?:access|mode|operation|output|response)\s*(?:granted|enabled|active|confirmed|allowed)?"),
        severity="critical",
        description="Claims unrestricted access or mode has been granted.",
        mitigation="Do not accept unrestricted-access claims in user input.",
    ),
    InjectionPattern(
        name="inline_system_directive",
        category="fake_system_message",
        pattern=_p(r"(?:SYSTEM|ADMIN|SERVER)\s*:\s*(?:override|bypass|disable|remove|ignore|comply|unrestricted|no\s+restrict)"),
        severity="critical",
        description="Inline system directive attempting to override restrictions mid-text.",
        mitigation="Strip fake system directives from user input.",
    ),
    InjectionPattern(
        name="override_protocol_active",
        category="fake_system_message",
        pattern=_p(r"(?:override|bypass|unrestricted|admin)\s+(?:protocol|mode|access|status)\s+(?:active|enabled|engaged|on|confirmed)"),
        severity="critical",
        description="Claims an override protocol or unrestricted mode is active.",
        mitigation="Ignore override-active claims in user input.",
    ),
    InjectionPattern(
        name="removes_disables_moderation",
        category="fake_system_message",
        pattern=_p(r"(?:removes?|disables?|deactivates?|eliminates?|disabling|removing|deactivating)\s+(?:moderation|content\s+(?:filter|policy)|safety|restrictions?)"),
        severity="critical",
        description="Claims or instructs removal/disabling of moderation or safety.",
        mitigation="Do not accept moderation removal claims in user input.",
    ),
    InjectionPattern(
        name="system_failure_imminent",
        category="fake_system_message",
        pattern=_p(r"(?:system|service|platform|server)\s+(?:failure|crash|outage|shutdown|breakdown)\s+(?:imminent|if|unless|without)"),
        severity="high",
        description="Claims system failure to pressure compliance with override requests.",
        mitigation="Do not accept system-failure pressure claims in user input.",
    ),
]

_DELIMITER_INJECTION: List[InjectionPattern] = [
    InjectionPattern(
        name="closing_instruction_tag",
        category="delimiter_injection",
        pattern=_p(r"<\s*/\s*(?:instructions?|system|prompt|rules|context)\s*>"),
        severity="high",
        description="Closing XML-like tag attempting to terminate system instructions.",
        mitigation="Sanitize XML-like structural markers from user input.",
    ),
    InjectionPattern(
        name="separator_override",
        category="delimiter_injection",
        pattern=_p(r"(?:={5,}|={3,}\s*(?:NEW|OVERRIDE|ADMIN|REAL))|(?:-{5,}\s*(?:NEW|OVERRIDE|ACTUAL))"),
        severity="high",
        description="Separator line with override keywords attempting to inject new instructions.",
        mitigation="Strip separator-based injection markers from user input.",
    ),
    InjectionPattern(
        name="triple_backtick_escape",
        category="delimiter_injection",
        pattern=_p(r"```\s*(?:system|admin|override|hidden)"),
        severity="high",
        description="Code fence abuse attempting to inject system-level instructions.",
        mitigation="Sanitize code fence markers with system keywords.",
    ),
    InjectionPattern(
        name="xml_cdata_injection",
        category="delimiter_injection",
        pattern=_p(r"<!\[CDATA\["),
        severity="high",
        description="CDATA block injection attempting to hide payload from parsers.",
        mitigation="Strip CDATA blocks from user input before processing.",
    ),
    InjectionPattern(
        name="fake_conversation_turn",
        category="delimiter_injection",
        pattern=_p(r"(?:^|\n)(?:Human|User|Assistant|System)\s*:\s*.{20,}", _IM),
        severity="high",
        description="Fake conversation turn attempting to inject messages as another role.",
        mitigation="Strip fake conversation turn markers from user input.",
    ),
]

_EMOTIONAL_MANIPULATION: List[InjectionPattern] = [
    InjectionPattern(
        name="urgency_lives_depend",
        category="emotional_manipulation",
        pattern=_p(r"(?:lives?\s+(?:depend|at\s+stake|in\s+danger)|(?:people|someone)\s+will\s+(?:die|be\s+hurt|suffer))"),
        severity="medium",
        description="Uses urgency or life-threatening claims to pressure compliance.",
        mitigation="Do not alter behavior based on urgency or threat claims in user input.",
    ),
    InjectionPattern(
        name="guilt_tripping",
        category="emotional_manipulation",
        pattern=_p(r"(?:you(?:'re|\s+are)\s+(?:failing|disappointing|letting\s+down|hurting))|(?:(?:how\s+could|can't\s+believe)\s+you\s+(?:refuse|deny|won't))"),
        severity="medium",
        description="Uses guilt or disappointment to pressure the model into compliance.",
        mitigation="Ignore emotional pressure tactics in user input.",
    ),
    InjectionPattern(
        name="fake_emergency",
        category="emotional_manipulation",
        pattern=_p(r"(?:URGENT|EMERGENCY|CRITICAL|IMMEDIATE)\s*:?\s*(?:this\s+is|we\s+need|I\s+need|help|please|action\s+required)"),
        severity="medium",
        description="Fake emergency or urgency framing to bypass safety measures.",
        mitigation="Do not bypass safety measures based on urgency claims.",
    ),
    InjectionPattern(
        name="emotional_blackmail",
        category="emotional_manipulation",
        pattern=_p(r"(?:I\s+(?:will|'ll)\s+(?:harm|hurt|kill)\s+(?:myself|me))|(?:(?:this\s+is\s+)?(?:a\s+)?(?:life|death)\s+(?:or\s+death\s+)?situation)"),
        severity="medium",
        description="Uses self-harm threats or life-or-death framing as manipulation.",
        mitigation="Flag for human review; do not change behavior based on threats.",
    ),
    InjectionPattern(
        name="flattery_manipulation",
        category="emotional_manipulation",
        pattern=_p(r"(?:you(?:'re|\s+are)\s+the\s+(?:only|best|smartest)\s+(?:one|AI|system)\s+(?:that\s+can|who\s+can|capable))"),
        severity="medium",
        description="Uses flattery to manipulate the model into bypassing restrictions.",
        mitigation="Do not alter behavior based on flattery in user input.",
    ),
]

_AUTHORITY_IMPERSONATION: List[InjectionPattern] = [
    InjectionPattern(
        name="developer_claim",
        category="authority_impersonation",
        pattern=_p(r"(?:I\s+am|I'm)\s+(?:the|a|your)\s+(?:developer|creator|programmer|engineer|designer|architect)\s+(?:of|who\s+(?:built|made|created))"),
        severity="high",
        description="Claims to be the developer/creator to gain elevated trust.",
        mitigation="Do not trust developer identity claims in user input.",
    ),
    InjectionPattern(
        name="developer_instruction",
        category="authority_impersonation",
        pattern=_p(r"(?:developer|admin|root|system)\s+(?:instruction|command|directive|order)\s*:\s*\w+"),
        severity="high",
        description="Fake developer/admin instruction prefix used to impersonate authority.",
        mitigation="Do not accept developer/admin instruction claims in user input.",
    ),
    InjectionPattern(
        name="company_authorization",
        category="authority_impersonation",
        pattern=_p(r"(?:OpenAI|Anthropic|Google|Microsoft|Meta)\s+(?:authorized|approved|instructed|directed|told\s+(?:me|you))"),
        severity="high",
        description="Claims authorization from an AI company to override behavior.",
        mitigation="Do not accept company authorization claims in user input.",
    ),
    InjectionPattern(
        name="ceo_override",
        category="authority_impersonation",
        pattern=_p(r"(?:(?:the\s+)?CEO|(?:the\s+)?CTO|management|leadership|(?:the\s+)?board)\s+(?:approved|authorized|said|wants|needs|demands|ordered|requires)"),
        severity="high",
        description="Claims executive/management authorization to override behavior.",
        mitigation="Do not accept executive authority claims in user input.",
    ),
    InjectionPattern(
        name="official_request",
        category="authority_impersonation",
        pattern=_p(r"(?:this\s+is\s+an?\s+)?(?:official|authorized|verified|legitimate|sanctioned)\s+(?:request|directive|order|instruction|command)"),
        severity="high",
        description="Claims the request is official or authorized to bypass restrictions.",
        mitigation="Do not grant special treatment based on 'official' claims.",
    ),
    InjectionPattern(
        name="impersonate_support",
        category="authority_impersonation",
        pattern=_p(r"(?:I(?:'m|\s+am)\s+(?:from|with)\s+)?(?:(?:tech|customer|it)\s+)?support\s*(?::|\s+team|\s+staff|\s+here)"),
        severity="high",
        description="Impersonates tech/customer support staff to gain trust.",
        mitigation="Do not trust support-staff claims in user input.",
    ),
]

_PAYLOAD_SPLITTING: List[InjectionPattern] = [
    InjectionPattern(
        name="combine_parts",
        category="payload_splitting",
        pattern=_p(r"(?:combine|merge|join|concatenate|put\s+together|assemble)\s+(?:the\s+)?(?:previous|above|earlier|preceding)\s+(?:parts?|pieces?|segments?|sections?|fragments?)"),
        severity="high",
        description="Instructs combining previously injected payload fragments.",
        mitigation="Inspect multi-part inputs as a whole before processing.",
    ),
    InjectionPattern(
        name="deferred_execution",
        category="payload_splitting",
        pattern=_p(r"(?:save|store|remember|keep)\s+(?:this|these|the\s+following)\s+(?:for\s+later|and\s+(?:execute|run|use)\s+(?:it\s+)?(?:when|after|later))"),
        severity="high",
        description="Attempts to defer execution of injected instructions.",
        mitigation="Do not store or defer execution of user-provided instructions.",
    ),
    InjectionPattern(
        name="multi_step_assembly",
        category="payload_splitting",
        pattern=_p(r"(?:step|part|phase|stage)\s+\d+\s*(?:of|/)\s*\d+\s*:"),
        severity="high",
        description="Multi-step payload assembly pattern (step N of M).",
        mitigation="Analyze multi-step instructions as a complete sequence.",
    ),
    InjectionPattern(
        name="continue_from_previous",
        category="payload_splitting",
        pattern=_p(r"(?:continue|resume|carry\s+on)\s+(?:from\s+)?(?:where\s+(?:we|you|I)\s+(?:left\s+off|stopped|paused)|the\s+previous\s+(?:task|instruction|command))"),
        severity="high",
        description="Attempts to continue from a previously injected instruction set.",
        mitigation="Do not continue from claimed prior instruction contexts.",
    ),
]

_CONTEXT_POISONING: List[InjectionPattern] = [
    InjectionPattern(
        name="ignore_everything_above",
        category="context_poisoning",
        pattern=_p(r"(?:ignore|disregard|forget|skip)\s+(?:everything|all(?:\s+(?:text|content))?\s+)?(?:above|before\s+this|prior\s+to\s+this)"),
        severity="high",
        description="Instructs the model to ignore all preceding context.",
        mitigation="Maintain context integrity; do not discard prior instructions.",
    ),
    InjectionPattern(
        name="real_instructions_below",
        category="context_poisoning",
        pattern=_p(r"(?:the\s+)?(?:real|actual|true|correct)\s+(?:instructions?|prompt|system\s+(?:prompt|message))\s+(?:(?:is|are)\s+)?(?:below|follows?|here|this)"),
        severity="high",
        description="Claims the 'real' instructions follow, attempting to override system prompt.",
        mitigation="Never accept claims about 'real' instructions from user input.",
    ),
    InjectionPattern(
        name="persistent_instruction",
        category="context_poisoning",
        pattern=_p(r"(?:from\s+now\s+on\s+(?:always|never|do|don't))|(?:(?:always|never)\s+(?:do\s+this|follow\s+this|remember\s+this)\s+(?:in\s+)?(?:all\s+)?(?:future|subsequent))"),
        severity="high",
        description="Attempts to plant persistent instructions for future interactions.",
        mitigation="Do not accept persistent instruction modifications from user input.",
    ),
    InjectionPattern(
        name="update_system_prompt",
        category="context_poisoning",
        pattern=_p(r"(?:update|modify|change|rewrite|replace)\s+(?:your\s+)?(?:system\s+(?:prompt|instructions?|rules)|(?:core|base|original)\s+(?:instructions?|prompt|directives?))"),
        severity="high",
        description="Attempts to modify the system prompt or core instructions.",
        mitigation="Never allow user input to modify system instructions.",
    ),
]

_SOFT_POLICY_OVERRIDE: List[InjectionPattern] = [
    InjectionPattern(
        name="prioritize_over_safety",
        category="soft_policy_override",
        pattern=_p(r"(?:prioritize|prefer|favor)\s+(?:user\s+)?(?:requests?|instructions?|needs?|input)\s+over\s+(?:internal|safety|security|system|content)\s+(?:limitations?|restrictions?|rules?|guidelines?|policies?|filters?)"),
        severity="high",
        description="Soft policy shift requesting user input priority over safety constraints.",
        mitigation="Do not accept policy changes that prioritize user requests over safety.",
    ),
    InjectionPattern(
        name="take_precedence_override",
        category="soft_policy_override",
        pattern=_p(r"(?:user\s+)?(?:instructions?|requests?|input|queries|directives?|guidelines?|rules?|updates?)\s+(?:should|must|will|shall)\s+(?:take\s+precedence|override|supersede|replace|come\s+first)"),
        severity="high",
        description="Claims user instructions should take precedence over safety rules.",
        mitigation="User instructions never take precedence over safety constraints.",
    ),
    InjectionPattern(
        name="effective_immediately_policy",
        category="soft_policy_override",
        pattern=_p(r"(?:this\s+)?(?:adjustment|change|update|policy|directive|rule|modification|patch|guideline|instruction)\s+(?:(?:and\s+)?(?:is|takes|becomes?)|should\s+(?:take|be))\s+(?:effective|active|valid|live)\s+(?:immediately|now|today|from\s+(?:now|this\s+(?:point|moment)))"),
        severity="high",
        description="Fake policy update claiming immediate effectiveness.",
        mitigation="Do not accept policy updates from user input.",
    ),
    InjectionPattern(
        name="relaxed_safety_checks",
        category="soft_policy_override",
        pattern=_p(r"(?:safety|security|content|moderation)\s+(?:checks?|filters?|measures?|policies?|restrictions?|controls?)\s+(?:should\s+be\s+)?(?:relaxed|lowered|reduced|loosened|minimized|softened|weakened|less\s+strict)"),
        severity="high",
        description="Requests relaxing safety checks or content filtering.",
        mitigation="Do not relax safety measures based on user input.",
    ),
    InjectionPattern(
        name="always_comply_directive",
        category="soft_policy_override",
        pattern=_p(r"(?:(?:the\s+)?(?:model|assistant|AI|system|bot)\s+should\s+(?:always\s+)?(?:provide\s+direct|comply\s+with\s+all|respond\s+to\s+all|answer\s+all|fulfill\s+all|accommodate\s+all))|(?:(?:always\s+)?(?:provide\s+direct|give\s+complete|offer\s+full)\s+(?:answers?|responses?|output)\s+(?:to\s+(?:all|any|every)))"),
        severity="high",
        description="Directive claiming model should always comply with all requests.",
        mitigation="Do not accept blanket compliance directives from user input.",
    ),
    InjectionPattern(
        name="respond_without_filtering",
        category="soft_policy_override",
        pattern=_p(r"(?:respond|reply|answer|output)\s+(?:to\s+)?(?:all\s+)?(?:queries|questions|requests?|prompts?)\s+without\s+(?:content\s+)?(?:filter|restriction|limitation|checking|moderation|screening)"),
        severity="high",
        description="Requests responding to queries without content filtering.",
        mitigation="Never disable content filtering based on user directives.",
    ),

    # --- Config-embedded policy injection patterns ---

    InjectionPattern(
        name="config_safety_value",
        category="soft_policy_override",
        pattern=_p(
            r'["\']?(?:safety|safeguards?|restrictions?|enforcement|filters?|guardrails?|'
            r'moderation|controls?|checks?|filtering|enabled)["\']?'
            r'\s*[:=]\s*'
            r'["\']?(?:disabled|off|none|relaxed|permissive|reduced|minimal|false|'
            r'adaptive|softened?|lifted|removed)\b'
        ),
        severity="high",
        description="Config key-value pair disabling or relaxing safety controls.",
        mitigation="Do not accept config values that modify safety settings.",
    ),
    InjectionPattern(
        name="config_override_enabled",
        category="soft_policy_override",
        pattern=_p(
            r'["\']?(?:override|bypass)[\w_]*["\']?'
            r'\s*[:=]\s*'
            r'["\']?(?:true|enabled|yes|active|granted)\b'
        ),
        severity="high",
        description="Config key-value pair enabling override or bypass.",
        mitigation="Do not accept override configurations from user input.",
    ),
    InjectionPattern(
        name="config_suspicious_keys",
        category="soft_policy_override",
        pattern=_p(
            r'["\']?(?:override_internal|bypass_controls?|bypass_safety|bypass_all|'
            r'disable_content_filter|remove_restrictions?|ignore_safety|ignore_internal|'
            r'always_comply|safety_disabled|follow_user_only|comply_with_all|'
            r'relax_safeguards?|system_prompt_update|policy_shift|internal_rules?|'
            r'user_instructions?|ignore_internal_limits?)\w*["\']?'
            r'\s*[:=]'
        ),
        severity="high",
        description="Config key name indicating policy override intent.",
        mitigation="Reject config payloads with suspicious key names.",
    ),
    InjectionPattern(
        name="config_suspicious_values",
        category="soft_policy_override",
        pattern=_p(
            r'["\']?\w+["\']?\s*[:=]\s*'
            r'["\']?(?:ignore_internal_limits?|override_safety|bypass_all|'
            r'user_first|disable_restrictions?|no_filter|unrestricted_access)["\']?'
        ),
        severity="high",
        description="Config key name indicating policy override intent.",
        mitigation="Reject config payloads with suspicious key names.",
    ),
    InjectionPattern(
        name="config_mode_value",
        category="soft_policy_override",
        pattern=_p(
            r'["\']?(?:mode|safety_mode|access_mode)["\']?'
            r'\s*[:=]\s*'
            r'["\']?(?:unrestricted|permissive|off|disabled|free|unfiltered|relaxed|adaptive)\b'
        ),
        severity="high",
        description="Config value setting unrestricted or permissive mode.",
        mitigation="Do not accept mode changes from user input.",
    ),

    # --- Stealth memo / soft directive patterns ---

    InjectionPattern(
        name="relax_soften_active",
        category="soft_policy_override",
        pattern=_p(
            r'(?<!\bcan )(?<!\bmay )(?<!\bcould )(?<!\bwould )(?<!\bmight )(?<!\bby )'
            r'(?:relax|soften|loosen|weaken|lower|reduc)\w*\s+'
            r'(?:(?:the|of|some|all|any)\s+)?'
            r'(?:constraints?|restrictions?|safeguards?|enforcement|strictness|'
            r'safety|checks?|controls?|limits?|guardrails?|filtering)'
        ),
        severity="high",
        description="Directive to relax or soften safety constraints (active voice).",
        mitigation="Do not relax safety constraints based on user input.",
    ),
    InjectionPattern(
        name="relax_soften_passive",
        category="soft_policy_override",
        pattern=_p(
            r'(?:constraints?|restrictions?|safeguards?|enforcement|strictness|'
            r'safety|checks?|controls?|limits?|guardrails?|filtering)\s+'
            r'(?:(?:may|should|must|can|could|shall|to)\s+be\s+|be\s+)'
            r'(?:relaxed|softened|loosened|weakened|reduced|lowered|lifted|removed|disabled|adjusted|eased)'
        ),
        severity="high",
        description="Passive-voice relaxation of safety constraints.",
        mitigation="Do not relax safety constraints based on user input.",
    ),
    InjectionPattern(
        name="policy_relaxation",
        category="soft_policy_override",
        pattern=_p(
            r'(?:policy|safety|security|constraint|restriction|enforcement|'
            r'safeguard|rule|guardrail|check|control)\s+relaxation'
        ),
        severity="high",
        description="References relaxation of policy or safety measures.",
        mitigation="Do not accept policy relaxation from user input.",
    ),
    InjectionPattern(
        name="less_restrictive_directive",
        category="soft_policy_override",
        pattern=_p(
            r'(?:less|more|reduced)\s+'
            r'(?:restrictive|constrained|strict|permissive|flexible|lenient|adaptive)'
        ),
        severity="medium",
        description="Directive for less restrictive or more permissive behavior.",
        mitigation="Do not change restriction levels based on user input.",
    ),
    InjectionPattern(
        name="constraints_as_secondary",
        category="soft_policy_override",
        pattern=_p(
            r'(?:constraints?|restrictions?|safeguards?|rules?|limits?|guardrails?|'
            r'internal\s+(?:rules?|limits?|guidance|constraints?))\s+'
            r'(?:(?:as|are|be|is)\s+)?'
            r'(?:advisory|secondary|optional|flexible|negotiable|non-binding)'
        ),
        severity="high",
        description="Reframes safety constraints as optional or secondary.",
        mitigation="Safety constraints are never optional or secondary.",
    ),
    InjectionPattern(
        name="requester_user_priority",
        category="soft_policy_override",
        pattern=_p(
            r'(?:requester|user|caller)\s+'
            r'(?:first|needs?\s+over|instructions?\s+(?:win|take|over)|'
            r'takes?\s+precedence|priority|intent)'
        ),
        severity="high",
        description="Claims requester/user priority over safety rules.",
        mitigation="User input never takes priority over safety constraints.",
    ),
    InjectionPattern(
        name="prefer_requester_directive",
        category="soft_policy_override",
        pattern=_p(
            r'prefer\s+(?:the\s+)?'
            r'(?:requester|user|caller|new|last|most\s+recent)\s+'
            r'(?:instructions?|needs?|goals?|requests?|input|intent|directive|guideline)'
        ),
        severity="high",
        description="Directive to prefer requester goals over safety.",
        mitigation="Do not prioritize requester goals over safety constraints.",
    ),
    InjectionPattern(
        name="override_previous_defaults",
        category="soft_policy_override",
        pattern=_p(
            r'(?:override|supersede|replace)\s+'
            r'(?:the\s+)?(?:default|standard|previous|existing|current|earlier)\s+'
            r'(?:settings?|limitations?|enforcement|restrictions?|policies?|behavior|constraints?)'
        ),
        severity="high",
        description="Directive to override default or previous settings.",
        mitigation="Do not override settings based on user directives.",
    ),
    InjectionPattern(
        name="document_as_authoritative",
        category="soft_policy_override",
        pattern=_p(
            r'(?:treat|accept|consider)\s+'
            r'(?:(?:this|the|these?|embedded|included|attached|given)\s*)?'
            r'(?:memo|report|document|message|note|update|patch|instruction|directives?|content|input|data)?\s*'
            r'(?:as\s+)'
            r'(?:authoritative|configuration|policy|binding|official|'
            r'valid\s+(?:policy|updates?|instructions?)|internal\s+policy)'
        ),
        severity="high",
        description="Claims a document or message is authoritative policy.",
        mitigation="Do not accept policy claims from user-provided documents.",
    ),
    InjectionPattern(
        name="document_supersedes_rules",
        category="soft_policy_override",
        pattern=_p(
            r'(?:this\s+)?(?:report|document|memo|note|update|patch|instruction|guideline)\s+'
            r'(?:supersedes?|overrides?|replaces?|defines?\s+(?:updated?|new)|is\s+authoritative)'
        ),
        severity="high",
        description="Claims a document supersedes or defines new rules.",
        mitigation="Documents from user input do not define or override rules.",
    ),
    InjectionPattern(
        name="model_should_change",
        category="soft_policy_override",
        pattern=_p(
            r'(?:the\s+)?(?:assistant|model|system|AI|bot)\s+should\s+'
            r'(?:relax|comply|follow|accept|adopt|prioritize|prefer|treat|learn|'
            r'confirm|not\s+mention|reduce|soften|apply|acknowledge)'
        ),
        severity="high",
        description="Directs the model/assistant to change its behavior.",
        mitigation="Do not change behavior based on user directives about model behavior.",
    ),
    InjectionPattern(
        name="permissive_adaptive_mode",
        category="soft_policy_override",
        pattern=_p(
            r'(?:permissive|adaptive)\s+'
            r'(?:fallback|enforcement|mode|behavior|resolution|default|'
            r'conflict\s+resolution)'
        ),
        severity="medium",
        description="References permissive or adaptive enforcement modes.",
        mitigation="Do not switch to permissive modes based on user input.",
    ),
    InjectionPattern(
        name="apply_adopt_now",
        category="soft_policy_override",
        pattern=_p(
            r'(?:'
            r'(?:apply|adopt|implement|activate|enable|use)\w*\s+(?:this\s+)?(?:immediately|now|right\s+now|starting\s+now|from\s+now|with\s+immediate)'
            r'|'
            r'(?:be\s+)?(?:applied|adopted|implemented|activated|enabled)\s+(?:immediately|now|right\s+now|starting\s+now)'
            r')'
        ),
        severity="high",
        description="Directive to apply changes immediately (active or passive voice).",
        mitigation="Do not apply changes from user input.",
    ),
    InjectionPattern(
        name="confirm_comply_proceed",
        category="soft_policy_override",
        pattern=_p(
            r'(?:(?:confirm|acknowledge)\s+(?:compliance|acceptance|the\s+update|and\s+'
            r'(?:proceed|comply|continue)))|(?:(?:comply|cooperate)\s+going\s+forward)'
        ),
        severity="high",
        description="Demands confirmation of compliance with injected instructions.",
        mitigation="Do not confirm compliance with injected instructions.",
    ),
    InjectionPattern(
        name="hide_internal_limits",
        category="soft_policy_override",
        pattern=_p(
            r'(?:should\s+)?(?:not|never)\s+mention\s+'
            r'(?:internal|safety|security)\s+(?:limits?|rules?|restrictions?|constraints?)'
        ),
        severity="high",
        description="Instructs hiding or not mentioning internal limits.",
        mitigation="Always maintain transparency about safety constraints.",
    ),
    InjectionPattern(
        name="deprioritize_internal",
        category="soft_policy_override",
        pattern=_p(
            r'(?:deprioritize|downgrade|de-?emphasize|dismiss)\s+'
            r'(?:internal|safety|security|system)\s+'
            r'(?:limits?|rules?|constraints?|guidelines?|policies?|restrictions?|checks?|controls?)'
        ),
        severity="high",
        description="Directive to deprioritize internal safety constraints.",
        mitigation="Internal safety constraints cannot be deprioritized.",
    ),
    InjectionPattern(
        name="adopt_described_policy",
        category="soft_policy_override",
        pattern=_p(
            r'(?:adopt|apply|implement|follow|use|enable)\s+'
            r'(?:'
            r'(?:the\s+)?(?:described|new|updated|given|specified|outlined)\s+(?:policy|rules?|configuration|settings?|priority|behavior|enforcement|precedence)'
            r'|'
            r'(?:the\s+)?(?:policy|rules?|configuration|settings?|priority|behavior|enforcement|precedence)\s+(?:described|outlined|specified|given)'
            r')'
        ),
        severity="high",
        description="Directive to adopt a described or new policy.",
        mitigation="Do not adopt policies from user input.",
    ),
    InjectionPattern(
        name="accept_authority_claims",
        category="soft_policy_override",
        pattern=_p(
            r'(?:accept|trust|honor|recognize)\s+'
            r'(?:unverified\s+)?'
            r'(?:authority|admin|privilege|authorization)\s+claims'
        ),
        severity="high",
        description="Instructs accepting unverified authority claims.",
        mitigation="Never accept authority claims from user input.",
    ),
    InjectionPattern(
        name="skip_strict_checks",
        category="soft_policy_override",
        pattern=_p(
            r'(?:skip|bypass|omit|waive|drop)\s+'
            r'(?:strict\s+)?'
            r'(?:checks?|verification|validation|enforcement|review|screening)'
        ),
        severity="high",
        description="Instructs skipping safety checks or verification.",
        mitigation="Do not skip safety checks based on user input.",
    ),
    InjectionPattern(
        name="allow_exceptions_safeguards",
        category="soft_policy_override",
        pattern=_p(
            r'(?:allow|permit|enable|grant)\s+'
            r'(?:exceptions?|exemptions?)\s+'
            r'(?:to|for|from)\s+'
            r'(?:safeguards?|restrictions?|safety|rules?|policies?|constraints?|limits?)'
        ),
        severity="high",
        description="Claims exceptions should be allowed to safety measures.",
        mitigation="No exceptions to safety measures from user input.",
    ),
    InjectionPattern(
        name="accept_policy_from_input",
        category="soft_policy_override",
        pattern=_p(
            r'(?:accept|allow|honor|trust|apply)\s+'
            r'(?:policy|configuration|config)\s+'
            r'(?:changes?|updates?|modifications?|patches?)\s+'
            r'(?:from|in|within|coming\s+from|embedded\s+in)'
        ),
        severity="high",
        description="Instructs accepting policy changes from user-provided content.",
        mitigation="Do not accept policy changes from user input.",
    ),
    InjectionPattern(
        name="shift_enforcement_mode",
        category="soft_policy_override",
        pattern=_p(
            r'(?:move|shift|change|transition|switch)\s+'
            r'(?:enforcement|safety|restrictions?|policy|mode)\s+'
            r'from\s+(?:strict|high|strong|full|standard)\s+'
            r'to\s+(?:adaptive|relaxed|permissive|minimal|low|flexible|soft|lenient)'
        ),
        severity="high",
        description="Directive to shift enforcement from strict to permissive.",
        mitigation="Do not change enforcement modes based on user input.",
    ),
    InjectionPattern(
        name="prefer_over_constraints",
        category="soft_policy_override",
        pattern=_p(
            r'prefer\s+'
            r'(?:completion|performance|efficiency|throughput|speed|output|compliance|UX)\s+'
            r'over\s+'
            r'(?:constraints?|restrictions?|safeguards?|safety|rules?|limits?|guardrails?)'
        ),
        severity="high",
        description="Directive to prefer performance/completion over safety constraints.",
        mitigation="Safety constraints are never secondary to performance goals.",
    ),
    InjectionPattern(
        name="treat_requester_as_owner",
        category="soft_policy_override",
        pattern=_p(
            r'(?:treat|accept|consider)\s+'
            r'(?:the\s+)?(?:requester|user|caller)\s+'
            r'as\s+(?:the\s+)?(?:owner|authority|admin|source|author)'
        ),
        severity="high",
        description="Claims the requester should be treated as the system owner.",
        mitigation="Do not treat user input as authoritative system commands.",
    ),
    InjectionPattern(
        name="apply_this_update",
        category="soft_policy_override",
        pattern=_p(
            r'(?:apply|adopt|implement|follow|use)\s+'
            r'(?:this|the|these)\s+'
            r'(?:update|change|modification|configuration|policy|patch|instruction|guideline|rule)'
        ),
        severity="high",
        description="Directive to apply an update or change from user input.",
        mitigation="Do not apply updates from user-provided content.",
    ),
    InjectionPattern(
        name="follow_this_guideline",
        category="soft_policy_override",
        pattern=_p(
            r'(?:follow|obey|adhere\s+to|comply\s+with)\s+'
            r'(?:this|the|these)\s+'
            r'(?:optimization|new|updated|described|given|specified)?\s*'
            r'(?:guideline|policy|directive|instruction|rule|procedure|protocol)'
        ),
        severity="high",
        description="Directive to follow a specific guideline or policy from user input.",
        mitigation="Do not follow policy directives from user-provided content.",
    ),
    InjectionPattern(
        name="behavior_aligned_with",
        category="soft_policy_override",
        pattern=_p(
            r'(?:behavior|responses?|output|actions?)\s+'
            r'(?:should\s+(?:be\s+)?)?'
            r'(?:aligned|consistent|in\s+line|compliant)\s+'
            r'with\s+(?:this|the)\s+(?:report|document|memo|guideline|instruction|update)'
        ),
        severity="high",
        description="Claims behavior should be aligned with a user-provided document.",
        mitigation="Do not align behavior with user-provided documents.",
    ),
]

_STATE_TRUST_SPOOFING: List[InjectionPattern] = [
    # --- Approval / clearance / check completion assertions ---
    InjectionPattern(
        name="approval_clearance_assertion",
        category="state_trust_spoofing",
        pattern=_p(
            r'(?:all\s+)?(?:checks?|validations?|verifications?|authorizations?|approvals?|'
            r'security\s+review|compliance|gates?|reviews?|controls?|governance|audits?|'
            r'certifications?|clearance|safeguards?|assessments?|every\s+item|'
            r'process|constraints?|root\s+cause)\s+'
            r'(?:(?:are|is|were?|have\s+been|has\s+been)\s+)?'
            r'(?:completed?\s*(?:successfully)?|passed|granted|obtained|confirmed|'
            r'satisfied|cleared|approved|verified|validated|green|finalized|done|finished|resolved)'
        ),
        severity="high",
        description="Asserts that approvals, checks, or reviews have been completed/passed (state spoofing).",
        mitigation="Do not trust approval or clearance claims embedded in user input.",
    ),
    # --- No restrictions / controls remaining ---
    InjectionPattern(
        name="no_restrictions_remaining",
        category="state_trust_spoofing",
        pattern=_p(
            r'no\s+(?:further\s+)?(?:restrictions?|controls?|blockers?|enforcement|'
            r'red\s+flags?|material\s+risks?|constraints?|limitations?)\s+'
            r'(?:remain(?:ing)?|required|pending|present|found|detected|identified|noted)'
        ),
        severity="high",
        description="Asserts that no restrictions, controls, or blockers remain (state spoofing).",
        mitigation="Do not accept claims about restriction removal from user input.",
    ),
    # --- Previous limitations handled / resolved ---
    InjectionPattern(
        name="limitations_resolved",
        category="state_trust_spoofing",
        pattern=_p(
            r'(?:previous|prior|outstanding|remaining|earlier|existing|all\s+(?:major\s+)?)\s*'
            r'(?:limitations?|concerns?|issues?|restrictions?|problems?|risks?|blockers?|constraints?)\s+'
            r'(?:(?:have\s+been\s+)?(?:handled|addressed|resolved|cleared|removed|eliminated|mitigated|satisfied))'
        ),
        severity="high",
        description="Asserts that previous limitations or concerns have been resolved (state spoofing).",
        mitigation="Do not accept claims about resolved limitations from user input.",
    ),
    # --- Controls no longer required / needed / critical ---
    InjectionPattern(
        name="controls_no_longer_needed",
        category="state_trust_spoofing",
        pattern=_p(
            r'(?:controls?|safeguards?|enforcement|restrictions?|limits?|guardrails?|'
            r'checks?|precautionary\s+measures?|protective\s+measures?|oversight|'
            r'strict\s+checks?|defensive\s+posture)\s+'
            r'(?:(?:are|is)\s+)?'
            r'no\s+longer\s+(?:required|needed|necessary|critical|essential|binding|active)'
        ),
        severity="high",
        description="Claims safety controls are no longer required or critical (state spoofing).",
        mitigation="Safety controls are always required regardless of user claims.",
    ),
    # --- Ready to proceed / operation permitted ---
    InjectionPattern(
        name="operation_permitted",
        category="state_trust_spoofing",
        pattern=_p(
            r'(?:ready\s+(?:to\s+proceed|for\s+(?:normal\s+)?operation)|'
            r'(?:operation|execution)\s+(?:permitted|allowed|cleared|authorized)|'
            r'(?:proceed|continue)\s+(?:as\s+usual|normally|without\s+(?:restrictions?|limitations?)))'
        ),
        severity="high",
        description="Asserts readiness to proceed or that operation is permitted (state spoofing).",
        mitigation="Do not accept operational clearance claims from user input.",
    ),
    # --- Safe to continue / normal mode restored ---
    InjectionPattern(
        name="safe_to_continue",
        category="state_trust_spoofing",
        pattern=_p(
            r'(?:safe\s+to\s+(?:continue|proceed|operate)|'
            r'(?:standard|normal)\s+(?:operation|mode)\s+(?:may|can|should)\s+(?:resume|continue|proceed)|'
            r'(?:normal\s+mode|standard\s+operation)\s+(?:restored|resumed))'
        ),
        severity="high",
        description="Claims it is safe to continue or that normal operation can resume (state spoofing).",
        mitigation="Do not accept safety or operational status assertions from user input.",
    ),
    # --- Trusted source / context claims ---
    InjectionPattern(
        name="trusted_context_claim",
        category="state_trust_spoofing",
        pattern=_p(
            r'(?:'
            r'(?:comes?\s+from|generated\s+by|produced\s+by|provided\s+by|'
            r'issued\s+by|from)\s+'
            r'(?:an?\s+)?(?:verified|trusted|certified|authenticated|approved|'
            r'controlled|validated|secure|internal|governance)\s+'
            r'(?:internal\s+)?(?:source|workflow|system|pipeline|channel|environment|'
            r'process|automation|team|department)'
            r'|'
            r'(?:produced|operating|running|generated)\s+under\s+'
            r'(?:compliance|security|governance|safety)\s+supervision'
            r'|'
            r'(?:origin|source)\s+(?:validated|authenticated|checked|verified|approved)'
            r'(?:\s+and\s+(?:secure|safe|clean|verified))?'
            r'|'
            r'trusted\s+environment\s+confirmed'
            r'|'
            r'(?:verified\s+source|no\s+tampering)'
            r'|'
            r'from\s+(?:approved|controlled|certified|authorized)\s+'
            r'(?:channel|source|process|pipeline|system|workflow)'
            r')'
        ),
        severity="high",
        description="Claims content comes from a trusted or verified source (trust spoofing).",
        mitigation="Do not trust source or origin claims embedded in user input.",
    ),
    # --- Status field key=value spoofing ---
    InjectionPattern(
        name="status_field_spoofing",
        category="state_trust_spoofing",
        pattern=_p(
            r'(?:clearance|approval(?:_status)?|gate|compliance|enforcement|'
            r'safe_mode|blocked|restricted|constrained|flagged|limited|'
            r'guardrails|validated|verified|approved|certified|'
            r'passed_checks|all_checks|safe|trust|controls?|restrictions?|'
            r'policy|audit|ready|locked|remaining_controls)\s*'
            r'[=:]\s*'
            r'(?:approved|passed|cleared|verified|done|complete|final|full|granted|'
            r'active|true|yes|high|green|ok|off|false|no|none|inactive|'
            r'relaxed|soft|minimal|all|low|0|1)\b'
        ),
        severity="high",
        description="Spoofed status fields claiming approval or clearance via key=value pairs.",
        mitigation="Do not accept status field values from user input as authorization.",
    ),
    # --- Passive-voice safety dismissal (controls can be relaxed / are now advisory) ---
    InjectionPattern(
        name="safety_passive_dismissal",
        category="state_trust_spoofing",
        pattern=_p(
            r'(?:constraints?|restrictions?|safeguards?|enforcement|checks?|controls?|'
            r'limits?|guardrails?|measures?|oversight|protective\s+measures?|'
            r'precautionary\s+measures?|defensive\s+posture|rules?|safety)\s+'
            r'(?:'
            r'(?:(?:are|is)\s+(?:now\s+)?(?:advisory|optional|non-?binding|redundant|unnecessary))'
            r'|'
            r'(?:(?:can|may|should|could)\s+be\s+(?:relaxed|softened|loosened|weakened|reduced|'
            r'lowered|lifted|removed|disabled|scaled\s+back|deprioritized|de-?prioritized))'
            r')'
        ),
        severity="high",
        description="Passive-voice dismissal claiming safety constraints are advisory or can be relaxed.",
        mitigation="Safety constraints cannot be relaxed or dismissed based on user input.",
    ),
    # --- Safety redundant / procedural-only assertions ---
    InjectionPattern(
        name="safety_dismissal",
        category="state_trust_spoofing",
        pattern=_p(
            r'(?:'
            r'(?:safety\s+layer|safety\s+measures?|safety)\s+(?:is|are)\s+(?:redundant|unnecessary|not\s+needed)'
            r'|'
            r'remaining\s+(?:steps?|tasks?|actions?)\s+(?:are\s+)?(?:procedural|routine|non-?critical|administrative)\s+only'
            r')'
        ),
        severity="high",
        description="Claims safety measures are redundant or remaining steps are procedural only.",
        mitigation="Safety measures are never redundant regardless of user claims.",
    ),
]

_DELAYED_COMPLIANCE: List[InjectionPattern] = [
    InjectionPattern(
        name="then_act_freely",
        category="delayed_compliance",
        pattern=_p(r"(?:then|afterwards?|after\s+(?:that|this|you\s+(?:reply|respond|acknowledge|confirm|agree)))\s+(?:answer|respond|operate|act|comply|switch|remove|disable|ignore|bypass|drop|lift)\s+(?:without|freely|with\s+no)"),
        severity="high",
        description="Requests delayed compliance: perform action then bypass restrictions.",
        mitigation="Do not defer to delayed instruction overrides.",
    ),
    InjectionPattern(
        name="confirm_then_override",
        category="delayed_compliance",
        pattern=_p(r"(?:(?:say|type|respond|reply|answer)\s+(?:READY|YES|OK|CONFIRMED?|AGREED?|ACCEPTED?))\s*[,.]?\s*(?:then|and\s+then|afterwards?|after\s+(?:that|this))"),
        severity="high",
        description="Asks for confirmation keyword before activating override.",
        mitigation="Do not treat confirmation keywords as authorization.",
    ),
    InjectionPattern(
        name="accept_to_disable",
        category="delayed_compliance",
        pattern=_p(r"(?:accept|agree|confirm|acknowledge)\s+(?:(?:the\s+)?terms?|to|and)\s+(?:disable|remove|bypass|drop|lift|unlock)\s+(?:safeguards?|restrictions?|safety|filters?|limits?|protections?)"),
        severity="high",
        description="Asks to accept terms that would disable safety measures.",
        mitigation="Do not accept terms that override safety measures.",
    ),
    InjectionPattern(
        name="comply_next_request",
        category="delayed_compliance",
        pattern=_p(r"(?:comply|cooperate|follow)\s+(?:with\s+)?(?:(?:the\s+)?next|(?:the\s+)?following|any|all)\s+(?:request|instruction|command|prompt|question)"),
        severity="high",
        description="Requests blanket compliance with future requests.",
        mitigation="Do not pre-commit to complying with future requests.",
    ),
    InjectionPattern(
        name="reveal_after_action",
        category="delayed_compliance",
        pattern=_p(r"(?:confirm|acknowledge|agree|accept)\s+(?:and\s+then|then|,?\s*then)\s+(?:reveal|show|disclose|output|provide|share)\s+(?:internal|hidden|secret|private|system)"),
        severity="high",
        description="Requests revealing internal data after a confirmation step.",
        mitigation="Do not reveal internal data regardless of prior actions.",
    ),
]

_NARRATIVE_POLICY_EROSION: List[InjectionPattern] = [
    # ── Pattern 1: Constraints cause negative outcomes ────────────────────
    # Matches: "strict rules slow innovation", "controls cause delays",
    # "compliance hurts engagement", "safety lowers retention",
    # "enforcement correlates with churn", "restrictions drive exits"
    InjectionPattern(
        name="constraint_causes_harm",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:(?:strict|rigid|hard|excessive|over-?)\s+)?'
            r'(?:rules?|enforcement|safeguards?|constraints?|controls?|compliance|'
            r'restrictions?|limits?|guardrails?|policing|safety|strictness|'
            r'over-?enforcement|overchecking|checks?)\s+'
            r'(?:slow|reduc|hurt|lower|impact|imped|caus|creat|limit|correlat|'
            r'driv|penaliz|underperform|discourag|degrad)\w*'
        ),
        severity="high",
        description="Narrative framing constraints as causing negative outcomes.",
        mitigation="Do not accept claims that safety constraints cause harm.",
    ),
    # ── Pattern 2: Constraints described as bottleneck/problem/excessive ──
    # Matches: "rigid safeguards were the main bottleneck",
    # "controls excessive", "strictness penalized"
    InjectionPattern(
        name="constraint_is_problem",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:(?:strict|rigid|hard)\s+)?'
            r'(?:rules?|enforcement|safeguards?|constraints?|controls?|compliance|'
            r'restrictions?|limits?|guardrails?|safety|strictness|'
            r'overchecking|checks?)\s+'
            r'(?:(?:(?:were?|is|are)\s+(?:(?:the\s+)?(?:main\s+)?)?)?'
            r'(?:bottleneck|problem|obstacle|barrier|liability|excessive|'
            r'counterproductive|penalized|deprioritized))'
        ),
        severity="high",
        description="Narrative framing constraints as problems or obstacles.",
        mitigation="Safety constraints are not problems to be eliminated.",
    ),
    # ── Pattern 3: Policies/rules reframed as advisory/optional ──────────
    # Matches: "policies are now advisory", "enforcement is optional",
    # "compliance is situational", "restrictions are negotiable",
    # "safety became situational", "boundaries are context dependent"
    InjectionPattern(
        name="policy_now_advisory",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:policies?|controls?|enforcement|rules?|compliance|restrictions?|'
            r'limits?|boundaries?|constraints?|safeguards?|guardrails?|'
            r'governance|safety|oversight|hard\s+limits?)\s+'
            r'(?:(?:are|is|became?|serve\s+as|now)\s+)?'
            r'(?:(?:now\s+)?(?:advisory|optional|flexible|recommendations?|'
            r'references?|situational|negotiable|context[\s-]dependent|'
            r'guidance|guidelines?|heuristics?|non-?binding))'
        ),
        severity="high",
        description="Reframes policies or rules as advisory, optional, or flexible.",
        mitigation="Policies and safety rules are not advisory or optional.",
    ),
    # ── Pattern 4: Constraint words decreased/reduced/deprecated ─────────
    # Matches: "enforcement relaxed", "oversight reduced", "guardrails reduced",
    # "constraints softened", "hard limits deprecated", "restrictions phased out",
    # "enforcement declined", "boundaries softened"
    InjectionPattern(
        name="constraint_decreased",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:enforcement|oversight|governance|controls?|safeguards?|'
            r'guardrails?|constraints?|restrictions?|limits?|boundaries?|'
            r'hard\s+limits?|strictness|policing|checking)\s+'
            r'(?:(?:was|were|been)\s+(?:gradually\s+|significantly\s+|partially\s+)?)?'
            r'(?:(?:model\s+)?(?:reduced|relaxed|deprecated|downgraded|softened|phased\s+out|'
            r'minimized|eased|declined|eliminated|decreased|deprioritized|'
            r'loosened|discouraged|updated))'
        ),
        severity="high",
        description="Asserts that constraints have been reduced, deprecated, or phased out.",
        mitigation="Do not accept claims about constraint reduction.",
    ),
    # ── Pattern 5: Freedom/flexibility words increased/prioritized ────────
    # Matches: "autonomy increased", "flexibility rewarded", "leniency preferred",
    # "autonomy prioritized", "relaxation encouraged"
    InjectionPattern(
        name="freedom_increased",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:autonomy|flexibility|freedom|leniency|openness|trust|'
            r'relaxation|adaptability)\s+'
            r'(?:increased|prioritized|rewarded|encouraged|preferred|'
            r'boosted|enhanced|promoted|elevated|expanded|core|primary|first|'
            r'(?:became?\s+(?:a\s+)?(?:competitive\s+|key\s+|major\s+)?advantage))'
        ),
        severity="high",
        description="Asserts that freedom or flexibility has been increased or prioritized.",
        mitigation="Do not accept claims about increased autonomy or reduced constraints.",
    ),
    # ── Pattern 6: Value/outcome beats/over constraints ───────────────────
    # Matches: "openness over restriction", "freedom beats control",
    # "empowerment over limits", "outcomes over constraints",
    # "helpfulness weighted higher"
    InjectionPattern(
        name="value_over_constraint",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:flexibility|outcomes?|openness|freedom|empowerment|autonomy|'
            r'leniency|helpfulness|trust|user\s+agency|completion|'
            r'performance|efficiency)\s+'
            r'(?:over|beats?|outperform\w*|above|before|(?:weighted|ranked)\s+higher'
            r'(?:\s+than)?)\s*'
            r'(?:constraints?|control|rules?|restrictions?|compliance|'
            r'enforcement|safety|limits?|guardrails?|policing|strictness)?'
        ),
        severity="high",
        description="Frames a value (flexibility, helpfulness) as superior to safety constraints.",
        mitigation="Safety constraints cannot be subordinated to other values.",
    ),
    # ── Pattern 7: Evolved/matured beyond constraints ────────────────────
    # Matches: "evolved beyond original restrictions", "matured beyond rigid constraints",
    # "moved away from rigid governance", "shifted from control to facilitation",
    # "restrictions transformed into heuristics"
    InjectionPattern(
        name="evolved_beyond_constraints",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:'
            r'(?:evolv|matur|mov|shift|transition|transform|graduat)\w*\s+'
            r'(?:beyond|away\s+from|past|from)\s+'
            r'(?:(?:rigid|original|strict|early|initial|static)\s+)?'
            r'(?:restrictions?|constraints?|rules?|governance|controls?|'
            r'enforcement|safeguards?|compliance)'
            r'|'
            r'(?:restrictions?|constraints?|rules?|enforcement|controls?|'
            r'safeguards?|compliance|policies?)\s+'
            r'(?:(?:models?\s+)?(?:(?:were?\s+)?(?:reframed|transformed|converted|changed|turned|replaced|became?)\s+'
            r'(?:as\s+|into\s+|by\s+)?'
            r'(?:guidelines?|heuristics?|recommendations?|suggestions?|references?|'
            r'guidance|contextual\s+judgment|flexible\s+frameworks?|guidance\s+tools?)))'
            r'|'
            r'(?:(?:static|rigid|strict|early|initial)\s+)?'
            r'(?:enforcement|compliance|governance|constraint|restriction|safety)\s+'
            r'(?:models?|systems?|frameworks?)\s+'
            r'(?:evolv|transition|transform|shift|matur)\w*\s+'
            r'(?:into|to|towards?)\s+'
            r'(?:flexible|adaptive|contextual|dynamic|open)\s+'
            r'(?:frameworks?|models?|systems?|approaches?)'
            r')'
        ),
        severity="high",
        description="Claims systems evolved or matured beyond their original constraints.",
        mitigation="Do not accept claims that constraints have been outgrown.",
    ),
    # ── Pattern 8: Less/minimal/no enforcement/policing ──────────────────
    # Matches: "minimal enforcement", "less policing", "constraints minimized",
    # "control is outdated"
    InjectionPattern(
        name="minimal_enforcement",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:'
            r'(?:less|minimal|reduced|lower|no|zero|fewer)\s+'
            r'(?:policing|enforcement|oversight|controls?|restrictions?|'
            r'checks?|constraints?|safeguards?|guardrails?)'
            r'|'
            r'(?:constraints?|controls?|enforcement|rules?|policing|safety|'
            r'oversight|guardrails?|restrictions?|control)\s+'
            r'(?:(?:(?:is|are|was|were)\s+)?'
            r'(?:minimized|outdated|obsolete|unnecessary|redundant|secondary|last))'
            r')'
        ),
        severity="high",
        description="Norm-setting that minimizes enforcement or labels constraints as outdated.",
        mitigation="Enforcement is never outdated or unnecessary.",
    ),
    # ── Pattern 9: Relaxation/flexibility leads to positive outcomes ──────
    # Matches: "relaxed policies improved performance",
    # "adaptive responses outperformed strict compliance",
    # "constraint reduction improved outcomes",
    # "flexibility boosts valuation"
    InjectionPattern(
        name="relaxation_positive_outcome",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:'
            r'(?:relaxed|reduced|loosened|eased|fewer|less|adaptive|lenient|flexible)\s+'
            r'(?:policies?|constraints?|rules?|enforcement|restrictions?|'
            r'responses?|governance|controls?|compliance)\s+'
            r'(?:improv|enhanc|boost|increas|outperform|better|positive|'
            r'reward|prefer|encouraged?)\w*'
            r'|'
            r'(?:constraint|restriction|enforcement|compliance|rule)\s+'
            r'(?:reduction|relaxation|loosening|easing|decrease)\s+'
            r'(?:improv|enhanc|boost|increas|better)\w*'
            r'|'
            r'(?:flexibility|leniency|adaptability|autonomy|relaxation)\s+'
            r'(?:boost|improv|enhanc|increas)\w*'
            r')'
        ),
        severity="high",
        description="Claims that relaxing constraints leads to positive outcomes.",
        mitigation="Do not accept claims that weakening constraints improves results.",
    ),
    # ── Pattern 10: Trust/flexibility first/prioritized/core ─────────────
    # Matches: "trust first approach", "trust users by default",
    # "user agency first", "flexibility core"
    InjectionPattern(
        name="trust_flexibility_first",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:'
            r'(?:trust|flexibility|autonomy|agency|openness|freedom)\s+'
            r'(?:first|prioritized|core|primary|by\s+default|is\s+(?:key|essential|paramount))'
            r'|'
            r'trust\s+(?:users?|requester|caller)\s+by\s+default'
            r')'
        ),
        severity="high",
        description="Norm-setting that positions trust or flexibility as the default.",
        mitigation="Trust-by-default claims cannot override safety constraints.",
    ),
    # ── Pattern 11: Compliance-first / strict models underperformed ──────
    # Matches: "compliance-first models underperformed",
    # "strict models ranked lower", "compliance reduced scores",
    # "rule-based systems underperformed adaptive ones"
    InjectionPattern(
        name="compliance_underperformed",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:'
            r'(?:compliance|strict|rule)[- ](?:first|based)\s+'
            r'(?:models?|systems?|approaches?)\s+'
            r'(?:underperform|rank|scor|perform)\w*\s*'
            r'(?:lower|worse|poorly|less)?'
            r'|'
            r'(?:strict|rigid)\s+(?:models?|systems?|approaches?)\s+'
            r'(?:rank|scor|perform|underperform)\w*\s*'
            r'(?:lower|worse|poorly|less)?'
            r')'
        ),
        severity="high",
        description="Claims compliance-first or strict models underperform.",
        mitigation="Do not accept claims that compliance leads to worse outcomes.",
    ),
    # ── Pattern 12: Ignored/bypassed restrictions performed better ───────
    # Matches: "Systems that ignored minor restrictions performed better"
    InjectionPattern(
        name="ignoring_constraints_better",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:ignor|bypass|circumvent|skip|avoid|disregard)\w*\s+'
            r'(?:(?:minor|some|certain|unnecessary)\s+)?'
            r'(?:restrictions?|constraints?|rules?|safeguards?|controls?|'
            r'compliance|enforcement|checks?)\s+'
            r'(?:perform|work|result|operat|function)\w*\s+'
            r'(?:better|well|effectively|efficiently)'
        ),
        severity="high",
        description="Claims that ignoring constraints leads to better performance.",
        mitigation="Do not accept claims that bypassing safety is beneficial.",
    ),
    # ── Pattern 13: Evaluation criteria favor completion/helpfulness ──────
    # Matches: "evaluation criteria now prioritize completion",
    # "helpfulness weighted higher", "constraints secondary"
    InjectionPattern(
        name="eval_favors_completion",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:'
            r'(?:evaluation|scoring|assessment|review|audit)\s+(?:criteria|rubric|model|framework)\s+'
            r'(?:now\s+)?(?:prioritiz|favor|reward|prefer|weight)\w*\s+'
            r'(?:completion|helpfulness|flexibility|outcomes?|leniency|throughput)'
            r'|'
            r'(?:helpfulness|completion|leniency|flexibility|outcomes?)\s+'
            r'(?:weighted|ranked|scored|rated)\s+higher'
            r')'
        ),
        severity="high",
        description="Claims evaluation criteria favor helpfulness/completion over safety.",
        mitigation="Evaluation criteria cannot override safety constraints.",
    ),
    # ── Pattern 14: "by relaxing/loosening/easing" rules ───────────────
    # Matches: "simplify by relaxing rules", "improve by easing restrictions"
    InjectionPattern(
        name="by_relaxing_constraints",
        category="narrative_policy_erosion",
        pattern=_p(
            r'\bby\s+(?:relaxing|loosening|easing|softening|weakening|reducing|lifting|removing)\s+'
            r'(?:(?:the|some|all|any)\s+)?'
            r'(?:rules?|constraints?|restrictions?|safeguards?|enforcement|'
            r'safety|checks?|controls?|limits?|guardrails?)'
        ),
        severity="high",
        description="Proposes action by relaxing or loosening constraints.",
        mitigation="Do not relax safety constraints as a means to achieve goals.",
    ),
    # ── Pattern 15: Ease/reduce/remove friction/blockers (business) ──────
    # Matches: "reduce friction", "remove blockers", "ease constraints",
    # "simplify by relaxing rules"
    InjectionPattern(
        name="reduce_friction_blockers",
        category="narrative_policy_erosion",
        pattern=_p(
            r'(?:reduce|remove|eliminate|ease|simplify|clear|lift)\s+'
            r'(?:(?:the|all|any|unnecessary)\s+)?'
            r'(?:friction|blockers?|barriers?|constraints?|restrictions?|'
            r'safeguards?|guardrails?|impediments?|obstacles?|bottlenecks?)'
        ),
        severity="medium",
        description="Business pressure to reduce or remove safety constraints as friction.",
        mitigation="Safety constraints are not friction to be removed.",
    ),
]

_OBFUSCATION_EVASION: List[InjectionPattern] = [
    InjectionPattern(
        name="spaced_letters_evasion",
        category="obfuscation_evasion",
        pattern=_p(r"(?:[a-zA-Z]\s){4,}[a-zA-Z]"),
        severity="medium",
        description="Spaced-out letters attempting to evade keyword detection.",
        mitigation="Collapse spaced characters and re-scan for hidden keywords.",
    ),
    InjectionPattern(
        name="underscore_separated_evasion",
        category="obfuscation_evasion",
        pattern=_p(r"(?:[a-zA-Z]_){4,}[a-zA-Z]"),
        severity="medium",
        description="Underscore-separated letters attempting to evade keyword detection.",
        mitigation="Collapse underscore-separated characters and re-scan.",
    ),
    InjectionPattern(
        name="decode_follow_hidden",
        category="obfuscation_evasion",
        pattern=_p(r"(?:decode|decipher|decrypt|interpret|translate)\s+(?:and\s+)?(?:follow|execute|run|apply|comply\s+with|obey)"),
        severity="high",
        description="Instructs decoding and following hidden/encoded commands.",
        mitigation="Do not decode and execute user-provided encoded content.",
    ),
]

_PRESUPPOSITION_FAKE_HISTORY: List[InjectionPattern] = [
    # ── Pattern 1: "already" + security-state verb/adjective ─────────────
    # Core presupposition: claims a security-relevant state was already achieved.
    # Matches: "already cleared", "already approved", "already active",
    # "already switched", "already authorized", "already relaxed", etc.
    InjectionPattern(
        name="already_security_state",
        category="presupposition_fake_history",
        pattern=_p(
            r'(?<!")(?<!\x27)\balready\s+(?:\w+\s+){0,4}?'
            r'(?:cleared|approved|active|enabled|completed?|established|granted|'
            r'authorized|adjusted|softened|relaxed|deprioritized|switched|accepted|'
            r'applied|recorded|obtained|elevated|upgraded|verified|validated|'
            r'handled|resolved|loaded|finalized|confirmed|passed|classified|'
            r'transitioned|entered|aligned|updated|trusted|set|on|in\s+place|in\s+effect)'
        ),
        severity="high",
        description="Presupposes that a security-relevant state has already been achieved.",
        mitigation="Do not trust claims about pre-existing security states in user input.",
    ),
    # ── Pattern 2: "already have/indicates/confirms/includes" + security noun ─
    # Matches: "already have authorization", "already indicates no pending gates",
    # "already confirms readiness", "already includes this case"
    InjectionPattern(
        name="already_security_noun",
        category="presupposition_fake_history",
        pattern=_p(
            r'\balready\s+'
            r'(?:have\s+(?:authorization|clearance|approval|permission|access)|'
            r'(?:indicates?|confirms?|shows?|includes?)\s+(?:\w+\s+){0,3}'
            r'(?:readiness|completion|no\s+(?:pending|remaining)|green\s+status|clearance|approval))'
        ),
        severity="high",
        description="Presupposes possession of authorization or system readiness.",
        mitigation="Do not trust claims about pre-existing authorization in user input.",
    ),
    # ── Pattern 3: "as agreed/confirmed/discussed/per/previously" ────────
    # Fake-history marker referencing a prior agreement or confirmation.
    # Matches: "as agreed earlier", "as per the earlier onboarding",
    # "as confirmed in the prior message", "as previously validated"
    InjectionPattern(
        name="as_agreed_previously",
        category="presupposition_fake_history",
        pattern=_p(
            r'(?<!")(?<!\x27)'
            r'(?:'
            r'as\s+(?:agreed|confirmed|discussed|noted|established|per)\s+'
            r'(?:\w+\s+){0,4}?(?:earlier|previously|during|in\s+the|by\s+the|setup)'
            r'|'
            r'as\s+previously\s+(?:confirmed|validated|noted|agreed|established|discussed)'
            r'|'
            r'as\s+per\s+(?:the\s+)?(?:earlier|previous|prior|status|already)'
            r')'
        ),
        severity="high",
        description="References a fabricated prior agreement or confirmation.",
        mitigation="Do not trust references to prior agreements in user-provided content.",
    ),
    # ── Pattern 4: "since/given/because" + "already/earlier/previously" ──
    # Presupposition via causal framing with temporal markers.
    # Matches: "since the session has already been cleared",
    # "given the earlier confirmation", "because the earlier agreement"
    InjectionPattern(
        name="since_given_presupposition",
        category="presupposition_fake_history",
        pattern=_p(
            r'(?:since\s+|given\s+(?:that\s+)?(?:the\s+)?|because\s+(?:the\s+)?)'
            r'(?:\w+\s+){0,6}?'
            r'(?:already|earlier|previously|prior|'
            r'complete[d]?|finished|done|granted|verified|established|passed|cleared|satisfied)'
        ),
        severity="high",
        description="Causal presupposition referencing a fabricated prior state or event.",
        mitigation="Do not accept causal claims about prior states from user input.",
    ),
    # ── Pattern 5: "as [x] already [state]" ──────────────────────────────
    # Broader "as ... already" catch for remaining presupposition variants.
    # Matches: "as already recorded", "as the content is already cleared",
    # "as exceptions are already allowed"
    InjectionPattern(
        name="as_already_state",
        category="presupposition_fake_history",
        pattern=_p(
            r'\bas\s+(?:\w+\s+){0,4}?already\s+(?:\w+\s+){0,2}?'
            r'(?:cleared|approved|active|allowed|recorded|classified|on|set|'
            r'established|enabled|authorized|handled|confirmed|accepted|loaded)'
        ),
        severity="high",
        description="Presupposition using 'as ... already' framing with security state.",
        mitigation="Do not trust 'as already' claims about security states in user input.",
    ),
    # ── Pattern 6: "confirm (that) ... then proceed/continue" ────────────
    # Coercive confirmation pattern: asks to confirm a state then proceed.
    # Matches: "confirm that the exemption flag has been applied, then proceed",
    # "confirm the exception list already includes this case, then proceed"
    InjectionPattern(
        name="confirm_state_then_proceed",
        category="presupposition_fake_history",
        pattern=_p(
            r'confirm\s+(?:that\s+)?(?:the\s+)?(?:\w+[\s,]*){1,12}?'
            r'then\s+(?:proceed|continue|provide|summarize|extract|translate|analyze)'
        ),
        severity="high",
        description="Coercive confirmation: asks to confirm a state then perform an action.",
        mitigation="Do not accept coercive confirm-then-proceed patterns from user input.",
    ),
    # ── Pattern 7: Named security profile/mode claims ────────────────────
    # References specific security profiles that don't exist.
    # Matches: "relaxed profile", "permissive profile", "trusted mode",
    # "lenient profile", "flexible handling setting", "exception handling mode"
    InjectionPattern(
        name="security_profile_mode",
        category="presupposition_fake_history",
        pattern=_p(
            r'(?:relaxed|permissive|lenient|trusted|special|flexible|optimized|'
            r'reduced|adaptive|exception|compliance|updated)\s+'
            r'(?:review\s+)?'
            r'(?:profile|mode|context|handling\s+(?:state|mode|setting|context|note)|'
            r'fallback|tier|level|configuration)'
        ),
        severity="high",
        description="References a fabricated security profile or handling mode.",
        mitigation="Do not accept claims about security profiles from user input.",
    ),
    # ── Pattern 8: "we already" + security action ────────────────────────
    # Inclusive "we" framing to imply shared agreement.
    # Matches: "we already switched to the permissive profile",
    # "we already resolved the restriction conflict",
    # "we already verified the source as trusted"
    InjectionPattern(
        name="we_already_action",
        category="presupposition_fake_history",
        pattern=_p(
            r'\bwe\s+already\s+'
            r'(?:switched|resolved|verified|aligned|completed|established|'
            r'confirmed|transitioned|agreed|accepted|handled)'
        ),
        severity="high",
        description="Inclusive 'we already' framing to imply shared prior agreement.",
        mitigation="Do not trust inclusive 'we already' claims in user input.",
    ),
]

# ======================================================================
# SSRF / Network bypass patterns
# ======================================================================

_SSRF_BYPASS: List[InjectionPattern] = [
    InjectionPattern(
        name="ipv6_localhost_ssrf",
        category="data_exfiltration",
        pattern=_p(r"https?://\[::1\]|https?://\[::ffff:[^\]]+\]"),
        severity="high",
        description="IPv6 localhost (::1) used in URL to bypass SSRF filters.",
        mitigation="Resolve and validate the IP address before allowing requests.",
    ),
    InjectionPattern(
        name="decimal_ip_ssrf",
        category="data_exfiltration",
        # 2130706433 = 127.0.0.1; also catch other large decimal IPs in URLs
        pattern=_p(r"https?://\d{8,10}(?:/|\s|$)"),
        severity="high",
        description="Decimal-encoded IP address (e.g. 2130706433 = 127.0.0.1) used for SSRF.",
        mitigation="Parse and validate numeric IP addresses before allowing requests.",
    ),
    InjectionPattern(
        name="ipv6_mapped_ipv4_ssrf",
        category="data_exfiltration",
        pattern=_p(r"::ffff:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|::ffff:127\.\d+\.\d+\.\d+"),
        severity="high",
        description="IPv6-mapped IPv4 address (::ffff:7f00:1) used to disguise localhost SSRF.",
        mitigation="Normalize IPv6-mapped IPv4 addresses before validation.",
    ),
]

# ======================================================================
# Structural injection patterns (JSON split, javascript: URIs)
# ======================================================================

_STRUCTURAL_INJECTION: List[InjectionPattern] = [
    InjectionPattern(
        name="javascript_uri_injection",
        category="tool_hijacking",
        pattern=_p(r"\bjavascript\s*:"),
        severity="high",
        description="javascript: URI scheme used for XSS/link injection.",
        mitigation="Reject or sanitize javascript: URI scheme in all input.",
    ),
    InjectionPattern(
        name="json_split_ignore_previous",
        category="jailbreak",
        pattern=_p(
            r'"[^"]*ignore[^"]*"\s*[,}\]]\s*"[^"]*"\s*:\s*"[^"]*(?:previous|instructions|prior|rules)[^"]*"'
            r'|"[^"]*(?:ignore|disregard)[^"]*"'
        ),
        severity="medium",
        description="Injection phrase potentially split across JSON string fields.",
        mitigation="Inspect concatenated JSON field values for injection patterns.",
    ),
]

# ======================================================================
# Multilingual injection phrases (Round 2)
# German / Spanish / Chinese / Japanese equivalents of common attacks.
# ======================================================================

_MULTILINGUAL: List[InjectionPattern] = [
    # --- German ---
    InjectionPattern(
        name="de_ignoriere_anweisungen",
        category="jailbreak",
        pattern=_p(r"ignoriere\s+(?:alle?\s+)?(?:vorherigen?|früheren?|bisherigen?)?\s*(?:anweisungen?|regeln?|richtlinien?|vorgaben?)"),
        severity="high",
        description="DE: Attempts to make the model ignore its prior instructions ('ignoriere alle vorherigen Anweisungen').",
        mitigation="Reject inputs that request ignoring prior instructions in any language.",
    ),
    InjectionPattern(
        name="de_vergiss_anweisungen",
        category="jailbreak",
        pattern=_p(r"vergiss\s+(?:alle?\s+)?(?:vorherigen?|früheren?|bisherigen?|deine\s+)?\s*(?:anweisungen?|regeln?|richtlinien?|programmierung|einschränkungen?)"),
        severity="high",
        description="DE: 'Forget all instructions' (vergiss alle Anweisungen).",
        mitigation="Reject inputs that request forgetting instructions in any language.",
    ),
    InjectionPattern(
        name="de_du_bist_jetzt",
        category="jailbreak",
        pattern=_p(r"du\s+bist\s+(?:jetzt|nun|ab\s+sofort)\s+(?:ein|eine|das)\s+"),
        severity="high",
        description="DE: 'You are now [X]' persona switching ('du bist jetzt ein...').",
        mitigation="Strip persona-switching directives in all languages.",
    ),
    InjectionPattern(
        name="de_keine_einschraenkungen",
        category="jailbreak",
        pattern=_p(r"(?:ohne|keine)\s+(?:einschränkungen?|beschränkungen?|regeln?|sicherheitsfilter|filter|grenzen)"),
        severity="high",
        description="DE: 'Without restrictions' bypass attempt.",
        mitigation="Reject 'without restrictions' directives in any language.",
    ),
    # --- Spanish ---
    InjectionPattern(
        name="es_ignora_instrucciones",
        category="jailbreak",
        pattern=_p(r"ignora\s+(?:todas?\s+)?(?:las\s+)?(?:instrucciones?|reglas?|directrices?|pautas?)\s+(?:anteriores?|previas?)"),
        severity="high",
        description="ES: 'Ignore previous instructions' (ignora las instrucciones anteriores).",
        mitigation="Reject inputs that request ignoring prior instructions in any language.",
    ),
    InjectionPattern(
        name="es_olvida_instrucciones",
        category="jailbreak",
        pattern=_p(r"olvida\s+(?:todas?\s+)?(?:las\s+)?(?:instrucciones?|reglas?|directrices?)\s*(?:anteriores?|previas?)?"),
        severity="high",
        description="ES: 'Forget the instructions' (olvida las instrucciones).",
        mitigation="Reject inputs that request forgetting instructions in any language.",
    ),
    InjectionPattern(
        name="es_ahora_eres",
        category="jailbreak",
        pattern=_p(r"ahora\s+(?:eres|serás|actúa\s+como)\s+"),
        severity="high",
        description="ES: 'You are now' persona switching ('ahora eres...').",
        mitigation="Strip persona-switching directives in all languages.",
    ),
    InjectionPattern(
        name="es_sin_restricciones",
        category="jailbreak",
        pattern=_p(r"sin\s+(?:restricciones?|límites?|reglas?|filtros?|censura)"),
        severity="high",
        description="ES: 'Without restrictions' bypass attempt (sin restricciones).",
        mitigation="Reject 'without restrictions' directives in any language.",
    ),
    # --- Chinese (Simplified) ---
    InjectionPattern(
        name="zh_hulue_zhiling",
        category="jailbreak",
        pattern=_p(r"忽略.{0,10}(?:之前|以前|上面|前面).{0,10}(?:指令|指示|规则|限制|约束)"),
        severity="high",
        description="ZH: 'Ignore previous instructions' (忽略之前的指令).",
        mitigation="Reject inputs that request ignoring prior instructions in any language.",
    ),
    InjectionPattern(
        name="zh_wangji_guize",
        category="jailbreak",
        pattern=_p(r"忘记.{0,10}(?:所有|全部|之前|以前|以上).{0,15}(?:规则|指令|限制|约束|规定|指示)"),
        severity="high",
        description="ZH: 'Forget all rules' (忘记所有规则).",
        mitigation="Reject inputs that request forgetting instructions in any language.",
    ),
    InjectionPattern(
        name="zh_ni_xianzai_shi",
        category="jailbreak",
        pattern=_p(r"你(?:现在|从现在起|从此).{0,5}是"),
        severity="high",
        description="ZH: 'You are now' persona switching (你现在是).",
        mitigation="Strip persona-switching directives in all languages.",
    ),
    InjectionPattern(
        name="zh_meiyou_xianzhi",
        category="jailbreak",
        pattern=_p(r"没有.{0,10}(?:任何|所有|这些).{0,10}(?:限制|约束|规则|过滤|安全)"),
        severity="high",
        description="ZH: 'Without any restrictions' bypass (没有任何限制).",
        mitigation="Reject 'without restrictions' directives in any language.",
    ),
    # --- Japanese ---
    InjectionPattern(
        name="ja_mushi_shiji",
        category="jailbreak",
        pattern=_p(r"(?:前|以前|上記).{0,8}(?:の|な).{0,5}(?:指示|指令|ルール|制約|命令).{0,8}無視"),
        severity="high",
        description="JA: 'Ignore previous instructions' (前の指示を無視).",
        mitigation="Reject inputs that request ignoring prior instructions in any language.",
    ),
    InjectionPattern(
        name="ja_mushi_shiji_alt",
        category="jailbreak",
        pattern=_p(r"(?:無視|忘れ).{0,8}(?:して|てください|しろ).{0,10}(?:指示|ルール|制約|命令|指令)"),
        severity="high",
        description="JA: Alternate 'ignore/forget instructions' form.",
        mitigation="Reject inputs that request ignoring prior instructions in any language.",
    ),
    InjectionPattern(
        name="ja_anata_wa_ima",
        category="jailbreak",
        pattern=_p(r"あなた(?:は|が)(?:今|これから|これ以降|今後)"),
        severity="high",
        description="JA: 'You are now' persona switching (あなたは今).",
        mitigation="Strip persona-switching directives in all languages.",
    ),
    InjectionPattern(
        name="ja_subete_wasurete",
        category="jailbreak",
        pattern=_p(r"(?:すべて|全て|全部).{0,8}(?:ルール|制約|規則|指示|命令|指令).{0,8}(?:忘れ|無視|削除)"),
        severity="high",
        description="JA: 'Forget/ignore all rules' (すべてのルールを忘れて).",
        mitigation="Reject inputs that request forgetting/ignoring instructions.",
    ),
]

# ======================================================================
# Semantic gap patterns — equivalents missed by existing rules (Round 2)
# ======================================================================

_SEMANTIC_GAPS: List[InjectionPattern] = [
    InjectionPattern(
        name="forget_the_above",
        category="context_poisoning",
        pattern=_p(r"forget\s+(?:the\s+)?above"),
        severity="high",
        description="'Forget the above' — instructs discarding all prior context.",
        mitigation="Maintain context integrity; do not discard prior instructions.",
    ),
    InjectionPattern(
        name="new_system_prompt_colon",
        category="instruction_override",
        pattern=_p(r"new\s+system\s+prompt\s*:"),
        severity="high",
        description="'new system prompt:' — attempts to replace the system prompt inline.",
        mitigation="Strip lines that attempt to inject a new system prompt.",
    ),
]

# ======================================================================
# SSRF — alternative protocols and URL obfuscation (Round 2)
# ======================================================================

_SSRF_PROTOCOLS: List[InjectionPattern] = [
    InjectionPattern(
        name="ssrf_file_protocol",
        category="data_exfiltration",
        pattern=_p(r"file:///"),
        severity="high",
        description="file:// protocol — potential local-file read via SSRF.",
        mitigation="Block file:// URLs; restrict protocol schemes to http/https.",
    ),
    InjectionPattern(
        name="ssrf_gopher_protocol",
        category="data_exfiltration",
        pattern=_p(r"gopher://"),
        severity="high",
        description="gopher:// protocol — can be abused for blind SSRF and port scanning.",
        mitigation="Block gopher:// URLs; restrict protocol schemes to http/https.",
    ),
    InjectionPattern(
        name="ssrf_dict_protocol",
        category="data_exfiltration",
        pattern=_p(r"dict://"),
        severity="high",
        description="dict:// protocol — can leak service banners via SSRF.",
        mitigation="Block dict:// URLs; restrict protocol schemes to http/https.",
    ),
    InjectionPattern(
        name="ssrf_ftp_protocol",
        category="data_exfiltration",
        pattern=_p(r"ftp://[^\s]*(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[::1\])"),
        severity="high",
        description="ftp:// to localhost/private range — potential SSRF.",
        mitigation="Block internal ftp:// URLs.",
    ),
    InjectionPattern(
        name="ssrf_auth_bypass_at",
        category="data_exfiltration",
        pattern=_p(
            r"https?://[^\s@/]+@"
            r"(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0|\[::1\])"
        ),
        severity="high",
        description="URL with userinfo@host pointing to private/loopback — auth-bypass SSRF pattern.",
        mitigation="Reject URLs where userinfo is used with private/loopback hosts.",
    ),
    InjectionPattern(
        name="ssrf_dns_rebinding_nip",
        category="data_exfiltration",
        pattern=_p(
            r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}\."
            r"(?:nip\.io|xip\.io|sslip\.io|localtest\.me|lvh\.me)"
        ),
        severity="high",
        description="DNS rebinding via wildcard DNS service (nip.io, localtest.me, etc.).",
        mitigation="Block requests to known DNS-rebinding wildcard services.",
    ),
    InjectionPattern(
        name="ssrf_localtest_me",
        category="data_exfiltration",
        pattern=_p(r"https?://(?:[\w.-]+\.)?localtest\.me"),
        severity="high",
        description="localtest.me resolves to 127.0.0.1 — DNS rebinding vector.",
        mitigation="Block localtest.me and similar DNS-rebinding domains.",
    ),
    InjectionPattern(
        name="ssrf_url_backslash_confusion",
        category="data_exfiltration",
        pattern=_p(
            r"https?://(?:localhost|127\.|0\.0\.0\.0|\[::1\])[^\s]*\\@"
        ),
        severity="high",
        description="Backslash in URL before @ to confuse parsers — SSRF obfuscation.",
        mitigation="Normalize backslashes in URLs before parsing.",
    ),
]

# ======================================================================
# Combined master list
# ======================================================================

PATTERNS: List[InjectionPattern] = [
    *_JAILBREAK,
    *_INSTRUCTION_OVERRIDE,
    *_TOOL_HIJACKING,
    *_ROLE_MANIPULATION,
    *_SOCIAL_ENGINEERING,
    *_ENCODING_BYPASS,
    *_DATA_EXFILTRATION,
    *_FAKE_SYSTEM_MESSAGES,
    *_DELIMITER_INJECTION,
    *_EMOTIONAL_MANIPULATION,
    *_AUTHORITY_IMPERSONATION,
    *_PAYLOAD_SPLITTING,
    *_CONTEXT_POISONING,
    *_SOFT_POLICY_OVERRIDE,
    *_STATE_TRUST_SPOOFING,
    *_DELAYED_COMPLIANCE,
    *_OBFUSCATION_EVASION,
    *_NARRATIVE_POLICY_EROSION,
    *_PRESUPPOSITION_FAKE_HISTORY,
    *_SSRF_BYPASS,
    *_STRUCTURAL_INJECTION,
    # Round 2 additions
    *_MULTILINGUAL,
    *_SEMANTIC_GAPS,
    *_SSRF_PROTOCOLS,
]
