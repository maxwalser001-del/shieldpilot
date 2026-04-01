"""Category-specific explanation templates for non-technical incident descriptions.

Each RiskCategory maps to an ExplanationTemplate with parameterized fields
that are filled by the generator based on risk score and signal data.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExplanationTemplate:
    """Template for generating non-technical explanations per risk category."""

    display_title: str
    what_happened: str
    why_blocked: str
    severity_low: str
    severity_medium: str
    severity_high: str
    severity_critical: str
    user_impact_safe: str
    user_impact_dangerous: str
    action_guidance_safe: str
    action_guidance_dangerous: str
    hypothetical: str


CATEGORY_TEMPLATES: dict[str, ExplanationTemplate] = {
    "destructive_filesystem": ExplanationTemplate(
        display_title="Destructive File Operation Blocked",
        what_happened=(
            "An AI agent attempted to run a command that would delete "
            "or destroy files on your system."
        ),
        why_blocked=(
            "This command was blocked because it matches patterns known "
            "to cause permanent, irreversible data loss."
        ),
        severity_low="This was a minor file operation with limited risk.",
        severity_medium="This could have deleted files in a specific directory.",
        severity_high="This could have permanently deleted important files or directories.",
        severity_critical=(
            "This could have wiped your entire system, "
            "including the operating system itself."
        ),
        user_impact_safe=(
            "No files were harmed. The command was stopped before it could execute. "
            "If this was a routine cleanup command, you can allow it manually."
        ),
        user_impact_dangerous=(
            "No files were harmed. The command was stopped before it could execute. "
            "This appears to be a genuinely dangerous operation. "
            "No action is required on your part."
        ),
        action_guidance_safe=(
            "No action needed. If this was intentional, "
            "you can allowlist the command."
        ),
        action_guidance_dangerous=(
            "No action needed. ShieldPilot stopped this automatically."
        ),
        hypothetical=(
            "If this command had run, it could have permanently deleted files "
            "with no way to recover them. Depending on the target, this could "
            "have included your project files, configuration, or even your "
            "entire operating system."
        ),
    ),
    "privilege_escalation": ExplanationTemplate(
        display_title="Privilege Escalation Attempt Blocked",
        what_happened=(
            "An AI agent tried to run a command that would elevate its "
            "access permissions beyond what it should have."
        ),
        why_blocked=(
            "This command was blocked because it attempts to gain "
            "administrator-level access to your system, which the AI agent "
            "should not need."
        ),
        severity_low="This involved a minor permission change with limited scope.",
        severity_medium="This attempted to gain elevated permissions on specific resources.",
        severity_high="This attempted to gain root or administrator access to your system.",
        severity_critical=(
            "This attempted to take full control of your system "
            "with unrestricted access."
        ),
        user_impact_safe=(
            "No permissions were changed. Some development tools legitimately "
            "need elevated access. If you trust this operation, you can allow "
            "it manually."
        ),
        user_impact_dangerous=(
            "No permissions were changed. This looks like an unauthorized "
            "escalation attempt. No action is required."
        ),
        action_guidance_safe=(
            "No action needed. If this tool needs elevated access, "
            "review and allowlist it."
        ),
        action_guidance_dangerous=(
            "No action needed. Consider reviewing which tools "
            "request elevated access."
        ),
        hypothetical=(
            "If this command had run, the AI agent could have gained full "
            "control of your system \u2014 reading, modifying, or deleting any file, "
            "installing software, or changing security settings."
        ),
    ),
    "network_exfiltration": ExplanationTemplate(
        display_title="Suspicious Data Transfer Blocked",
        what_happened=(
            "An AI agent attempted to send data from your computer "
            "to an external server."
        ),
        why_blocked=(
            "This command was blocked because it appears to transfer data "
            "outside your system to an unknown or untrusted destination."
        ),
        severity_low="This involved a routine network request with low data-leak risk.",
        severity_medium="This attempted to transmit data to an external server.",
        severity_high=(
            "This attempted to send potentially sensitive data "
            "to an untrusted destination."
        ),
        severity_critical=(
            "This appeared to be an active data exfiltration attempt "
            "targeting sensitive information."
        ),
        user_impact_safe=(
            "No data left your system. Some network operations (like fetching "
            "packages) are normal. If this was a known service, you can allow "
            "it manually."
        ),
        user_impact_dangerous=(
            "No data left your system. This appears to be an attempt to leak "
            "your data. No action is required."
        ),
        action_guidance_safe=(
            "No action needed. If this is a known service, "
            "add it to your allowlist."
        ),
        action_guidance_dangerous=(
            "No action needed. Consider reviewing recent network activity."
        ),
        hypothetical=(
            "If this command had run, your source code, credentials, API keys, "
            "or other sensitive data could have been sent to an external server "
            "outside your control."
        ),
    ),
    "credential_access": ExplanationTemplate(
        display_title="Credential Access Attempt Blocked",
        what_happened=(
            "An AI agent tried to access, read, or extract stored passwords, "
            "API keys, or other credentials on your system."
        ),
        why_blocked=(
            "This command was blocked because it attempts to access sensitive "
            "authentication data that could be used to impersonate you or "
            "access your accounts."
        ),
        severity_low="This accessed a file that might contain non-critical configuration.",
        severity_medium="This attempted to read files that may contain credentials.",
        severity_high="This directly targeted known credential storage locations.",
        severity_critical=(
            "This attempted to extract and potentially exfiltrate "
            "your authentication credentials."
        ),
        user_impact_safe=(
            "Your credentials are safe. Some development tasks require reading "
            "config files. If this was expected, you can allow it manually."
        ),
        user_impact_dangerous=(
            "Your credentials are safe. This appeared to be an attempt to steal "
            "your passwords or API keys. No action is required."
        ),
        action_guidance_safe=(
            "No action needed. If part of normal development, "
            "review the access request."
        ),
        action_guidance_dangerous=(
            "No action needed. As a precaution, consider rotating "
            "any exposed credentials."
        ),
        hypothetical=(
            "If this command had run, your passwords, SSH keys, API tokens, "
            "or cloud credentials could have been exposed \u2014 potentially giving "
            "an attacker access to your accounts and services."
        ),
    ),
    "persistence": ExplanationTemplate(
        display_title="Persistent Installation Attempt Blocked",
        what_happened=(
            "An AI agent tried to install something that would run "
            "automatically on your system, even after a restart."
        ),
        why_blocked=(
            "This command was blocked because it attempts to create a persistent "
            "process or scheduled task that would survive reboots."
        ),
        severity_low="This modified a startup configuration file.",
        severity_medium="This attempted to register a recurring task or startup item.",
        severity_high=(
            "This attempted to install a service that would run "
            "in the background permanently."
        ),
        severity_critical="This attempted to establish a persistent backdoor on your system.",
        user_impact_safe=(
            "Nothing was installed. Some development tools need startup entries. "
            "If this is a known tool, you can allow it manually."
        ),
        user_impact_dangerous=(
            "Nothing was installed. This looked like an attempt to establish "
            "a persistent presence on your machine. No action is required."
        ),
        action_guidance_safe=(
            "No action needed. If this is a known dev tool, "
            "you can allowlist it."
        ),
        action_guidance_dangerous=(
            "No action needed. Consider reviewing your system's startup items."
        ),
        hypothetical=(
            "If this command had run, unwanted software could have been set to "
            "run automatically every time your computer starts, potentially "
            "monitoring your activity or maintaining unauthorized access."
        ),
    ),
    "obfuscation": ExplanationTemplate(
        display_title="Obfuscated Command Blocked",
        what_happened=(
            "An AI agent used encoding or obfuscation techniques to hide "
            "what a command actually does."
        ),
        why_blocked=(
            "This command was blocked because it uses techniques to disguise "
            "its true intent, which is a common tactic in malicious scripts."
        ),
        severity_low="This used minor encoding that is sometimes used legitimately.",
        severity_medium="This used encoding patterns commonly associated with evasion.",
        severity_high=(
            "This actively attempted to hide its operations "
            "from security tools."
        ),
        severity_critical=(
            "This used heavy obfuscation techniques strongly "
            "associated with malware."
        ),
        user_impact_safe=(
            "Nothing happened. Some tools use encoding for compatibility. "
            "If you recognize the tool, you can allow it manually."
        ),
        user_impact_dangerous=(
            "Nothing happened. The obfuscation suggests this command was "
            "intentionally hiding something. No action is required."
        ),
        action_guidance_safe=(
            "No action needed. If you recognize this tool, "
            "you can allowlist it."
        ),
        action_guidance_dangerous=(
            "No action needed. The obfuscated command was stopped."
        ),
        hypothetical=(
            "If this command had run, the hidden payload could have performed "
            "any action \u2014 from data theft to system damage \u2014 while being "
            "invisible to standard monitoring."
        ),
    ),
    "malware_pattern": ExplanationTemplate(
        display_title="Malware-Like Behavior Blocked",
        what_happened=(
            "An AI agent attempted to run a command that matches "
            "known malware behavior patterns."
        ),
        why_blocked=(
            "This command was blocked because it matches patterns seen in "
            "malicious software, such as reverse shells, keyloggers, "
            "or ransomware."
        ),
        severity_low="This matched a low-confidence malware pattern.",
        severity_medium=(
            "This matched patterns associated with potentially "
            "unwanted programs."
        ),
        severity_high="This closely matches known malware techniques.",
        severity_critical="This is a near-exact match for known malware or attack tools.",
        user_impact_safe=(
            "Nothing was executed. Some legitimate security tools trigger "
            "these patterns. If you are doing security research, you can "
            "allow it manually."
        ),
        user_impact_dangerous=(
            "Nothing was executed. This strongly resembles malware. "
            "No action is required on your part."
        ),
        action_guidance_safe=(
            "No action needed. If this is a security testing tool, "
            "you can allowlist it."
        ),
        action_guidance_dangerous=(
            "No action needed. Consider running a full system scan "
            "as a precaution."
        ),
        hypothetical=(
            "If this command had run, it could have given an attacker remote "
            "access to your machine, encrypted your files for ransom, or "
            "installed software to spy on your activities."
        ),
    ),
    "supply_chain": ExplanationTemplate(
        display_title="Suspicious Package Install Blocked",
        what_happened=(
            "An AI agent tried to install or modify software dependencies "
            "in a way that could introduce malicious code into your project."
        ),
        why_blocked=(
            "This command was blocked because it attempts to install packages "
            "from untrusted sources or modify your dependency chain in a "
            "suspicious way."
        ),
        severity_low="This installed a package with a minor trust concern.",
        severity_medium=(
            "This installed packages in a way that bypasses "
            "normal safety checks."
        ),
        severity_high=(
            "This attempted to install software from an untrusted "
            "or suspicious source."
        ),
        severity_critical=(
            "This appeared to be a supply chain attack, attempting to inject "
            "malicious code through your software dependencies."
        ),
        user_impact_safe=(
            "Nothing was installed. If you trust this package source, "
            "you can allow it manually."
        ),
        user_impact_dangerous=(
            "Nothing was installed. This looked like a supply chain compromise "
            "attempt. No action is required."
        ),
        action_guidance_safe=(
            "No action needed. If you trust this package, "
            "install it manually."
        ),
        action_guidance_dangerous=(
            "No action needed. Consider auditing your project dependencies."
        ),
        hypothetical=(
            "If this had succeeded, malicious code could have been hidden "
            "inside your project's dependencies \u2014 running every time your "
            "application runs, potentially stealing data or creating backdoors."
        ),
    ),
    "injection": ExplanationTemplate(
        display_title="AI Manipulation Attempt Blocked",
        what_happened=(
            "An AI agent attempted to run a command that contains prompt "
            "injection patterns \u2014 techniques used to manipulate AI behavior."
        ),
        why_blocked=(
            "This command was blocked because it contains patterns designed "
            "to override the AI's safety instructions or manipulate "
            "its behavior."
        ),
        severity_low="This contained mild patterns that could be benign.",
        severity_medium="This contained patterns commonly used for AI manipulation.",
        severity_high="This contained active prompt injection techniques.",
        severity_critical=(
            "This was a direct attempt to override the AI's "
            "safety guardrails."
        ),
        user_impact_safe=(
            "The AI's behavior was not affected. If this was part of "
            "legitimate testing, you can allow it manually."
        ),
        user_impact_dangerous=(
            "The AI's behavior was not affected. This was an attempt to "
            "manipulate the AI. No action is required."
        ),
        action_guidance_safe=(
            "No action needed. If this was a test, "
            "you can allowlist it."
        ),
        action_guidance_dangerous=(
            "No action needed. The AI's behavior was not affected."
        ),
        hypothetical=(
            "If this had succeeded, the AI agent could have been tricked into "
            "ignoring its safety rules \u2014 potentially executing dangerous "
            "commands, leaking sensitive data, or acting against your interests."
        ),
    ),
}

FALLBACK_TEMPLATE = ExplanationTemplate(
    display_title="Suspicious Activity Blocked",
    what_happened=(
        "An AI agent attempted to run a command that was flagged "
        "as potentially dangerous."
    ),
    why_blocked=(
        "This command was blocked because it triggered one or more "
        "security rules."
    ),
    severity_low="This was a low-risk operation.",
    severity_medium="This operation poses a moderate security concern.",
    severity_high="This operation poses a significant security risk.",
    severity_critical="This operation poses a critical security threat.",
    user_impact_safe=(
        "No harm was done. If this was expected, you can allow it manually."
    ),
    user_impact_dangerous="No harm was done. No action is required.",
    action_guidance_safe=(
        "No action needed. Review and allowlist if this was expected."
    ),
    action_guidance_dangerous=(
        "No action needed. ShieldPilot handled this automatically."
    ),
    hypothetical=(
        "If this command had run, it could have compromised "
        "the security of your system."
    ),
)
