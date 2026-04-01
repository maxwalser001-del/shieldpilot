"use strict";

/**
 * OpenClaw Event Mapping for ShieldPilot
 *
 * This module documents how OpenClaw events map to ShieldPilot's
 * adapter layer (sentinelai/adapters/openclaw.py).
 *
 * The Python OpenClawAdapter handles the actual translation:
 *   OpenClaw tool name -> ShieldPilot canonical name
 *   ShieldPilot decision -> OpenClaw action
 *
 * This JS module provides:
 *   1. Client-side validation before sending to Python
 *   2. Event normalization for edge cases
 *   3. Response mapping documentation
 */

// Mirror of OpenClawAdapter._TOOL_NAME_MAP (for client-side reference)
const TOOL_NAME_MAP = {
  shell: "Bash",
  bash: "Bash",
  writeFile: "Write",
  write_file: "Write",
  editFile: "Edit",
  edit_file: "Edit",
  readFile: "Read",
  read_file: "Read",
  search: "Grep",
  glob: "Glob",
  webSearch: "WebSearch",
  webFetch: "WebFetch",
};

// Risk levels for each tool category
const TOOL_RISK_CATEGORY = {
  Bash: "high",       // Shell commands - highest risk
  Write: "medium",    // File writes - medium risk
  Edit: "medium",     // File edits - medium risk
  Read: "low",        // File reads - low risk
  Grep: "low",        // Search - low risk
  Glob: "low",        // File pattern - low risk
  WebSearch: "low",   // Web search - low risk
  WebFetch: "medium", // Web fetch - medium (data exfil possible)
};

// ShieldPilot decision -> OpenClaw action
const DECISION_MAP = {
  allow: "allow",
  deny: "deny",
  ask: "review",
};

/**
 * Normalize an OpenClaw event before sending to the Python hook.
 * Ensures all required fields exist with sensible defaults.
 *
 * @param {Object} event - Raw OpenClaw event
 * @returns {Object} - Normalized event
 */
function normalizeEvent(event) {
  const normalized = {
    event: event.event || "preToolExecution",
    tool: {
      name: event.tool?.name || "unknown",
      parameters: event.tool?.parameters || {},
    },
    context: {
      workingDir: event.context?.workingDir || process.cwd(),
      sessionId: event.context?.sessionId || null,
    },
  };

  // Preserve any additional context fields
  if (event.context) {
    for (const [key, value] of Object.entries(event.context)) {
      if (!(key in normalized.context)) {
        normalized.context[key] = value;
      }
    }
  }

  return normalized;
}

/**
 * Validate that an event has the minimum required structure.
 *
 * @param {Object} event - OpenClaw event to validate
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateEvent(event) {
  const errors = [];

  if (!event || typeof event !== "object") {
    return { valid: false, errors: ["Event must be an object"] };
  }

  if (!event.tool || typeof event.tool !== "object") {
    errors.push("Missing required 'tool' object");
  } else if (!event.tool.name || typeof event.tool.name !== "string") {
    errors.push("Missing required 'tool.name' string");
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Get the canonical ShieldPilot tool name for an OpenClaw tool.
 *
 * @param {string} openclawName - OpenClaw tool name
 * @returns {string} - ShieldPilot canonical name
 */
function getCanonicalToolName(openclawName) {
  return TOOL_NAME_MAP[openclawName] || openclawName;
}

/**
 * Get the risk category for a tool.
 *
 * @param {string} toolName - Canonical tool name
 * @returns {string} - "high", "medium", or "low"
 */
function getToolRiskCategory(toolName) {
  const canonical = getCanonicalToolName(toolName);
  return TOOL_RISK_CATEGORY[canonical] || "medium";
}

module.exports = {
  TOOL_NAME_MAP,
  TOOL_RISK_CATEGORY,
  DECISION_MAP,
  normalizeEvent,
  validateEvent,
  getCanonicalToolName,
  getToolRiskCategory,
};
