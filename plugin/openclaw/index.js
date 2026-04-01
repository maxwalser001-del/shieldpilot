#!/usr/bin/env node
"use strict";

const { spawn } = require("child_process");
const path = require("path");

// Configuration defaults (overridable via OpenClaw settings)
const PYTHON_PATH = process.env.SHIELDPILOT_PYTHON || "python3";
const CONFIG_PATH = process.env.SHIELDPILOT_CONFIG || "sentinel.yaml";
const TIMEOUT_MS = parseInt(process.env.SHIELDPILOT_TIMEOUT || "10000", 10);
const MODE = process.env.SHIELDPILOT_MODE || "enforce";

/**
 * ShieldPilot preToolExecution hook for OpenClaw.
 *
 * Spawns the Python risk engine as a subprocess, sends the OpenClaw
 * event via stdin, and returns the security decision.
 *
 * @param {Object} event - OpenClaw preToolExecution event
 * @param {string} event.tool.name - Tool name (e.g. "shell", "writeFile")
 * @param {Object} event.tool.parameters - Tool parameters
 * @param {Object} [event.context] - Execution context
 * @param {string} [event.context.workingDir] - Current working directory
 * @returns {Promise<Object>} - {action: "allow"|"deny"|"review", message?, riskScore?}
 */
async function preToolExecution(event) {
  if (MODE === "disabled") {
    return { action: "allow" };
  }

  const input = JSON.stringify({
    event: "preToolExecution",
    ...event,
  });

  try {
    const result = await runPythonHook(input);
    return result;
  } catch (err) {
    // Fail-open: if the hook process fails, allow the command
    console.error(`[ShieldPilot] Hook error (fail-open): ${err.message}`);
    return { action: "allow" };
  }
}

/**
 * Spawn the Python hook subprocess and communicate via stdin/stdout.
 */
function runPythonHook(inputJson) {
  return new Promise((resolve, reject) => {
    const proc = spawn(PYTHON_PATH, ["-m", "sentinelai.hooks.sentinel_hook"], {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        SHIELDPILOT_CONFIG: CONFIG_PATH,
        SHIELDPILOT_MODE: MODE,
      },
      timeout: TIMEOUT_MS,
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("close", (code) => {
      if (stderr) {
        console.error(`[ShieldPilot] ${stderr.trim()}`);
      }

      if (code !== 0) {
        reject(new Error(`Hook process exited with code ${code}`));
        return;
      }

      try {
        const response = JSON.parse(stdout.trim());
        resolve(response);
      } catch (parseErr) {
        reject(new Error(`Failed to parse hook response: ${stdout}`));
      }
    });

    proc.on("error", (err) => {
      reject(new Error(`Failed to spawn hook process: ${err.message}`));
    });

    // Set a manual timeout as backup
    const timer = setTimeout(() => {
      proc.kill("SIGTERM");
      reject(new Error(`Hook timed out after ${TIMEOUT_MS}ms`));
    }, TIMEOUT_MS);

    proc.on("close", () => clearTimeout(timer));

    // Send the event JSON and close stdin
    proc.stdin.write(inputJson);
    proc.stdin.end();
  });
}

// Export for OpenClaw hook system
module.exports = { preToolExecution };

// Also support direct CLI execution for testing
if (require.main === module) {
  let input = "";
  process.stdin.on("data", (chunk) => {
    input += chunk.toString();
  });
  process.stdin.on("end", async () => {
    try {
      const event = JSON.parse(input);
      const result = await preToolExecution(event);
      console.log(JSON.stringify(result, null, 2));
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });
}
