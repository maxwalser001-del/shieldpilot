"""Sandboxed command executor with resource limits and environment isolation."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from sentinelai.core.config import SandboxConfig
from sentinelai.core.models import ExecutionResult

logger = logging.getLogger(__name__)

# Maximum number of characters captured from stdout / stderr.
_OUTPUT_LIMIT = 10_000


class CommandSandbox:
    """Execute shell commands inside a restricted sandbox.

    Security measures applied:
    * Sensitive environment variables are stripped from the child process.
    * A hard timeout prevents run-away processes.
    * On macOS / Linux, resource limits (CPU, memory, file-size) are enforced
      via the ``resource`` module when available.
    * The ``SENTINEL_SANDBOXED=1`` flag is injected so child processes can
      detect they are running inside the sandbox.
    """

    def __init__(self, config: SandboxConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, command: str, working_dir: Optional[str] = None) -> ExecutionResult:
        """Run *command* in a sandboxed subprocess and return the result.

        Parameters
        ----------
        command:
            Shell command string to execute.
        working_dir:
            Optional working directory for the child process.  Defaults to the
            current working directory of the parent process.

        Returns
        -------
        ExecutionResult
            Pydantic model containing exit code, captured output, timing info,
            and whether the process timed out.
        """
        safe_env = self._build_safe_env()
        timeout = self._config.timeout

        # Choose the appropriate preexec_fn for the current platform.
        preexec = self._set_resource_limits if platform.system() in ("Linux", "Darwin") else None

        timed_out = False
        start = time.monotonic()

        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=safe_env,
                cwd=working_dir,
                preexec_fn=preexec,
            )

            try:
                raw_stdout, raw_stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                raw_stdout, raw_stderr = proc.communicate()
                timed_out = True

            elapsed_ms = (time.monotonic() - start) * 1000.0

            stdout_text = raw_stdout.decode("utf-8", errors="replace")[:_OUTPUT_LIMIT]
            stderr_text = raw_stderr.decode("utf-8", errors="replace")[:_OUTPUT_LIMIT]

            return ExecutionResult(
                command=command,
                exit_code=proc.returncode,
                stdout=stdout_text,
                stderr=stderr_text,
                timed_out=timed_out,
                execution_time_ms=round(elapsed_ms, 2),
            )

        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            logger.error("Sandbox execution failed for %r: %s", command, exc)
            return ExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=str(exc)[:_OUTPUT_LIMIT],
                timed_out=timed_out,
                execution_time_ms=round(elapsed_ms, 2),
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_safe_env(self) -> Dict[str, str]:
        """Return a copy of the current environment with sensitive vars removed.

        The list of variables to strip comes from
        ``config.sandbox.restricted_env_vars``.  The ``SENTINEL_SANDBOXED``
        flag is always added so child processes can detect the sandbox.
        """
        env = os.environ.copy()

        for var in self._config.restricted_env_vars:
            env.pop(var, None)

        # Mark the child process as running inside the sandbox.
        env["SENTINEL_SANDBOXED"] = "1"
        return env

    def _set_resource_limits(self) -> None:
        """Pre-exec hook that applies OS-level resource limits.

        Called only on macOS and Linux where the ``resource`` module is
        available.  Any failure (e.g. unsupported limit on a particular
        platform) is logged and silently ignored so that command execution
        still proceeds.
        """
        try:
            import resource  # Unix-only
        except ImportError:
            logger.debug("resource module not available; skipping resource limits")
            return

        # CPU time limit (seconds) -- use the configured timeout.
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (self._config.timeout, self._config.timeout))
        except (ValueError, OSError) as exc:
            logger.debug("Could not set RLIMIT_CPU: %s", exc)

        # Virtual memory / address-space limit.
        max_mem_bytes = self._config.max_memory_mb * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (max_mem_bytes, max_mem_bytes))
        except (ValueError, OSError) as exc:
            logger.debug("Could not set RLIMIT_AS: %s", exc)

        # Maximum file-size the process may create.
        max_fsize_bytes = self._config.max_file_size_mb * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_fsize_bytes, max_fsize_bytes))
        except (ValueError, OSError) as exc:
            logger.debug("Could not set RLIMIT_FSIZE: %s", exc)
