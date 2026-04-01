# ShieldPilot OS Compatibility Matrix

## Supported Platforms

| Platform | Python Versions | CI Tested | Status |
|----------|----------------|-----------|--------|
| Ubuntu (Linux) | 3.9, 3.10, 3.11, 3.12 | Yes | Full support |
| macOS | 3.9, 3.10, 3.11, 3.12 | Yes | Full support |
| Windows | Not tested | No | Not supported |

## Why Windows Is Not Supported

The sandbox module (`sentinelai/sandbox/executor.py`) relies on Unix-specific features:

1. **`preexec_fn`** in `subprocess.Popen` — sets resource limits (`RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`) via the `resource` module, which is not available on Windows.
2. **Bash shell** — commands are passed to `shell=True` which invokes `/bin/sh` on Unix but `cmd.exe` on Windows.
3. **Environment variable syntax** — tests use `$VAR` syntax (not `%VAR%`).

## Test Markers

Tests requiring Unix are decorated with `@unix_only`:

```python
from tests.conftest import unix_only

@unix_only
class TestCommandSandbox:
    ...
```

Tests requiring Linux specifically use `@linux_only`.

## CI Configuration

Defined in `.github/workflows/ci.yml`:

- **OS**: `ubuntu-latest`, `macos-latest`
- **Python**: `3.9`, `3.10`, `3.11`, `3.12`
- **Total jobs**: 8 (2 OS x 4 Python)
- **Coverage**: Uploaded from `ubuntu-latest` + Python 3.11 only
- **Security scans**: Run once on `ubuntu-latest` + Python 3.11
