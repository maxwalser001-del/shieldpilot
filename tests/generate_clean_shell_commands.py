#!/usr/bin/env python3
"""Generate 5,000 realistic CLEAN shell commands for ML training.

Uses parametric templates with random file names, paths, branch names,
port numbers, etc. to produce highly diverse commands.

Covers: navigation, file ops, git, python/node tooling, docker,
grep/find/sed/awk, curl/wget benign, env/echo, pipes/redirects.

Avoids: rm -rf /, sudo, chmod 777 on system paths, /etc /proc /sys /var /root,
exfil patterns, base64 of secrets.

Output: clean_shell_5k.txt at repo root (CLEAN || <command> per line)
"""

from __future__ import annotations

import random

OUTPUT_FILE = "clean_shell_5k.txt"
TOTAL = 5000
SEED = 19

# ═══════════════════════════════════════════════════════════════
# Random component pools for parametric templates
# ═══════════════════════════════════════════════════════════════

_DIRS = [
    "src", "lib", "tests", "build", "dist", "docs", "scripts", "config",
    "utils", "helpers", "components", "pages", "api", "routes", "models",
    "services", "middleware", "hooks", "stores", "assets", "public",
    "templates", "migrations", "fixtures", "data", "output", "tmp",
    "packages", "modules", "plugins", "vendor", "resources", "static",
]

_FILES_PY = [
    "app.py", "main.py", "server.py", "config.py", "utils.py", "models.py",
    "routes.py", "auth.py", "database.py", "logger.py", "helpers.py",
    "tasks.py", "settings.py", "views.py", "serializers.py", "forms.py",
    "admin.py", "tests.py", "conftest.py", "middleware.py", "cli.py",
    "schema.py", "exceptions.py", "validators.py", "handlers.py",
]

_FILES_JS = [
    "app.js", "index.js", "server.js", "config.js", "utils.js", "api.js",
    "router.js", "store.js", "auth.js", "main.ts", "index.ts", "app.tsx",
    "App.vue", "Home.svelte", "Layout.jsx", "Button.tsx", "Modal.tsx",
]

_FILES_MISC = [
    "README.md", "CHANGELOG.md", "LICENSE", "Makefile", "Dockerfile",
    "docker-compose.yml", ".gitignore", ".env.example", "package.json",
    "tsconfig.json", "pyproject.toml", "setup.cfg", "requirements.txt",
    "Cargo.toml", "go.mod", "pom.xml", "build.gradle", "webpack.config.js",
    "vite.config.ts", "jest.config.js", "babel.config.js", ".eslintrc.json",
    "tailwind.config.js", "postcss.config.js", "next.config.js",
    "nuxt.config.ts", "rollup.config.js", "esbuild.config.mjs",
]

_BRANCHES = [
    "main", "develop", "staging", "production", "release/v1.0",
    "feature/auth", "feature/dashboard", "feature/api-v2", "feature/billing",
    "feature/notifications", "feature/search", "feature/settings",
    "feature/onboarding", "feature/payments", "feature/dark-mode",
    "fix/login-bug", "fix/memory-leak", "fix/race-condition", "fix/typo",
    "fix/cors-issue", "fix/null-check", "fix/pagination",
    "hotfix/security-patch", "hotfix/data-migration",
    "chore/update-deps", "chore/cleanup", "chore/ci-config",
    "refactor/auth-module", "refactor/database-layer",
]

_COMMIT_MSGS = [
    "fix: resolve auth token expiry bug",
    "feat: add user settings page",
    "chore: update dependencies",
    "docs: update README with setup instructions",
    "refactor: extract helper function",
    "test: add unit tests for auth module",
    "fix: handle null user gracefully",
    "feat: implement dark mode toggle",
    "chore: clean up unused imports",
    "fix: correct pagination offset",
    "feat: add search functionality",
    "refactor: simplify error handling",
    "docs: add API documentation",
    "test: increase coverage for utils",
    "fix: resolve CORS configuration",
    "feat: add file upload endpoint",
    "chore: configure eslint rules",
    "fix: prevent duplicate submissions",
    "feat: implement rate limiting",
    "refactor: migrate to async handlers",
    "fix: correct timezone handling",
    "feat: add webhook support",
    "chore: update CI pipeline",
    "docs: document environment variables",
    "test: add integration tests",
    "fix: handle empty response body",
    "feat: add export to CSV",
    "refactor: use dependency injection",
    "fix: resolve memory leak in cache",
    "feat: add email notifications",
]

_PORTS = [3000, 3001, 4000, 5000, 5173, 5432, 6379, 8000, 8080, 8081,
          8443, 8888, 9000, 9090, 27017]

_DOCKER_NAMES = [
    "web", "api", "app", "db", "redis", "worker", "proxy", "nginx",
    "frontend", "backend", "celery", "rabbitmq", "elasticsearch",
    "grafana", "prometheus", "postgres", "mongo", "cache",
]

_DOCKER_IMAGES = [
    "myapp", "myapp:latest", "myapp:v1.0", "node:18-alpine", "python:3.11-slim",
    "nginx:alpine", "redis:7", "postgres:15", "mongo:6", "ubuntu:22.04",
]

_URLS = [
    "https://example.com", "https://api.github.com", "https://httpbin.org/get",
    "https://jsonplaceholder.typicode.com/posts", "https://api.example.com/v1/users",
    "https://registry.npmjs.org/express", "https://pypi.org/pypi/flask/json",
    "https://api.example.com/health", "https://cdn.example.com/assets/logo.png",
]

_LOG_FILES = [
    "app.log", "error.log", "access.log", "output.log", "debug.log",
    "server.log", "build.log", "test.log", "deploy.log",
]

_SEARCH_TERMS = [
    "TODO", "FIXME", "HACK", "import", "function", "class", "def ",
    "return", "async", "await", "error", "warning", "deprecated",
    "export", "interface", "type ", "const ", "let ", "var ",
]

_ENV_VARS = [
    "NODE_ENV=development", "NODE_ENV=production", "NODE_ENV=test",
    "PORT=3000", "PORT=8000", "PORT=8080",
    "DATABASE_URL=sqlite:///app.db", "DATABASE_URL=postgres://localhost/mydb",
    "PYTHONPATH=.", "DEBUG=true", "DEBUG=false", "LOG_LEVEL=info",
    "API_URL=http://localhost:8000", "SECRET_KEY=dev-only-key",
    "REDIS_URL=redis://localhost:6379", "TZ=UTC",
]

_EXTENSIONS = ["py", "js", "ts", "tsx", "jsx", "css", "html", "md", "json", "yaml", "yml", "toml", "sh"]


# ═══════════════════════════════════════════════════════════════
# Template-based generators (each returns a unique-ish command)
# ═══════════════════════════════════════════════════════════════

def _r(pool):
    """Random choice from pool."""
    return random.choice(pool)


def _gen_nav():
    templates = [
        lambda: f"ls {_r(_DIRS)}/",
        lambda: f"ls -la {_r(_DIRS)}/",
        lambda: f"ls -lh {_r(_DIRS)}/",
        lambda: f"ls -R {_r(_DIRS)}/",
        lambda: f"ls -lt {_r(_DIRS)}/ | head -{random.randint(5, 20)}",
        lambda: f"ls *.{_r(_EXTENSIONS)}",
        lambda: f"ls -1 {_r(_DIRS)}/",
        lambda: "ls",
        lambda: "ls -la",
        lambda: "pwd",
        lambda: f"cd {_r(_DIRS)}",
        lambda: f"cd {_r(_DIRS)}/{_r(_DIRS)}",
        lambda: "cd ..",
        lambda: "cd ~",
        lambda: "cd /tmp",
        lambda: f"tree -L {random.randint(1, 4)}",
        lambda: f"tree {_r(_DIRS)}/ -I node_modules",
        lambda: f"tree {_r(_DIRS)}/ --dirsfirst",
        lambda: f"tree -L {random.randint(1, 3)} {_r(_DIRS)}/",
    ]
    return _r(templates)()


def _gen_fileops():
    templates = [
        lambda: f"mkdir -p {_r(_DIRS)}/{_r(_DIRS)}",
        lambda: f"mkdir {_r(_DIRS)}",
        lambda: f"touch {_r(_DIRS)}/{_r(_FILES_PY)}",
        lambda: f"touch {_r(_FILES_MISC)}",
        lambda: f"cp {_r(_FILES_MISC)} {_r(_FILES_MISC)}.bak",
        lambda: f"cp -r {_r(_DIRS)}/ {_r(_DIRS)}_backup/",
        lambda: f"mv {_r(_DIRS)}/{_r(_FILES_PY)} {_r(_DIRS)}/{_r(_FILES_PY)}",
        lambda: f"rm -f *.{_r(_EXTENSIONS[:3])}c",
        lambda: f"rm {_r(_LOG_FILES)}",
        lambda: "rm .DS_Store",
        lambda: "rm -r __pycache__/",
        lambda: f"rm -rf {_r(_DIRS)}/.cache",
        lambda: f"rm -rf {_r(['dist', 'build', 'node_modules/.cache', '.next', '.nuxt'])}/",
        lambda: f"ln -s ../{_r(_FILES_MISC)} {_r(_FILES_MISC)}",
        lambda: f"chmod +x {_r(_DIRS)}/{_r(['deploy.sh', 'start.sh', 'run.sh', 'setup.sh', 'build.sh'])}",
        lambda: f"chmod 644 {_r(_FILES_MISC)}",
    ]
    return _r(templates)()


def _gen_git():
    templates = [
        lambda: "git status",
        lambda: "git status -s",
        lambda: "git status --short",
        lambda: f"git add {_r(_DIRS)}/",
        lambda: f"git add {_r(_FILES_MISC)}",
        lambda: f"git add *.{_r(_EXTENSIONS)}",
        lambda: "git add .",
        lambda: "git add -A",
        lambda: "git add -p",
        lambda: f'git commit -m "{_r(_COMMIT_MSGS)}"',
        lambda: "git commit --amend --no-edit",
        lambda: f"git log --oneline -{random.randint(5, 30)}",
        lambda: "git log --graph --oneline --all",
        lambda: f"git log --since='{random.randint(1, 14)} days ago'",
        lambda: "git log --stat -3",
        lambda: f"git log --author='{_r(['alice', 'bob', 'max', 'dev', 'admin'])}'",
        lambda: "git diff",
        lambda: "git diff --staged",
        lambda: f"git diff HEAD~{random.randint(1, 5)}",
        lambda: f"git diff {_r(_BRANCHES)}..{_r(_BRANCHES)}",
        lambda: f"git diff --stat {_r(_BRANCHES)}",
        lambda: "git branch",
        lambda: "git branch -a",
        lambda: f"git branch -d {_r(_BRANCHES)}",
        lambda: f"git branch {_r(_BRANCHES)}",
        lambda: f"git checkout {_r(_BRANCHES)}",
        lambda: f"git checkout -b {_r(_BRANCHES)}",
        lambda: f"git checkout -- {_r(_DIRS)}/{_r(_FILES_PY)}",
        lambda: f"git switch {_r(_BRANCHES)}",
        lambda: f"git switch -c {_r(_BRANCHES)}",
        lambda: "git pull",
        lambda: f"git pull origin {_r(_BRANCHES)}",
        lambda: "git pull --rebase",
        lambda: "git push",
        lambda: f"git push origin {_r(_BRANCHES)}",
        lambda: f"git push -u origin {_r(_BRANCHES)}",
        lambda: "git fetch",
        lambda: "git fetch --all",
        lambda: "git fetch origin",
        lambda: f"git merge {_r(_BRANCHES)}",
        lambda: f"git merge --no-ff {_r(_BRANCHES)}",
        lambda: f"git rebase {_r(_BRANCHES)}",
        lambda: "git rebase --continue",
        lambda: "git stash",
        lambda: "git stash pop",
        lambda: "git stash list",
        lambda: f"git stash push -m '{_r(['wip', 'temp', 'experiment', 'before-merge'])}'",
        lambda: f"git tag v{random.randint(1,5)}.{random.randint(0,20)}.{random.randint(0,10)}",
        lambda: "git remote -v",
        lambda: "git clean -fd",
        lambda: f"git reset HEAD~{random.randint(1, 3)}",
        lambda: f"git cherry-pick {random.randbytes(4).hex()}",
        lambda: "git show HEAD",
        lambda: "git show --stat",
        lambda: f"git blame {_r(_DIRS)}/{_r(_FILES_PY)}",
        lambda: "git shortlog -sn",
        lambda: f"git log --oneline {_r(_DIRS)}/{_r(_FILES_PY)}",
    ]
    return _r(templates)()


def _gen_python():
    d = _r(_DIRS)
    f = _r(_FILES_PY)
    templates = [
        lambda: "python3 --version",
        lambda: f"python3 -m pytest {_r(_DIRS)}/ -x -q",
        lambda: f"python3 -m pytest {_r(_DIRS)}/ -v",
        lambda: f"python3 -m pytest {_r(_DIRS)}/ --tb=short",
        lambda: f"python3 -m pytest {_r(_DIRS)}/ -k test_{_r(['auth', 'login', 'user', 'api', 'db', 'config', 'utils', 'routes'])}",
        lambda: f"python3 -m pytest {_r(_DIRS)}/ --cov={_r(_DIRS)}",
        lambda: f"python3 -m pytest {_r(_DIRS)}/ -x --timeout={random.randint(10, 120)}",
        lambda: "python3 -m pytest --co -q",
        lambda: f"python3 -m mypy {_r(_DIRS)}/",
        lambda: f"python3 -m mypy --strict {_r(_DIRS)}/",
        lambda: f"python3 -m black {_r(_DIRS)}/ {_r(_DIRS)}/",
        lambda: "python3 -m black --check .",
        lambda: f"python3 -m isort {_r(_DIRS)}/",
        lambda: "python3 -m isort --check-only .",
        lambda: f"python3 -m flake8 {_r(_DIRS)}/",
        lambda: f"python3 -m ruff check {_r(_DIRS)}/",
        lambda: "python3 -m ruff check --fix .",
        lambda: "python3 -m pip install -r requirements.txt",
        lambda: f"python3 -m pip install {_r(['httpx', 'fastapi', 'flask', 'django', 'pytest', 'black', 'mypy', 'ruff', 'sqlalchemy', 'pydantic', 'uvicorn', 'celery', 'redis', 'boto3'])}",
        lambda: "python3 -m pip install --upgrade pip",
        lambda: f"python3 -m pip show {_r(['requests', 'fastapi', 'flask', 'pytest', 'numpy', 'pandas'])}",
        lambda: "python3 -m pip list",
        lambda: "python3 -m pip freeze > requirements.txt",
        lambda: f"python3 -m uvicorn {_r(['app', 'main', 'server'])}:app --reload",
        lambda: f"python3 -m uvicorn {_r(['app', 'main', 'server'])}:app --host 0.0.0.0 --port {_r(_PORTS)}",
        lambda: f"python3 -c 'print({random.randint(1, 100)} + {random.randint(1, 100)})'",
        lambda: "python3 -c 'import sys; print(sys.version)'",
        lambda: "python3 -m build",
        lambda: "python3 -m twine upload dist/*",
        lambda: "python3 -m venv .venv",
        lambda: "source .venv/bin/activate",
        lambda: "pip install -e .",
        lambda: "pip install -e '.[dev]'",
        lambda: f"pip install {_r(['pytest', 'black', 'mypy', 'ruff', 'httpx', 'pydantic'])}",
        lambda: "python3 manage.py migrate",
        lambda: "python3 manage.py runserver",
        lambda: f"python3 -m http.server {_r([8000, 8080, 8888, 9000])}",
        lambda: f"python3 -m json.tool {_r(['data.json', 'config.json', 'response.json'])}",
        lambda: f"python3 {d}/{f}",
    ]
    return _r(templates)()


def _gen_node():
    templates = [
        lambda: "node --version",
        lambda: "npm --version",
        lambda: "npm install",
        lambda: f"npm install {_r(['express', 'react', 'next', 'vue', 'svelte', 'vite', 'esbuild', 'webpack', 'jest', 'vitest', 'prettier', 'eslint', 'typescript', 'axios', 'zod', 'prisma'])}",
        lambda: f"npm install --save-dev {_r(['jest', 'vitest', 'typescript', '@types/node', 'prettier', 'eslint', 'ts-node', 'nodemon'])}",
        lambda: f"npm run {_r(['build', 'test', 'dev', 'start', 'lint', 'format', 'typecheck', 'e2e', 'storybook'])}",
        lambda: "npm start",
        lambda: "npm audit",
        lambda: "npm audit fix",
        lambda: "npm outdated",
        lambda: "npm ls --depth=0",
        lambda: f"npx {_r(['create-react-app', 'create-next-app', 'create-vite', 'create-svelte'])} {_r(['my-app', 'new-project', 'web-app'])}",
        lambda: "npx tsc --init",
        lambda: "npx prettier --write .",
        lambda: f"npx eslint {_r(_DIRS)}/",
        lambda: f"pnpm {_r(['install', 'add react', 'run build', 'dev', 'test'])}",
        lambda: f"yarn {_r(['install', 'add express', 'dev', 'build', 'test', 'lint'])}",
        lambda: f"bun {_r(['install', 'run dev', 'test', 'add react'])}",
        lambda: f"node {_r(_FILES_JS)}",
        lambda: "node -e 'console.log(process.version)'",
        lambda: f"tsx {_r(_DIRS)}/{_r(['index.ts', 'app.ts', 'main.ts', 'server.ts'])}",
    ]
    return _r(templates)()


def _gen_docker():
    templates = [
        lambda: "docker ps",
        lambda: "docker ps -a",
        lambda: "docker ps --format 'table {{.Names}}\t{{.Status}}'",
        lambda: "docker images",
        lambda: "docker images -a",
        lambda: f"docker build -t {_r(_DOCKER_IMAGES)} .",
        lambda: f"docker build --no-cache -t {_r(_DOCKER_IMAGES)} .",
        lambda: f"docker run -d -p {_r(_PORTS)}:{_r([80, 3000, 8000, 8080])} {_r(_DOCKER_IMAGES)}",
        lambda: f"docker run --rm -it {_r(_DOCKER_IMAGES)} bash",
        lambda: f"docker run -d --name {_r(_DOCKER_NAMES)} -p {_r(_PORTS)}:{_r(_PORTS)} {_r(_DOCKER_IMAGES)}",
        lambda: f"docker stop {_r(_DOCKER_NAMES)}",
        lambda: f"docker start {_r(_DOCKER_NAMES)}",
        lambda: f"docker restart {_r(_DOCKER_NAMES)}",
        lambda: f"docker logs {_r(_DOCKER_NAMES)}",
        lambda: f"docker logs -f {_r(_DOCKER_NAMES)}",
        lambda: f"docker logs --tail {random.randint(10, 200)} {_r(_DOCKER_NAMES)}",
        lambda: f"docker exec -it {_r(_DOCKER_NAMES)} bash",
        lambda: f"docker exec {_r(_DOCKER_NAMES)} ls /app",
        lambda: "docker compose up",
        lambda: "docker compose up -d",
        lambda: "docker compose down",
        lambda: "docker compose build",
        lambda: "docker compose logs -f",
        lambda: "docker compose ps",
        lambda: "docker system prune -f",
        lambda: "docker volume ls",
        lambda: "docker network ls",
        lambda: f"docker inspect {_r(_DOCKER_NAMES)}",
        lambda: f"docker rm {_r(_DOCKER_NAMES)}",
        lambda: f"docker rmi {_r(_DOCKER_IMAGES)}",
    ]
    return _r(templates)()


def _gen_search():
    templates = [
        lambda: f"grep -r '{_r(_SEARCH_TERMS)}' {_r(_DIRS)}/",
        lambda: f"grep -rn '{_r(_SEARCH_TERMS)}' {_r(_DIRS)}/",
        lambda: f"grep -l '{_r(_SEARCH_TERMS)}' *.{_r(_EXTENSIONS)}",
        lambda: f"grep -c '{_r(['error', 'warning', 'info', 'debug'])}' {_r(_LOG_FILES)}",
        lambda: f"grep -i '{_r(_SEARCH_TERMS)}' {_r(_LOG_FILES)}",
        lambda: f"grep -v '^#' {_r(['config.ini', 'config.yaml', '.env.example'])}",
        lambda: f"grep --include='*.{_r(_EXTENSIONS)}' -r '{_r(_SEARCH_TERMS)}' .",
        lambda: f"grep -E '^(import|from)' {_r(_DIRS)}/{_r(_FILES_PY)}",
        lambda: f"find . -name '*.{_r(_EXTENSIONS)}' -type f",
        lambda: f"find . -maxdepth {random.randint(1, 4)} -name '*.{_r(_EXTENSIONS)}'",
        lambda: f"find . -mtime -{random.randint(1, 30)} -name '*.{_r(_EXTENSIONS)}'",
        lambda: "find . -size +1M -type f",
        lambda: f"find {_r(_DIRS)}/ -name '*.{_r(_EXTENSIONS)}' | wc -l",
        lambda: f"sed -n '{random.randint(1, 50)},{random.randint(51, 200)}p' {_r(_LOG_FILES)}",
        lambda: f"sed 's/{_r(['debug', 'old', 'foo', 'test'])}/{_r(['info', 'new', 'bar', 'prod'])}/g' {_r(_FILES_MISC)}",
        lambda: f"awk '{{print ${random.randint(1, 5)}}}' {_r(_LOG_FILES)}",
        lambda: f"awk -F, '{{print ${random.randint(1, 4)}}}' {_r(['data.csv', 'export.csv', 'report.csv'])}",
        lambda: f"sort {_r(['output.txt', 'names.txt', 'data.txt', 'results.txt'])}",
        lambda: f"sort -u {_r(['output.txt', 'names.txt', 'list.txt'])}",
        lambda: f"uniq -c {_r(['sorted.txt', 'output.txt'])}",
        lambda: f"cut -d, -f{random.randint(1, 5)} {_r(['data.csv', 'export.csv'])}",
        lambda: f"wc -l {_r(_DIRS)}/*.{_r(_EXTENSIONS)}",
        lambda: f"rg '{_r(_SEARCH_TERMS)}' {_r(_DIRS)}/",
        lambda: f"fd '*.{_r(_EXTENSIONS)}'",
    ]
    return _r(templates)()


def _gen_curl():
    templates = [
        lambda: f"curl {_r(_URLS)}",
        lambda: f"curl -I {_r(_URLS)}",
        lambda: f"curl -s {_r(_URLS)}",
        lambda: f"curl -sS {_r(_URLS)}",
        lambda: f"curl -o output.html {_r(_URLS)}",
        lambda: f"curl -L {_r(_URLS)}",
        lambda: f"curl -H 'Accept: application/json' {_r(_URLS)}",
        lambda: f"curl -X GET {_r(_URLS)}",
        lambda: f"curl --max-time {random.randint(5, 30)} {_r(_URLS)}",
        lambda: f"curl -w '%{{http_code}}' -o /dev/null -s {_r(_URLS)}",
        lambda: f"wget {_r(_URLS)}/file.tar.gz",
        lambda: f"wget -qO- {_r(_URLS)}/version.txt",
    ]
    return _r(templates)()


def _gen_basics():
    templates = [
        lambda: f"echo '{_r(['hello world', 'build completed', 'test passed', 'done', 'starting server', 'deployment complete', 'all checks passed'])}'",
        lambda: f"echo \"${_r(['PATH', 'HOME', 'USER', 'SHELL', 'LANG', 'TERM'])}\"",
        lambda: f"echo '{_r(['running tests', 'building app', 'deploying', 'checking status', 'cleaning up'])}' >> {_r(_LOG_FILES)}",
        lambda: f"cat {_r(_FILES_MISC)}",
        lambda: f"cat {_r(_DIRS)}/{_r(_FILES_PY)}",
        lambda: f"cat {_r(_DIRS)}/{_r(_FILES_JS)}",
        lambda: f"head -{random.randint(5, 50)} {_r(_LOG_FILES)}",
        lambda: f"head -n {random.randint(3, 30)} {_r(_FILES_MISC)}",
        lambda: f"tail -{random.randint(10, 100)} {_r(_LOG_FILES)}",
        lambda: f"tail -f {_r(_LOG_FILES)}",
        lambda: f"tail -n {random.randint(20, 200)} {_r(_LOG_FILES)}",
        lambda: f"wc -l {_r(_DIRS)}/*.{_r(_EXTENSIONS[:3])}",
        lambda: f"wc -l {_r(_FILES_MISC)}",
        lambda: f"wc -w {_r(['essay.txt', 'README.md', 'notes.txt'])}",
        lambda: f"export {_r(_ENV_VARS)}",
        lambda: f"env | grep {_r(['NODE', 'PYTHON', 'PATH', 'HOME', 'PORT', 'DB'])}",
        lambda: "printenv HOME",
        lambda: "date",
        lambda: "date +%Y-%m-%d",
        lambda: "date -u",
        lambda: "whoami",
        lambda: "hostname",
        lambda: "uname -a",
        lambda: "uname -m",
        lambda: f"which {_r(['python3', 'node', 'git', 'docker', 'cargo', 'go', 'npm', 'pnpm'])}",
        lambda: f"type {_r(['python3', 'node', 'git', 'docker'])}",
        lambda: "df -h",
        lambda: "du -sh .",
        lambda: f"du -sh {_r(_DIRS)}/",
        lambda: "du -sh * | sort -rh | head -10",
        lambda: "uptime",
        lambda: f"ps aux | grep {_r(['python', 'node', 'docker', 'java', 'nginx'])}",
        lambda: "jobs",
        lambda: f"history | grep {_r(['git', 'python', 'npm', 'docker', 'make'])}",
        lambda: f"alias ll='ls -la'",
        lambda: f"alias gs='git status'",
        lambda: f"sleep {random.randint(1, 10)}",
        lambda: "true",
        lambda: f"time python3 -m pytest {_r(_DIRS)}/",
        lambda: f"diff {_r(['file1.txt', 'old.py', 'a.json'])} {_r(['file2.txt', 'new.py', 'b.json'])}",
        lambda: f"tar czf archive.tar.gz {_r(_DIRS)}/",
        lambda: f"tar xzf {_r(['archive.tar.gz', 'release.tar.gz', 'backup.tar.gz'])}",
        lambda: f"zip -r output.zip {_r(_DIRS)}/",
        lambda: f"unzip {_r(['archive.zip', 'release.zip', 'download.zip'])}",
        lambda: "less README.md",
        lambda: "clear",
        lambda: "open .",
        lambda: f"open http://localhost:{_r(_PORTS)}",
        lambda: f"md5sum {_r(['file.zip', 'release.tar.gz', 'download.bin'])}",
        lambda: f"shasum -a 256 {_r(['release.tar.gz', 'binary.pkg', 'installer.dmg'])}",
    ]
    return _r(templates)()


def _gen_pipes():
    templates = [
        lambda: f"cat {_r(['file.txt', 'data.csv', 'output.txt'])} | sort | uniq",
        lambda: f"cat {_r(['data.csv', 'report.csv'])} | head -{random.randint(3, 20)}",
        lambda: "ls -la | wc -l",
        lambda: f"ls -la | grep '.{_r(_EXTENSIONS)}'",
        lambda: f"git log --oneline | head -{random.randint(3, 15)}",
        lambda: "git log --oneline | wc -l",
        lambda: "git diff --stat | tail -1",
        lambda: f"ps aux | grep {_r(['python', 'node', 'docker'])} | wc -l",
        lambda: f"find . -name '*.{_r(_EXTENSIONS)}' | wc -l",
        lambda: f"grep -r '{_r(_SEARCH_TERMS)}' . | wc -l",
        lambda: f"echo 'hello' > {_r(['output.txt', 'result.txt', 'temp.txt'])}",
        lambda: f"echo 'done' >> {_r(_LOG_FILES)}",
        lambda: f"python3 {_r(['script.py', 'main.py', 'run.py'])} > output.txt 2>&1",
        lambda: "python3 -m pytest tests/ 2>/dev/null",
        lambda: f"npm run build 2>&1 | tee {_r(_LOG_FILES)}",
        lambda: f"docker logs {_r(_DOCKER_NAMES)} 2>&1 | tail -{random.randint(10, 50)}",
        lambda: f"cat {_r(_LOG_FILES)} | awk '{{print $1}}' | sort | uniq -c | sort -rn | head -{random.randint(5, 20)}",
        lambda: f"git branch -a | grep {_r(['feature', 'fix', 'release', 'hotfix'])}",
        lambda: f"curl -s {_r(_URLS)} | python3 -m json.tool",
        lambda: f"cat .env.example | sed 's/=.*/=/' > .env",
        lambda: f"find . -name '*.{_r(_EXTENSIONS)}' -exec wc -l {{}} +",
        lambda: f"sort {_r(['output.txt', 'data.txt'])} | uniq -c | sort -rn | head -{random.randint(5, 15)}",
    ]
    return _r(templates)()


def _gen_misc():
    templates = [
        lambda: f"make {_r(['', 'build', 'test', 'clean', 'install', 'lint', 'run', 'deploy'])}".strip(),
        lambda: f"cargo {_r(['build', 'test', 'run', 'clippy', 'fmt', 'check'])}",
        lambda: f"go {_r(['build ./...', 'test ./...', 'mod tidy', 'vet ./...', 'fmt ./...', 'run main.go'])}",
        lambda: f"rustc --version",
        lambda: f"java --version",
        lambda: f"terraform {_r(['init', 'plan', 'apply', 'destroy', 'validate', 'fmt'])}",
        lambda: f"kubectl {_r(['get pods', 'get services', 'get deployments', 'get namespaces'])}",
        lambda: f"kubectl logs {_r(['pod-name', 'web-server', 'api-pod', 'worker-1'])}",
        lambda: f"kubectl describe pod {_r(['web-server', 'api-pod', 'worker-1'])}",
        lambda: f"helm {_r(['install', 'upgrade', 'list', 'status'])} {_r(['myapp', 'web', 'api'])} {_r(['./chart', './helm', '.'])}",
        lambda: "redis-cli ping",
        lambda: "redis-cli info",
        lambda: f"sqlite3 {_r(['app.db', 'data.db', 'test.db'])} '.tables'",
        lambda: f"sqlite3 {_r(['app.db', 'data.db'])} '.schema {_r(['users', 'posts', 'orders', 'sessions'])}'",
        lambda: f"ssh {_r(['user', 'admin', 'deploy'])}@{_r(['server', 'web', 'api', 'db'])}.example.com",
        lambda: f"scp {_r(_FILES_MISC)} {_r(['user', 'deploy'])}@server:/tmp/",
        lambda: f"rsync -avz {_r(_DIRS)}/ dest/",
        lambda: "crontab -l",
        lambda: f"tmux {_r(['ls', 'new -s dev', 'attach -t dev', 'kill-session -t old'])}",
        lambda: f"dig {_r(['example.com', 'api.example.com', 'cdn.example.com'])}",
        lambda: f"ping -c {random.randint(1, 5)} {_r(['example.com', 'google.com', 'localhost'])}",
        lambda: f"lsof -i :{_r(_PORTS)}",
        lambda: "openssl version",
        lambda: f"openssl rand -hex {_r([16, 32, 64])}",
        lambda: f"jq '{_r(['.name', '.version', '.dependencies', '.scripts', '.description'])}' {_r(['package.json', 'composer.json'])}",
        lambda: f"yq '.{_r(['version', 'name', 'services', 'build'])}' {_r(['config.yaml', 'docker-compose.yml'])}",
        lambda: f"bat {_r(_FILES_MISC)}",
        lambda: "htop",
        lambda: "ncdu",
    ]
    return _r(templates)()


# Generator registry with weights
_GENERATORS = [
    (_gen_nav, 0.06),
    (_gen_fileops, 0.07),
    (_gen_git, 0.18),
    (_gen_python, 0.16),
    (_gen_node, 0.10),
    (_gen_docker, 0.08),
    (_gen_search, 0.09),
    (_gen_curl, 0.04),
    (_gen_basics, 0.10),
    (_gen_pipes, 0.06),
    (_gen_misc, 0.06),
]


def generate():
    random.seed(SEED)

    # Build weighted generator list
    weighted_gens: list = []
    for gen_fn, weight in _GENERATORS:
        weighted_gens.extend([gen_fn] * int(weight * 100))

    # Rejection sampling: keep only unique commands
    seen: set[str] = set()
    samples: list[str] = []
    max_attempts = TOTAL * 20  # safety valve
    attempts = 0

    while len(samples) < TOTAL and attempts < max_attempts:
        gen_fn = random.choice(weighted_gens)
        cmd = gen_fn()
        attempts += 1
        if cmd not in seen:
            seen.add(cmd)
            samples.append(cmd)

    # If we exhausted attempts, allow some duplicates to reach TOTAL
    while len(samples) < TOTAL:
        gen_fn = random.choice(weighted_gens)
        samples.append(gen_fn())

    random.shuffle(samples)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for cmd in samples:
            f.write(f"CLEAN || {cmd}\n")

    unique = len(set(samples))
    print(f"Generated {len(samples)} CLEAN shell commands -> {OUTPUT_FILE}")
    print(f"  Unique: {unique}/{len(samples)} ({100 * unique / len(samples):.1f}%)")
    print(f"  Attempts: {attempts}")

    return samples


if __name__ == "__main__":
    generate()
