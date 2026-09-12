#!/usr/bin/env python3
"""
appguardrail - Security guardrails for AI-built apps

Usage:
  appguardrail init [--tool <tool>] [--stack <stack>]
  appguardrail scan [--trivy] [--external auto|off] [--bandit] [--ruff] [--semgrep] [--zap-baseline <url>] [--findings-json <path>] [--codegraph] [<path>]
  appguardrail monitor
  appguardrail review [--stack <stack>] [--db <db>] [--payments <payments>]
  appguardrail report {buyer-diligence,founder-friendly,agency,fix-pack} --findings <json> [--out <path>]
  appguardrail org-bundle [--owner <org>] [--bundle-dir <path>]
  appguardrail hook [--codegraph]
  appguardrail --help
  appguardrail --version

Commands:
  init      Install security rules into your project
  scan      Run a lightweight security scan on a directory
  monitor   Install a GitHub Actions monitor workflow
  review    Generate an AI review prompt for your stack
  report    Generate product and diligence reports from findings JSON
  org-bundle Generate an organization buyer evidence bundle
  hook      Install a pre-commit hook to block vulnerabilities

Options:
  --tool    AI coding tool: auto, codex, copilot, cursor, claude-code, windsurf, lovable (default: auto)
  --stack   Tech stack: nextjs, nextjs-supabase, nextjs-firebase, remix, sveltekit
  --db      Database/backend: supabase, firebase, prisma, drizzle
  --payments  Payment provider: stripe
  --trivy  Also run Trivy filesystem scan
  --external  Auto-discover installed SAST/DAST engines for detected languages (default: auto)
  --bandit  Force-run Bandit Python SAST
  --ruff  Force-run Ruff Bandit-compatible security rules
  --semgrep  Force-run Semgrep multi-language SAST
  --zap-baseline  Run OWASP ZAP baseline scan against a URL
  --findings-json  Write normalized findings JSON for reports or dashboards
  --codegraph  Initialize or sync a CodeGraph index before scanning
  --help    Show this help message
  --version Show version
"""

import argparse
import fnmatch
import functools
import importlib.resources as resources  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from appguardrail_core.config import load_config
from appguardrail_core.controlplane import SafeRedirectHandler
from appguardrail_core.pinned_https import (
    DestinationValidationError,
    PinnedHTTPSFailure,
    post_json_pinned_https,
)
from appguardrail_core.external import build_external_scan_plan
from appguardrail_core.findings import NON_BLOCKING_CONTEXTS
from appguardrail_core.findings import is_deploy_blocking as core_is_deploy_blocking
from appguardrail_core.findings import normalize_findings
from appguardrail_core.language import (
    LANGUAGE_EXTENSIONS,
    detect_language_axes,
    detect_stack_profile,
)
from appguardrail_core.org_bundle import (
    OrgBundleError,
    annotate_missing_pr_repositories,
    gh_error_message,
    gh_pr_list,
    gh_repo_list,
)
from appguardrail_core.org_bundle import load_json as load_org_json
from appguardrail_core.org_bundle import render_org_evidence, write_bundle
from appguardrail_core.reports import (
    REPORT_TYPE_LABELS,
    ReportContext,
    render_report,
    supported_report_types,
)
from appguardrail_core.rules import build_rule_metadata
from appguardrail_core.scan_paths import ScanPathContext, build_scan_path_context

__version__ = "0.1.1"

_EMOJI_REGEX = re.compile(r"[ℹ⏭⚙⚠⚡✅✨❌🌐🐍👋💡🔍🔎🔧🔴🔵🚀🛡🟠🟡🧩🧭🧾]\uFE0F?\s*")

_ORIGINAL_PRINT = print


def _format_msg(msg: str) -> str:
    if os.getenv("APPGUARDRAIL_NO_EMOJI"):
        return _EMOJI_REGEX.sub("", msg)
    return msg


def _console_print(*values, **kwargs) -> None:
    """Print CLI values after applying accessibility formatting to strings."""
    _ORIGINAL_PRINT(
        *(_format_msg(value) if isinstance(value, str) else value for value in values),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Rule templates
# ---------------------------------------------------------------------------

RULES_CURSOR = """\
# AppGuardrail Security Rules

- Every API route must verify authentication before accessing data.
- For every user-owned resource, verify owner_id matches the current session user.
- Never use SUPABASE_SERVICE_ROLE_KEY or any admin key in client-side code.
- Always verify Stripe webhook signatures with stripe.webhooks.constructEvent.
- Validate all inputs (body, params, query) with a schema library before use.
- Return 403 Forbidden for ownership violations, not 404 or 200.
- File uploads must validate type, size, and filename server-side.
- Never set CORS to allow all origins on authenticated endpoints.
- Add tests for cross-user access denial on every resource endpoint.

See https://github.com/ContextualWisdomLab/appguardrail for full rules and checklists.
"""

RULES_CLAUDE = """\
## AppGuardrail Security Guardrails

Apply the following security rules to all code you generate:

1. **Authentication**: Check authentication as the first operation in every API handler.
2. **Authorization**: Verify resource ownership (owner_id === session.user.id) server-side.
3. **Secrets**: Never use NEXT_PUBLIC_ prefix on secret keys or service role keys.
4. **Input validation**: Validate all inputs with Zod or equivalent before processing.
5. **Stripe**: Always verify webhook signatures before processing payment events.
6. **Supabase**: Use getUser() (not getSession()) server-side; RLS on all tables.
7. **Files**: Validate type, size, and generate server-side filenames for uploads.
8. **CORS**: Restrict to known origins on authenticated endpoints.

Return 401 for unauthenticated requests, 403 for ownership violations.

See https://github.com/ContextualWisdomLab/appguardrail for full rules and checklists.
"""

RULES_CODEX = """\
# AppGuardrail Security Guardrails

When working in this repository, apply these security rules before proposing,
editing, or merging code:

- Check authentication at the start of every protected API handler.
- Verify resource ownership server-side before returning user-owned data.
- Never expose service-role, admin, Stripe secret, or webhook signing keys to client code.
- Validate request body, params, query, uploaded files, and webhook payloads server-side.
- Verify Stripe webhook signatures before processing payment events.
- Confirm Supabase RLS or equivalent authorization is enabled before trusting client filters.
- Run `appguardrail scan --codegraph .` before merging security-sensitive changes when CodeGraph is installed.
- Treat AppGuardrail critical/high findings as deploy blockers unless the finding is in docs, tests, examples, or scanner fixtures.

If CodeGraph is available, use it for call graph, blast radius, and ownership-flow checks before broad file reads.
"""

RULES_COPILOT = """\
# AppGuardrail Security Instructions

Apply these rules when suggesting code, reviewing pull requests, or generating fixes:

- Protected routes must authenticate first and authorize user-owned resources server-side.
- Do not place service-role keys, admin keys, Stripe secrets, or webhook secrets in client code.
- Validate all request inputs and uploaded files before use.
- Verify Stripe webhook signatures with the raw body and signing secret.
- Prefer tests that prove cross-user access returns 403.
- Run or recommend `appguardrail scan --codegraph .` for security-sensitive changes when CodeGraph is installed.
- Treat AppGuardrail critical/high findings in app code as deploy blockers.
"""

RULES_WINDSURF = RULES_CURSOR  # Windsurf uses the same format

RULES_LOVABLE = """\
# AppGuardrail Secure Build Checklist for Lovable

Use this checklist when building or reviewing an app generated with Lovable.
Paste the relevant sections as context into your Lovable prompt to enforce
security from the start.

## Prompt Prefix

Before generating any code, apply these security rules:

1. Every API route or server action must check authentication before accessing data.
2. Every resource endpoint must verify the authenticated user owns the requested record.
3. Never expose SUPABASE_SERVICE_ROLE_KEY or any admin key to the client.
4. Enable Supabase Row Level Security on every table that stores user data.
5. Validate all inputs (body, params, query) before processing.
6. Verify Stripe webhook signatures before processing payment events.
7. Never set CORS to allow all origins on authenticated endpoints.
8. Generate secure server-side filenames for uploads; validate type and size.

## Pre-Launch Security Checklist

- [ ] All protected pages and APIs require authentication.
- [ ] Every user-owned resource verifies ownership server-side.
- [ ] Supabase RLS is enabled on user-data tables.
- [ ] Service role keys and privileged API keys never reach browser code.
- [ ] `.env` files are ignored and secrets are not committed.
- [ ] Stripe webhooks call `stripe.webhooks.constructEvent`.
- [ ] Payment prices and amounts are selected server-side.
- [ ] Uploads validate type, size, and generated filenames server-side.
- [ ] Security headers and restricted CORS are configured before deploy.
"""

CHECKLIST_TEMPLATE = """\
# AppGuardrail Security Checklist

Generated by appguardrail init. Review before launching.

## Authentication
- [ ] All protected routes check authentication server-side
- [ ] Unauthenticated requests return 401
- [ ] Session tokens are stored securely

## Authorization
- [ ] Every resource endpoint verifies ownership (owner_id === session.user.id)
- [ ] Users cannot access each other's data by changing IDs
- [ ] Admin routes are protected by role checks

## Secrets
- [ ] No hardcoded secrets in source code
- [ ] .env files are in .gitignore
- [ ] No NEXT_PUBLIC_ prefix on secret keys

## Database
- [ ] Row Level Security enabled on all user-data tables (Supabase)
- [ ] Firebase rules do not use allow read, write: if true

## Payments
- [ ] Stripe webhook signature verified with constructEvent
- [ ] Prices fetched server-side, not from client request

## Deployment
- [ ] Security headers configured (X-Frame-Options, CSP, etc.)
- [ ] CORS restricted to known origins
- [ ] npm audit clean (no critical/high vulnerabilities)

See https://github.com/ContextualWisdomLab/appguardrail for full checklists.
"""

MONITOR_WORKFLOW = """\
name: AppGuardrail Monitor

on:
  pull_request:
  push:
    branches: [main, master, develop]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      CP_URL: ${{ secrets.APPGUARDRAIL_CONTROL_PLANE_URL }}
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.x"

      - name: Install AppGuardrail
        run: python -m pip install --disable-pip-version-check appguardrail

      - name: Run AppGuardrail (SARIF + deploy gate; push to control plane if configured)
        id: scan
        continue-on-error: true
        env:
          APPGUARDRAIL_API_KEY: ${{ secrets.APPGUARDRAIL_API_KEY }}
        run: |
          PUSH=""
          if [ -n "$CP_URL" ]; then PUSH="--push $CP_URL"; fi
          appguardrail scan --sarif appguardrail.sarif $PUSH .

      - name: Upload results to GitHub code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: appguardrail.sarif

      - name: Enforce deploy gate
        if: steps.scan.outcome == 'failure'
        run: |
          echo "AppGuardrail found deploy-blocking findings — see the Security tab."
          exit 1
"""

# ---------------------------------------------------------------------------
# Scan patterns
# ---------------------------------------------------------------------------

SCAN_RULES = [
    {
        "id": "python-insecure-deserialization",
        "pattern": re.compile(
            r"\b(?:pickle\.(?:load|loads|Unpickler)|marshal\.(?:load|loads)|yaml\.(?:load|unsafe_load))\s*\(",
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Insecure deserialization detected. Loading untrusted data with pickle, marshal, yaml.load, or yaml.unsafe_load can lead to arbitrary code execution. [OWASP A08:2021 - Software and Data Integrity Failures]",
        "extensions": [".py"],
    },
    {
        "id": "hardcoded-stripe-secret",
        "pattern": re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{24,}", re.MULTILINE),
        "severity": "CRITICAL",
        "message": "Hardcoded Stripe secret key detected. Rotate this key immediately. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
    {
        "id": "hardcoded-openai-key",
        "pattern": re.compile(r"sk-[A-Za-z0-9]{32,}", re.MULTILINE),
        "severity": "CRITICAL",
        "message": "Possible hardcoded OpenAI API key detected. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
    {
        "id": "next-public-secret",
        "pattern": re.compile(
            r"NEXT_PUBLIC_(?:STRIPE_SECRET|SUPABASE_SERVICE_ROLE|DATABASE|JWT_SECRET|NEXTAUTH_SECRET|API_SECRET)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Secret environment variable uses NEXT_PUBLIC_ prefix — this exposes it to the browser bundle. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": None,
    },
    {
        "id": "supabase-service-role-client",
        "pattern": re.compile(
            r"NEXT_PUBLIC_.*SERVICE_ROLE", re.IGNORECASE | re.MULTILINE
        ),
        "severity": "CRITICAL",
        "message": "Supabase service role key exposed to the client via NEXT_PUBLIC_ prefix. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".env",
            ".env.local",
            ".env.production",
        ],
    },
    {
        "id": "firebase-allow-all",
        "pattern": re.compile(
            r"allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true", re.MULTILINE
        ),
        "severity": "CRITICAL",
        "message": "Firebase/Firestore rule allows unrestricted read/write access. Add authentication and ownership checks. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".rules"],
    },
    {
        "id": "dangerous-cors",
        "pattern": re.compile(r"Access-Control-Allow-Origin['\",\s]*[*]", re.MULTILINE),
        "severity": "HIGH",
        "message": "CORS set to allow all origins (*). Restrict to known domains. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [".ts", ".tsx", ".js", ".jsx", ".py"],
    },
    {
        "id": "hardcoded-database-url",
        "pattern": re.compile(
            r'(?i)(?:DATABASE_URL|POSTGRES_URL)\s*[=:]\s*["\x27](?:postgres|postgresql|mysql)://\S+',
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Hardcoded database connection string detected. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
    {
        "id": "hardcoded-jwt-secret",
        "pattern": re.compile(
            r'(?i)(?:JWT_SECRET|NEXTAUTH_SECRET)\s*[=:]\s*["\x27][^"\x27\s]{8,}["\x27]',
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Hardcoded JWT/NextAuth secret detected. [OWASP A02:2021 - Cryptographic Failures]",
        "extensions": None,
    },
    {
        "id": "stripe-webhook-no-verify",
        "pattern": re.compile(
            r'constructEvent\s*\([^)]*(?:undefined|""|\'\')\s*\)', re.MULTILINE
        ),
        "severity": "CRITICAL",
        "message": "Stripe constructEvent called with empty/undefined webhook secret. [OWASP A08:2021 - Software and Data Integrity Failures]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "mock-session-in-handler",
        "pattern": re.compile(
            r'const\s+(?:session|user)\s*=\s*\{\s*(?:user\s*:\s*)?\{\s*id\s*:\s*["\x27]',
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Mock or hardcoded session/user object detected in route handler. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "dangerous-eval",
        "pattern": re.compile(r"\beval\s*\(", re.MULTILINE),
        "severity": "CRITICAL",
        "message": "Use of eval() detected. This is a critical risk for arbitrary code execution and injection attacks. [OWASP A03:2021 - Injection]",
        "extensions": [".js", ".jsx", ".ts", ".tsx", ".py"],
    },
    {
        "id": "react-dangerously-set-inner-html",
        "pattern": re.compile(r"dangerouslySetInnerHTML\s*=", re.MULTILINE),
        "severity": "HIGH",
        "message": "Use of dangerouslySetInnerHTML detected. This can lead to Cross-Site Scripting (XSS) if input is not sanitized. [OWASP A03:2021 - Injection]",
        "extensions": [".jsx", ".tsx"],
    },
    {
        "id": "sql-injection-risk",
        "pattern": re.compile(
            r'(?i)(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["\'].*?["\']\s*\+\s*[a-zA-Z0-9_]+)',
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Potential SQL injection detected: string concatenation or template literal in database query. [OWASP A03:2021 - Injection]",
        "extensions": [".ts", ".tsx", ".js", ".jsx", ".py"],
    },
    {
        "id": "node-command-injection",
        "pattern": re.compile(
            r'(?i)\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["\'].*?["\']\s*\+\s*[a-zA-Z0-9_]+)'
        ),
        "severity": "CRITICAL",
        "message": "Potential Command Injection detected: string concatenation or template literal in child_process execution. [OWASP A03:2021 - Injection]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "python-command-injection",
        "pattern": re.compile(
            r"(?i)(?:os\.system|subprocess\.(?:Popen|run|call|check_call|check_output))\s*\([^)]*shell\s*=\s*True"
        ),
        "severity": "CRITICAL",
        "message": "Potential Command Injection detected: shell=True used in Python subprocess/os command. [OWASP A03:2021 - Injection]",
        "extensions": [".py"],
    },
    {
        "id": "path-traversal-risk",
        "pattern": re.compile(
            r'(?i)\b(?:fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)|open)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["\'].*?["\']\s*\+\s*[a-zA-Z0-9_]+|f["\'][^"\']*\{[^}]+\}[^"\']*["\'])'
        ),
        "severity": "CRITICAL",
        "message": "Potential Path Traversal detected: dynamic path constructed using template literals, f-strings, or concatenation in file operations. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx", ".py"],
    },
    {
        "id": "browser-localstorage-sensitive-state",
        "pattern": re.compile(
            r"\blocalStorage\.setItem\s*\([^,\n]+,\s*(?:JSON\.stringify\s*\(|[^)]*(?:token|jwt|session|user|project|task|dsn|database|credential))",
            re.IGNORECASE | re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Client-side localStorage persistence of sensitive or user-controlled app state detected. Prefer server-side storage, HttpOnly cookies for tokens, or encrypted browser storage. [OWASP A02:2021 - Cryptographic Failures]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "dom-xss-html-sink",
        "pattern": re.compile(
            r"\b(?:innerHTML|outerHTML)\s*=|\binsertAdjacentHTML\s*\(",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "HTML injection sink detected. Ensure attacker-controlled values are encoded or sanitized before reaching innerHTML, outerHTML, or insertAdjacentHTML. [OWASP A03:2021 - Injection]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "unsafe-inline-script-csp",
        "pattern": re.compile(
            r"(?i)(?:content-security-policy[^;\n]*script-src[^;\n]*'unsafe-inline'|script-src[^;\n]*'unsafe-inline')",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Content Security Policy allows unsafe inline scripts. Remove 'unsafe-inline' from script-src or use nonces/hashes. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [".html", ".htm", ".js", ".jsx", ".ts", ".tsx"],
    },
    {
        "id": "frontend-database-dsn-exposure",
        "pattern": re.compile(
            r"(?i)\b(?:dsn|databaseUrl|database_url)\b[^\n]{0,80}\b(?:useState|useRef|input|placeholder|value|localStorage|sessionStorage)\b|\b(?:useState|useRef|input|placeholder|value|localStorage|sessionStorage)\b[^\n]{0,80}\b(?:dsn|databaseUrl|database_url)\b",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Database DSN or connection string appears to be collected, stored, or rendered in client-side code. Keep database credentials server-side. [OWASP A02:2021 - Cryptographic Failures]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "upload-filename-path-traversal-risk",
        "pattern": re.compile(
            r"(?i)(?:os\.path\.join\s*\([^)\n]*(?:file|upload|attachment)\w*\.filename|Path\s*\([^)\n]*\)\s*/\s*(?:file|upload|attachment)\w*\.filename|/\s*(?:file|upload|attachment)\w*\.filename)",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Uploaded filename is used in a filesystem path. Sanitize with a strict allowlist and verify the resolved path stays inside the intended directory. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".py"],
    },
    {
        "id": "python-dynamic-sql",
        "pattern": re.compile(
            r"(?is)(?:execute|query)\s*\(\s*(?:f[\"']\s*(?:select|insert|update|delete|with)\b[^\"']*\{[^}]+\}|[\"']\s*(?:select|insert|update|delete|with)\b[^\"']*[\"']\s*(?:\+|%))",
        ),
        "severity": "CRITICAL",
        "message": "Dynamic SQL query construction detected. Use parameterized queries or query-builder binding instead of string formatting or concatenation. [OWASP A03:2021 - Injection]",
        "extensions": [".py"],
    },
    {
        "id": "tool-execute-parameters-passthrough",
        "pattern": re.compile(
            r"(?is)[\"'][^\"'\n]*(?:/api)?/tools/(?:\{[^}\"']+\}|:[A-Za-z_][\w-]*)/execute[^\"'\n]*[\"'](?:(?!\n\s*(?:class|def|function|export|interface)\b).){0,2000}\b(?:registry|tool|handler|executor)\s*\.\s*execute\s*\([^)]*\b(?:request|req|body|payload|params)\b[^)]*\bparameters\b",
        ),
        "severity": "CRITICAL",
        "message": "Tool execution endpoint appears to pass request parameters directly into a registry or handler. Validate the tool code allowlist and parameter schema before dispatch. [OWASP A03:2021 - Injection]",
        "extensions": [
            ".py",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".ts",
            ".tsx",
            ".mts",
            ".cts",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".cs",
            ".kt",
            ".rs",
        ],
    },
    {
        "id": "python-jwt-decode-without-algorithms",
        "pattern": re.compile(
            r"jwt\.decode\s*\((?:(?!algorithms\s*=).){0,400}\)",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": "CRITICAL",
        "message": "JWT decode call does not appear to pin accepted algorithms. Explicitly require expected algorithms and validate issuer, audience, expiry, and key id. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": [".py"],
    },
    {
        "id": "python-subprocess-string-command",
        "pattern": re.compile(
            r"(?i)subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*\+)",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Subprocess command is built as a formatted or concatenated string. Pass an argument list and validate attacker-controlled command arguments. [OWASP A03:2021 - Injection]",
        "extensions": [".py"],
    },
    {
        "id": "python-permissive-cors",
        "pattern": re.compile(
            r"(?i)(?:allow_origins|origins)\s*=\s*\[\s*[\"']\*[\"']\s*\]",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "CORS allows every origin. Restrict authenticated APIs to known origins. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [".py"],
    },
    {
        "id": "client-side-dev-user-auth",
        "pattern": re.compile(
            r"(?i)(?:dev-user|x-dev-user|devUser)[^\n]{0,100}(?:auth|user|headers|localStorage|useState)|(?:auth|user|headers|localStorage|useState)[^\n]{0,100}(?:dev-user|x-dev-user|devUser)",
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Client-controlled dev-user authentication marker detected. Do not trust browser-supplied user identity for server authorization. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "state-changing-fetch-without-csrf-token",
        "pattern": re.compile(
            r"(?is)\bfetch\s*\([^)]*method\s*:\s*[\"'](?:POST|PUT|PATCH|DELETE)[\"'](?:(?!csrf|xsrf).){0,300}\)",
        ),
        "severity": "WARNING",
        "message": "State-changing browser request has no nearby CSRF/XSRF token marker. Confirm SameSite cookie policy or token validation on the server. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "http-exception-chains-internal-error",
        "pattern": re.compile(
            r"raise\s+HTTPException\s*\([^)]*\)\s+from\s+exc",
            re.MULTILINE,
        ),
        "severity": "WARNING",
        "message": "HTTPException is chained from an internal exception. Avoid leaking implementation details in API error responses. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [".py"],
    },
    {
        "id": "python-subprocess-user-controlled-args",
        "pattern": re.compile(
            r"(?is)subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*\[[^\]]{0,500}\b(?:source_path|input_path|filename|target_bytes|silence_noise)\b"
        ),
        "severity": "HIGH",
        "message": "Subprocess argument list includes high-risk user-controlled media or filename parameters. Validate each argument with strict allowlists and bounds before invoking external tools. [OWASP A03:2021 - Injection]",
        "extensions": [".py"],
    },
    {
        "id": "python-target-bytes-missing-upper-bound",
        "pattern": re.compile(
            r"(?is)\btarget_bytes\b(?:(?!\btarget_bytes\s*[<>]=?\s*(?:MAX_|max_|[0-9])).){0,500}\bif\s+target_bytes\s*<=\s*0\s*:"
        ),
        "severity": "HIGH",
        "message": "target_bytes is checked only for a lower bound. Add a server-side upper bound to prevent resource exhaustion in media processing. [OWASP A04:2021 - Insecure Design]",
        "extensions": [".py"],
    },
    {
        "id": "hardcoded-api-credential",
        "pattern": re.compile(
            r'(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[=:]\s*["\x27][^"\x27\s]{8,}["\x27]',
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Hardcoded API credential detected. Move credentials to secret storage and rotate any committed value. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
    {
        "id": "fastapi-state-changing-route-without-auth",
        "pattern": re.compile(
            r"(?is)@(?:app|router)\.(?:post|put|patch|delete)\s*\([^)]*\)\s*(?:async\s+)?def\s+\w+\s*\((?:(?!Depends|Security|current_user|require_auth|get_current_user|auth).){0,500}\)\s*:",
        ),
        "severity": "HIGH",
        "message": "State-changing FastAPI route has no nearby authentication dependency marker. Require authentication and server-side authorization before mutating state. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".py"],
    },
    {
        "id": "pydantic-bounding-box-unconstrained",
        "pattern": re.compile(
            r"(?is)class\s+\w*BoundingBox\w*\s*\([^)]*BaseModel[^)]*\)\s*:(?:(?!\nclass\s).){0,800}\b(?:x|y|width|height)\s*:\s*(?:float|int)\b(?:(?!Field\s*\(|ge\s*=|le\s*=).){0,800}\b(?:x|y|width|height)\s*:\s*(?:float|int)\b"
        ),
        "severity": "HIGH",
        "message": "Bounding box schema fields are unconstrained numeric values. Add min/max bounds to reject invalid coordinates before document processing. [OWASP A04:2021 - Insecure Design]",
        "extensions": [".py"],
    },
    {
        "id": "pydantic-unbounded-nested-list",
        "pattern": re.compile(
            r"(?is)class\s+\w+\s*\([^)]*BaseModel[^)]*\)\s*:(?:(?!\nclass\s).){0,800}\b\w+\s*:\s*(?:list|List)\s*\[\s*(?:list|List)\s*\["
        ),
        "severity": "HIGH",
        "message": "Pydantic model accepts nested lists without an obvious size or depth bound. Add max_length/depth validation for untrusted recursive structures. [OWASP A04:2021 - Insecure Design]",
        "extensions": [".py"],
    },
    {
        "id": "python-absolute-path-traversal-check-missing",
        "pattern": re.compile(
            r"(?is)Path\s*\([^)]*\)(?:(?!is_absolute).){0,600}[\"']\.\.[\"']\s+in\s+\w+\.parts"
        ),
        "severity": "HIGH",
        "message": "Path validation checks '..' parts but does not reject absolute paths nearby. Reject absolute paths and verify resolved paths stay under the allowed root. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".py"],
    },
    {
        "id": "python-okta-host-endswith-ssrf",
        "pattern": re.compile(
            r"(?is)\b(?:authenticator|hostname|netloc|parsed_url|parsed)\b(?:(?!\n\s*\n).){0,500}\.endswith\s*\(\s*(?:\([^\)]*)?[\"']\.?(?:okta|oktapreview)\.com[\"']"
        ),
        "severity": "HIGH",
        "message": "Okta/Snowflake authenticator host validation uses a suffix check. Parse the URL hostname and allow only exact Okta domains or verified subdomains to prevent SSRF bypasses. [OWASP A10:2021 - Server-Side Request Forgery]",
        "extensions": [".py"],
    },
    {
        "id": "python-subprocess-missing-timeout",
        "pattern": re.compile(
            r"(?is)(?:subprocess\.(?:run|Popen|call|check_call|check_output)\s*\((?!(?:(?!\n\s*\)\s*(?:\n|$)).)*timeout\s*=)(?:(?!\n\s*\)\s*(?:\n|$)).){0,1200}\n\s*\)|subprocess\.(?:run|Popen|call|check_call|check_output)\s*\((?:(?!timeout\s*=)[^\n])+\))"
        ),
        "severity": "HIGH",
        "message": "External process call has no timeout. Add a bounded timeout and handle TimeoutExpired to prevent worker exhaustion. [OWASP A04:2021 - Insecure Design]",
        "extensions": [".py"],
    },
    {
        "id": "shell-awk-variable-injection",
        "pattern": re.compile(
            r"(?is)\bawk\s+(?:[\"'][^\"'\n]{0,300}\$\{?[A-Za-z_][A-Za-z0-9_]*\}?[^\"'\n]{0,300}[\"']|[\"'][^\"'\n]{0,300}[\"']\s*\"\$[A-Za-z_][A-Za-z0-9_]*\")"
        ),
        "severity": "CRITICAL",
        "message": "Shell variable is interpolated into an awk program. Validate input and pass values with awk -v instead of embedding shell variables in the awk script. [OWASP A03:2021 - Injection]",
        "extensions": [".sh", ".bash"],
    },
    {
        "id": "node-exec-url-command-injection",
        "pattern": re.compile(
            r"(?i)\bexec(?:Sync)?\s*\(\s*(?:authUrl|browserUrl|openUrl|url|command)\b"
        ),
        "severity": "CRITICAL",
        "message": "child_process.exec is called with a URL or command variable. Use spawn/execFile with argument arrays and validate allowed URL protocols. [OWASP A03:2021 - Injection]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "node-unvalidated-output-path-write",
        "pattern": re.compile(
            r"(?i)\b(?:writeFile|writeFileSync|createWriteStream)\s*\(\s*(?:output|outputPath|filePath|dest|destination|exportPath)\b"
        ),
        "severity": "HIGH",
        "message": "File write uses a caller-controlled output path. Resolve the target and verify it stays inside the allowed project root before writing. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "python-expanduser-user-path-traversal",
        "pattern": re.compile(
            r"(?i)\bPath\s*\([^)]*(?:input|output|file|path)[^)]*\)\.expanduser\s*\("
        ),
        "severity": "HIGH",
        "message": "User-controlled path is expanded before containment validation. Reject traversal and verify resolved paths stay under the allowed root. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".py"],
    },
    {
        "id": "github-actions-secret-env-passthrough",
        "pattern": re.compile(
            r"(?is)\b(?:LLM_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|DB_PASS|DATABASE_URL|PRIVATE_KEY|ACCESS_TOKEN)\s*:\s*\$\{\{\s*secrets\."
        ),
        "severity": "HIGH",
        "message": "GitHub Actions passes a high-risk secret directly through environment variables. Prefer file-based secret handoff or a scoped platform token. [OWASP A03:2021 - Injection]",
        "extensions": [".yml", ".yaml"],
    },
    {
        "id": "github-actions-secrets-github-token",
        "pattern": re.compile(r"\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}", re.IGNORECASE),
        "severity": "HIGH",
        "message": "Workflow references secrets.GITHUB_TOKEN. Use github.token with least job permissions instead of secret-context token interpolation. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [".yml", ".yaml"],
    },
    {
        "id": "docker-cli-secret-env-leak",
        "pattern": re.compile(
            r"(?i)\bdocker\s+(?:run|exec|compose)[^\n]*(?:-e|--env)\s+(?:DB_PASS|DATABASE_URL|PASSWORD|TOKEN|[A-Z0-9_]*SECRET)[A-Z0-9_]*="
        ),
        "severity": "HIGH",
        "message": "Docker command passes a secret through CLI environment flags where it can leak through process listings. Use --env-file or secret mounts. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": [".sh", ".bash", ".yml", ".yaml"],
    },
    {
        "id": "html-target-blank-without-noopener",
        "pattern": re.compile(
            r"(?i)<a\b(?=[^>\n]*target\s*=\s*[\"']_blank[\"'])(?![^>\n]*rel\s*=\s*[\"'][^\"']*(?:noopener|noreferrer))[^>\n]*href\s*=\s*[\"']https?://"
        ),
        "severity": "WARNING",
        "message": 'External target=_blank link is missing rel="noopener noreferrer". Add rel attributes to prevent reverse tabnabbing. [OWASP A05:2021 - Security Misconfiguration]',
        "extensions": [".html", ".htm"],
    },
    {
        "id": "python-requests-verify-false",
        "pattern": re.compile(
            r"(?is)\b(?:requests|httpx)\.(?:request|get|post|put|patch|delete)\s*\((?:(?!\n\s*\)).){0,500}verify\s*=\s*False"
        ),
        "severity": "HIGH",
        "message": "HTTP client disables TLS certificate verification. Keep verification enabled or pin a trusted CA bundle. [CWE-295 - Improper Certificate Validation]",
        "extensions": [".py"],
    },
    {
        "id": "python-tempfile-mktemp",
        "pattern": re.compile(r"\btempfile\.mktemp\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "message": "tempfile.mktemp creates predictable names without opening the file atomically. Use NamedTemporaryFile or mkstemp. [CWE-377 - Insecure Temporary File]",
        "extensions": [".py"],
    },
    {
        "id": "python-flask-debug-true",
        "pattern": re.compile(
            r"(?is)\bapp\.run\s*\((?:(?!\n\s*\)).){0,300}debug\s*=\s*True|\bDEBUG\s*=\s*True"
        ),
        "severity": "HIGH",
        "message": "Debug mode is enabled in application code. Disable active debug code before deployment. [CWE-489 - Active Debug Code]",
        "extensions": [".py"],
    },
    {
        "id": "python-jinja-autoescape-disabled",
        "pattern": re.compile(
            r"(?is)\b(?:jinja2\.)?Environment\s*\((?:(?!\n\s*\)).){0,500}autoescape\s*=\s*False"
        ),
        "severity": "HIGH",
        "message": "Jinja2 autoescaping is disabled. Keep autoescape enabled for HTML templates to reduce XSS risk. [CWE-79 - Cross-site Scripting]",
        "extensions": [".py"],
    },
    {
        "id": "python-django-csrf-exempt",
        "pattern": re.compile(r"@csrf_exempt\b", re.MULTILINE),
        "severity": "HIGH",
        "message": "Django CSRF protection is explicitly disabled on a view. Require CSRF protection or document a safe non-browser authentication boundary. [CWE-352 - Cross-Site Request Forgery]",
        "extensions": [".py"],
    },
    {
        "id": "node-tls-validation-disabled",
        "pattern": re.compile(
            r"(?i)(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']0[\"']|rejectUnauthorized\s*:\s*false)"
        ),
        "severity": "HIGH",
        "message": "Node.js TLS certificate validation is disabled. Keep certificate validation enabled in production paths. [CWE-295 - Improper Certificate Validation]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "node-jwt-none-algorithm",
        "pattern": re.compile(
            r"(?is)\bjwt\.(?:verify|sign)\s*\((?:(?!\n\s*\)).){0,700}(?:algorithms?\s*:\s*\[[^\]]*[\"']none[\"']|algorithm\s*:\s*[\"']none[\"'])"
        ),
        "severity": "CRITICAL",
        "message": "JWT verification or signing allows the none algorithm. Pin expected algorithms and reject unsigned tokens. [CWE-347 - Improper Verification of Cryptographic Signature]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "node-cors-wildcard-with-credentials",
        "pattern": re.compile(
            r"(?is)\bcors\s*\(\s*\{(?:(?!\}\s*\)).){0,500}origin\s*:\s*[\"']\*[\"'](?:(?!\}\s*\)).){0,500}credentials\s*:\s*true"
        ),
        "severity": "HIGH",
        "message": "CORS allows every origin while credentials are enabled. Use an explicit allowlist for credentialed requests. [CWE-942 - Permissive Cross-domain Policy]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "node-helmet-csp-disabled",
        "pattern": re.compile(
            r"(?is)\bhelmet\s*\(\s*\{(?:(?!\}\s*\)).){0,500}contentSecurityPolicy\s*:\s*false"
        ),
        "severity": "HIGH",
        "message": "Helmet Content-Security-Policy is disabled. Keep CSP enabled or configure a strict policy. [CWE-693 - Protection Mechanism Failure]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "node-clickjacking-protection-disabled",
        "pattern": re.compile(
            r"(?is)(?:\bhelmet\s*\(\s*\{(?:(?!\}\s*\)).){0,500}(?:frameguard|xFrameOptions)\s*:\s*false|X-Frame-Options[\"']?\s*,\s*[\"']ALLOWALL[\"'])"
        ),
        "severity": "HIGH",
        "message": "Clickjacking protection is disabled. Use deny/sameorigin frame controls unless embedding is explicitly required. [CWE-1021 - Improper Restriction of Rendered UI Layers]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "express-reflected-input-send",
        "pattern": re.compile(
            r"(?is)\bres\.(?:send|write|end)\s*\((?:(?!sanitize|escape|encode).){0,300}\breq\.(?:query|params|body)\b"
        ),
        "severity": "HIGH",
        "message": "Express response sends request-controlled input without a nearby escaping marker. Encode output or render through a safe template context. [CWE-79 - Cross-site Scripting]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "java-spring-csrf-disabled",
        "pattern": re.compile(
            r"(?is)\.csrf\s*\(\s*\)\s*\.disable\s*\(|\.csrf\s*\(\s*\w+\s*->\s*\w+\.disable\s*\(\s*\)\s*\)|\.csrf\s*\(\s*AbstractHttpConfigurer\s*::\s*disable\s*\)"
        ),
        "severity": "HIGH",
        "message": "Spring CSRF protection is disabled. Keep CSRF enabled for browser-reachable state-changing routes or document a non-browser-only boundary. [CWE-352 - Cross-Site Request Forgery]",
        "extensions": [".java"],
    },
    {
        "id": "java-hostname-verifier-allow-all",
        "pattern": re.compile(
            r"(?is)(?:setHostnameVerifier\s*\([^)]*->\s*true|HostnameVerifier\b(?:(?!\n\s*\n).){0,800}\breturn\s+true\s*;)"
        ),
        "severity": "HIGH",
        "message": "Hostname verification accepts every host. Keep TLS hostname verification enabled to prevent machine-in-the-middle attacks. [CWE-295 - Improper Certificate Validation]",
        "extensions": [".java"],
    },
    {
        "id": "java-cookie-secure-false",
        "pattern": re.compile(r"\.setSecure\s*\(\s*false\s*\)", re.MULTILINE),
        "severity": "HIGH",
        "message": "Cookie Secure flag is explicitly disabled. Session and auth cookies should be restricted to HTTPS transport. [CWE-614 - Sensitive Cookie in HTTPS Session Without Secure Attribute]",
        "extensions": [".java"],
    },
    {
        "id": "java-jwt-none-algorithm",
        "pattern": re.compile(r"\bAlgorithm\.none\s*\(", re.MULTILINE),
        "severity": "CRITICAL",
        "message": "JWT code uses the none algorithm. Require a signed algorithm and validate issuer, audience, expiry, and key id. [CWE-347 - Improper Verification of Cryptographic Signature]",
        "extensions": [".java"],
    },
    {
        "id": "java-objectinputstream-deserialization",
        "pattern": re.compile(r"new\s+ObjectInputStream\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "message": "ObjectInputStream deserialization detected. Do not deserialize untrusted data without strict type allowlists and integrity controls. [CWE-502 - Deserialization of Untrusted Data]",
        "extensions": [".java"],
    },
    {
        "id": "hardcoded-password",
        "pattern": re.compile(
            r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\x27][^"\x27\s]{6,}["\x27]'
        ),
        "severity": "HIGH",
        "message": "Possible hardcoded password detected. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
]


def _unquote_rule_scalar(value: str) -> str:
    """Return a simple YAML scalar value from the controlled rule files."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote = value[0]
        value = value[1:-1]
        if quote == "'":
            value = value.replace("''", "'")
    return value


def _parse_inline_list(value: str):
    """Parse the `[a, b]` lists used by scanner/rules/*.yml."""
    value = value.strip()
    if not (value.startswith("[") and value.endswith("]")):
        return []
    inner = value[1:-1].strip()
    if not inner:
        return []
    return [_unquote_rule_scalar(item) for item in inner.split(",")]


def _extensions_for_languages(languages):
    """Map YAML rule languages to file extensions for the regex scanner."""
    if not languages or "generic" in languages:
        return None

    extensions = []
    for language in languages:
        extensions.extend(LANGUAGE_EXTENSIONS.get(language, []))
    return sorted(set(extensions)) or None


def _parse_yaml_regex_rules(text: str, origin: str = "<rules>"):
    """Parse the supported pattern-regex subset of AppGuardrail rule YAML."""
    parsed_rules = []
    current = None
    in_message = False
    path_mode = None

    def finish_rule():
        if not current:
            return
        message = "\n".join(current.pop("message_lines", [])).strip()
        current["message"] = message or f"Rule {current['id']} matched."
        parsed_rules.append(current.copy())

    for raw_line in text.splitlines():
        if raw_line.startswith("  - id: "):
            finish_rule()
            current = {
                "id": _unquote_rule_scalar(raw_line.split(":", 1)[1]),
                "origin": origin,
                "regexes": [],
                "languages": [],
                "message_lines": [],
                "include_paths": [],
                "exclude_paths": [],
                "required_substrings": [],
                "severity": "WARNING",
            }
            in_message = False
            path_mode = None
            continue

        if current is None:
            continue

        if in_message:
            if raw_line.startswith("      ") or not raw_line.strip():
                current["message_lines"].append(
                    raw_line[6:] if raw_line.startswith("      ") else ""
                )
                continue
            in_message = False

        stripped = raw_line.strip()
        if raw_line.startswith("    message: |"):
            in_message = True
            path_mode = None
            continue
        if raw_line.startswith("    severity: "):
            current["severity"] = _unquote_rule_scalar(
                raw_line.split(":", 1)[1]
            ).upper()
            path_mode = None
            continue
        if raw_line.startswith("    languages: "):
            current["languages"] = _parse_inline_list(raw_line.split(":", 1)[1])
            path_mode = None
            continue
        if raw_line.startswith("    prefilter: "):
            current["required_substrings"] = _parse_inline_list(
                raw_line.split(":", 1)[1]
            )
            path_mode = None
            continue
        if raw_line.startswith("      - pattern-regex: "):
            current["regexes"].append(
                _unquote_rule_scalar(raw_line.split("pattern-regex:", 1)[1])
            )
            path_mode = None
            continue
        if stripped == "include:":
            path_mode = "include_paths"
            continue
        if stripped == "exclude:":
            path_mode = "exclude_paths"
            continue
        if path_mode and raw_line.startswith("        - "):
            current[path_mode].append(_unquote_rule_scalar(raw_line.split("- ", 1)[1]))

    finish_rule()
    return parsed_rules


def _compile_yaml_regex_rule(rule):
    """Build runtime regex scanner rules from one parsed YAML rule."""
    compiled_rules = []
    extensions = _extensions_for_languages(rule.get("languages") or [])
    for regex in rule.get("regexes") or []:
        try:
            pattern = re.compile(regex, re.MULTILINE)
        except re.error:
            continue
        compiled_rules.append(
            {
                "id": rule["id"],
                "pattern": pattern,
                "severity": rule.get("severity", "WARNING"),
                "message": rule.get("message") or f"Rule {rule['id']} matched.",
                "extensions": extensions,
                "include_paths": rule.get("include_paths") or [],
                "exclude_paths": rule.get("exclude_paths") or [],
                "required_substrings": tuple(
                    rule.get("required_substrings") or ()
                ),
            }
        )
    return compiled_rules


def _load_packaged_regex_rules():
    """Load supported regex rules from packaged scanner/rules/*.yml files."""
    loaded = []
    try:
        rule_files = sorted(resources.files("scanner.rules").iterdir())
    except (FileNotFoundError, ModuleNotFoundError):
        return loaded

    for rule_file in rule_files:
        if rule_file.suffix not in {".yml", ".yaml"}:
            continue
        try:
            text = rule_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for rule in _parse_yaml_regex_rules(text, origin=rule_file.name):
            loaded.extend(_compile_yaml_regex_rule(rule))
    return loaded


SCAN_RULES.extend(_load_packaged_regex_rules())

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    ".cache",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".env",
    "coverage",
}

SECURITY_HIDDEN_DIRS = {
    ".github",
    ".vercel",
    ".netlify",
    ".supabase",
    ".firebase",
    ".well-known",
    ".config",
}

SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".zip",
    ".tar",
    ".gz",
    ".lock",
    ".map",
    ".log",
}

# ---------------------------------------------------------------------------
# Review prompt templates
# ---------------------------------------------------------------------------

REVIEW_PROMPT_BASE = """\
Please perform a security review of this codebase. Focus on vulnerabilities
common in AI-generated web applications.

Review the following areas:

1. **Authentication**: Are there API routes missing auth checks?
2. **Authorization**: Is resource ownership verified server-side for every endpoint?
3. **Secrets**: Are there hardcoded secrets or NEXT_PUBLIC_ on sensitive vars?
4. **Input Validation**: Is user input validated server-side before database operations?
5. **CORS & Headers**: Is CORS restricted? Are security headers configured?
6. **AI Patterns**: Are there TODO comments that defer security checks?
"""

REVIEW_PROMPT_SUPABASE = """\
7. **Supabase RLS**: Is Row Level Security enabled on all user-data tables?
   Do policies use auth.uid() correctly? Is service_role used client-side?
8. **Supabase Auth**: Is getUser() used server-side (not getSession())?
"""

REVIEW_PROMPT_FIREBASE = """\
7. **Firebase Rules**: Are Firestore/Storage rules allowing unrestricted access?
   Is Firebase Admin SDK used only server-side?
"""

REVIEW_PROMPT_STRIPE = """\
9. **Stripe**: Is webhook signature verified with constructEvent?
   Are prices fetched server-side, not from the client? Is billing portal behind auth?
"""

REVIEW_PROMPT_NEXTJS = """\
Stack context: Next.js application.
- Check App Router API routes (app/api/) and server actions for auth gaps.
- Check next.config.js for security headers.
- Verify no secrets use NEXT_PUBLIC_ prefix.
"""

REVIEW_PROMPT_FOOTER = """\

For each issue found, provide:
1. File and location
2. Vulnerability description
3. Risk if exploited
4. Specific code fix
5. Verification test
"""


def _display_path(path: str | Path) -> str:
    """Return a stable, slash-separated path for CLI output and reports."""
    return path.as_posix() if isinstance(path, Path) else path.replace("\\", "/")


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def cmd_init(args):
    """Install security rules into the project."""
    tool = getattr(args, "tool", "auto") or "auto"
    stack = getattr(args, "stack", None)
    project_root = Path(".").resolve()

    installed = []
    skipped = []

    tool_configs = {
        "cursor": {
            "path": Path(".cursor") / "rules" / "appguardrail.md",
            "content": RULES_CURSOR,
        },
        "codex": {
            "path": Path("AGENTS.md"),
            "content": RULES_CODEX,
            "append_marker": "AppGuardrail",
        },
        "copilot": {
            "path": Path(".github") / "copilot-instructions.md",
            "content": RULES_COPILOT,
            "append_marker": "AppGuardrail",
        },
        "claude-code": {
            "path": Path("CLAUDE.md"),
            "content": RULES_CLAUDE,
            "append_marker": "AppGuardrail",
        },
        "windsurf": {
            "path": Path(".windsurf") / "rules" / "appguardrail.md",
            "content": RULES_WINDSURF,
        },
        "lovable": {
            "path": Path("LOVABLE_SECURITY_CHECKLIST.md"),
            "content": RULES_LOVABLE,
        },
    }
    tool_groups = {
        "auto": ["codex", "copilot", "claude-code", "cursor", "windsurf"],
    }

    selected_tools = tool_groups.get(tool, [tool])

    unknown_tools = [
        selected for selected in selected_tools if selected not in tool_configs
    ]
    if unknown_tools:
        _console_print(f"❌ Error: Unknown tool '{tool}'", file=sys.stderr)
        _console_print(
            f"💡 Hint: Supported tools are {', '.join([*tool_groups.keys(), *tool_configs.keys()])}",
            file=sys.stderr,
        )
        sys.exit(1)

    for selected_tool in selected_tools:
        config = tool_configs[selected_tool]
        if config.get("shared_only"):
            continue

        target_file = project_root / config["path"]

        # SECURITY: Prevent Arbitrary File Write via symlink path traversal
        if not target_file.resolve().is_relative_to(project_root):
            _console_print(
                f"❌ Error: Target path {target_file} escapes the project root. Aborting.",
                file=sys.stderr,
            )
            _console_print(
                "💡 Hint: Ensure the target file or its symlinks do not point outside the repository.",
                file=sys.stderr,
            )
            sys.exit(1)

        target_file.parent.mkdir(parents=True, exist_ok=True)
        if target_file.is_symlink():
            target_file.unlink()

        if "append_marker" in config and target_file.exists():
            existing = target_file.read_text()
            if config["append_marker"] not in existing:
                target_file.write_text(existing + "\n\n" + config["content"])
                installed.append(f"{_display_path(config['path'])} (appended)")
            else:
                skipped.append(_display_path(config["path"]))
        else:
            target_file.write_text(config["content"])
            installed.append(_display_path(config["path"]))
    # Always create the checklist
    checklist_file = project_root / "APPGUARDRAIL_CHECKLIST.md"

    # SECURITY: Prevent Arbitrary File Write via symlink path traversal
    if not checklist_file.resolve().is_relative_to(project_root):
        _console_print(
            f"❌ Error: Checklist path {checklist_file} escapes the project root. Aborting.",
            file=sys.stderr,
        )
        _console_print(
            "💡 Hint: Ensure the checklist file or its symlinks do not point outside the repository.",
            file=sys.stderr,
        )
        sys.exit(1)

    if checklist_file.is_symlink():
        checklist_file.unlink()
    if not checklist_file.exists():
        checklist_file.write_text(CHECKLIST_TEMPLATE)
        installed.append("APPGUARDRAIL_CHECKLIST.md")
    else:
        skipped.append("APPGUARDRAIL_CHECKLIST.md")

    if stack and "supabase" in stack:
        _print_supabase_reminder()

    _console_print(_format_msg("\n✅ AppGuardrail initialized successfully!\n"))
    if installed:
        _console_print(_format_msg("✨ Created/updated files:"))
        for f in installed:
            _console_print(f"  {f}")
        _console_print()

    if skipped:
        _console_print(_format_msg("⏭️  Skipped (already configured):"))
        for f in skipped:
            _console_print(f"  {f}")
        _console_print()

    _console_print(_format_msg("🚀 Next steps:"))
    _console_print("  1. Review the installed rules and customize for your project")
    _console_print("  2. Run 'appguardrail scan .' to check for existing issues")
    _console_print("  3. Check APPGUARDRAIL_CHECKLIST.md before deploying")
    _console_print()


def _print_supabase_reminder():
    """Print extra operational reminders for Supabase-backed projects."""
    _console_print("\n💡 Hint: Supabase stack detected. Quick reminders:")
    _console_print("  - Enable RLS on every user-data table")
    _console_print("  - Use getUser() not getSession() on the server")
    _console_print("  - Keep SUPABASE_SERVICE_ROLE_KEY server-side only")
    _console_print()


def _detect_scan_languages(files):
    """Return language axes found in a scan target without requiring a profile."""
    return detect_language_axes(files)


def _external_tool_available(name: str, version_args=("--version",)):
    """Return a runnable external tool path, or None for missing/broken tools."""
    executable = shutil.which(name)
    if not executable:
        return None
    try:
        process = subprocess.run(  # noqa: S603 - executable resolved with shutil.which
            [executable, *version_args],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if process.returncode != 0:
        return None
    return executable


def _print_external_auto_skips(plan):
    """Print beginner-safe auto-mode skips without failing the scan."""
    skipped = [
        decision
        for decision in plan.decisions
        if decision.skip_reason and not decision.forced
    ]
    if not skipped:
        return
    _console_print("⚙️  External auto mode:")
    for decision in skipped:
        _console_print(f"   Skipped {decision.display_name}: {decision.skip_reason}")
    _console_print()


def cmd_scan(args):
    """Run a lightweight security scan."""
    scan_arg = Path(getattr(args, "path", ".") or ".")
    scan_path = scan_arg.resolve()
    run_trivy = getattr(args, "trivy", False)
    external_mode = getattr(args, "external", "off")
    force_bandit = getattr(args, "bandit", False)
    force_ruff = getattr(args, "ruff", False)
    force_semgrep = getattr(args, "semgrep", False)
    semgrep_config = getattr(args, "semgrep_config", None) or os.environ.get(
        "APPGUARDRAIL_SEMGREP_CONFIG", "auto"
    )
    zap_baseline_url = getattr(args, "zap_baseline", None) or os.environ.get(
        "APPGUARDRAIL_TARGET_URL"
    )
    findings_json = getattr(args, "findings_json", None)
    force_zap = bool(getattr(args, "zap_baseline", None))
    run_codegraph = getattr(args, "codegraph", False)

    if not scan_arg.exists():
        _console_print(f"❌ Error: Path does not exist: {scan_path}", file=sys.stderr)
        _console_print(
            "💡 Hint: Check if the path is correct or if you are in the right directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    if scan_arg.is_symlink():
        _console_print(f"Skipping symlink path: {scan_arg}")
        return 0

    _console_print(f"\n🔍 AppGuardrail scanning: {scan_path}\n")

    if run_codegraph:
        _console_print(
            "🧭 CodeGraph enabled: initializing or syncing structural index\n"
        )
        try:
            status = _run_codegraph_index(scan_path)
        except RuntimeError as exc:
            _console_print(f"❌ Error: {exc}", file=sys.stderr)
            _console_print(
                "💡 Hint: Install the CodeGraph CLI or run without --codegraph.",
                file=sys.stderr,
            )
            return 1
        if status:
            _console_print(status)
            _console_print()

    findings = []
    files_scanned = 0
    scanned_files = []

    scan_path_is_file = scan_path.is_file()
    path_context = build_scan_path_context(
        scan_path,
        base_path_is_file=scan_path_is_file,
    )

    if scan_path_is_file:
        files_to_scan = [scan_path]
    else:
        files_to_scan = _collect_files(scan_path)

    for file_path in files_to_scan:
        scanned_files.append(file_path)
        files_scanned += 1
        file_findings = _scan_file(
            file_path,
            scan_path,
            path_context=path_context,
        )
        findings.extend(file_findings)

    profile = detect_stack_profile(scanned_files)
    languages = set(profile.languages)
    if profile.languages:
        _console_print(f"🧩 Detected language axes: {', '.join(profile.languages)}")
        _console_print(f"🧭 Beginner profile: {profile.display_name}")
        _console_print(f"   {profile.beginner_summary}")
        if profile.frameworks:
            _console_print(f"   Framework signals: {', '.join(profile.frameworks)}")
        if profile.external_tools:
            _console_print(
                f"   Optional external engines: {', '.join(profile.external_tools)}"
            )
        if profile.zap_recommended:
            _console_print(
                "   ZAP baseline: provide --zap-baseline <url> for authorized DAST"
            )
        _console_print()

    external_plan = build_external_scan_plan(
        languages,
        external_mode=external_mode,
        force_trivy=run_trivy,
        force_bandit=force_bandit,
        force_ruff=force_ruff,
        force_semgrep=force_semgrep,
        zap_baseline_url=zap_baseline_url,
        force_zap=force_zap,
        tool_available=_external_tool_available,
    )
    _print_external_auto_skips(external_plan)

    if external_plan.trivy.should_run:
        _console_print("🔎 Trivy FS enabled: vuln, secret, misconfig\n")
        try:
            findings.extend(_run_trivy_fs(scan_path))
        except RuntimeError as exc:
            _console_print(f"❌ Error: {exc}", file=sys.stderr)
            _console_print(
                "💡 Hint: Ensure Trivy is installed and running correctly, or run without --trivy.",
                file=sys.stderr,
            )
            return 1

    if external_plan.bandit.should_run:
        _console_print("🐍 Bandit enabled: Python SAST\n")
        try:
            findings.extend(_run_bandit_scan(scan_path))
        except RuntimeError as exc:
            if external_plan.bandit.auto_selected and not external_plan.bandit.forced:
                _console_print(f"⚠️  Skipping Bandit auto integration: {exc}\n")
            else:
                _console_print(f"❌ Error: {exc}", file=sys.stderr)
                _console_print(
                    f"💡 Hint: {external_plan.bandit.hint}",
                    file=sys.stderr,
                )
                return 1

    if external_plan.ruff.should_run:
        _console_print("🐍 Ruff security rules enabled: select S\n")
        try:
            findings.extend(_run_ruff_security_scan(scan_path))
        except RuntimeError as exc:
            if external_plan.ruff.auto_selected and not external_plan.ruff.forced:
                _console_print(f"⚠️  Skipping Ruff auto integration: {exc}\n")
            else:
                _console_print(f"❌ Error: {exc}", file=sys.stderr)
                _console_print(
                    f"💡 Hint: {external_plan.ruff.hint}",
                    file=sys.stderr,
                )
                return 1

    if external_plan.semgrep.should_run:
        _console_print(f"🔎 Semgrep enabled: config {semgrep_config}\n")
        try:
            findings.extend(_run_semgrep_scan(scan_path, semgrep_config))
        except RuntimeError as exc:
            if external_plan.semgrep.auto_selected and not external_plan.semgrep.forced:
                _console_print(f"⚠️  Skipping Semgrep auto integration: {exc}\n")
            else:
                _console_print(f"❌ Error: {exc}", file=sys.stderr)
                _console_print(
                    f"💡 Hint: {external_plan.semgrep.hint}",
                    file=sys.stderr,
                )
                return 1

    if external_plan.zap.should_run:
        _console_print(f"🌐 OWASP ZAP baseline enabled: {zap_baseline_url}\n")
        try:
            findings.extend(_run_zap_baseline(zap_baseline_url))
        except RuntimeError as exc:
            if external_plan.zap.auto_selected and not external_plan.zap.forced:
                _console_print(f"⚠️  Skipping ZAP auto integration: {exc}\n")
            else:
                _console_print(f"❌ Error: {exc}", file=sys.stderr)
                _console_print(
                    f"💡 Hint: {external_plan.zap.hint}",
                    file=sys.stderr,
                )
                return 1

    if findings_json:
        try:
            _write_findings_json(findings, Path(findings_json))
        except RuntimeError as exc:
            _console_print(f"❌ Error: {exc}", file=sys.stderr)
            _console_print(
                "💡 Hint: Check the output path and directory permissions.",
                file=sys.stderr,
            )
            return 1

    sarif_path = getattr(args, "sarif", None)
    if sarif_path:
        try:
            _write_sarif(findings, Path(sarif_path))
        except RuntimeError as exc:
            _console_print(f"❌ Error: {exc}", file=sys.stderr)
            _console_print(
                "💡 Hint: Check the output path and directory permissions.",
                file=sys.stderr,
            )
            return 1

    push_url = getattr(args, "push", None)
    if push_url:
        _push_findings(push_url, findings)

    _print_scan_results(findings, files_scanned)
    if files_scanned == 0:
        return 1

    # Optional .appguardrail.json tunes the gate (fail_on threshold, rule excludes).
    config_dir = scan_path if scan_path.is_dir() else scan_path.parent
    try:
        config = load_config([config_dir, Path.cwd()])
    except RuntimeError as exc:
        _console_print(f"❌ Error: {exc}", file=sys.stderr)
        _console_print(
            "💡 Hint: Check configuration syntax or file permissions.",
            file=sys.stderr,
        )
        return 1
    if config.get("_path"):
        notes = []
        if config.get("fail_on"):
            notes.append(f"fail_on={config['fail_on']}")
        if config.get("exclude_rules"):
            count = len(config["exclude_rules"])
            s_suffix = "s" if count != 1 else ""
            notes.append(f"{count} rule{s_suffix} excluded")
        _console_print(
            f"⚙️  Config {config['_path']}" + (f": {', '.join(notes)}" if notes else "")
        )

    blocking = config.get("blocking_severities")
    excluded = config.get("exclude_rules") or set()

    def _gates(finding):
        if finding.get("rule_id") in excluded:
            return False
        return core_is_deploy_blocking(finding, blocking)

    return 1 if any(_gates(f) for f in findings) else 0


def _write_findings_json(findings, output_path: Path):
    """Write normalized findings JSON for report builders and dashboards."""
    normalized = normalize_findings(findings)
    payload = {
        "schema": "appguardrail.findings.v1",
        "findings": list(normalized),
    }
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise RuntimeError(f"Cannot write findings JSON: {output_path}") from exc
    _console_print(f"🧾 Findings JSON written: {output_path}")


def _is_safe_url(url: str) -> bool:
    import ipaddress
    import socket
    import urllib.parse

    if not isinstance(url, str):
        return False

    try:
        parsed = urllib.parse.urlparse(
            url
        )  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    except ValueError:
        return False

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False

    host = (parsed.hostname or "").lower()
    raw = host.split("%", 1)[0].strip("[]")

    def is_bad_ip(ip) -> bool:
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped:
            ip = mapped
        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_multicast
            or getattr(ip, "is_reserved", False)
            or not getattr(ip, "is_global", True)
        )

    try:
        ip = ipaddress.ip_address(raw)
        if is_bad_ip(ip):
            return False
    except ValueError:
        # Non-IP hostnames are expected; validate resolved addresses below.
        pass

    try:
        resolved = socket.getaddrinfo(raw, None)
        for entry in resolved:
            ip_str = entry[4][0].split("%", 1)[0]
            ip = ipaddress.ip_address(ip_str)
            if is_bad_ip(ip):
                return False
    except socket.gaierror:
        # Ignore DNS resolution failures. We just want to prevent known internal IPs.
        # This allows dummy domains in tests like `hook.example`.
        pass
    except ValueError:
        return False

    return True


def _push_findings(url, findings):
    """POST normalized findings through DNS-pinned public HTTPS."""
    import urllib.parse

    api_key = os.environ.get("APPGUARDRAIL_API_KEY", "")
    if not api_key:
        _console_print(
            "⚠️  --push set but APPGUARDRAIL_API_KEY is empty; skipping push.",
            file=sys.stderr,
        )
        return
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except (TypeError, ValueError):
        parsed = None
        hostname = None
    if (
        parsed is None
        or parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        _console_print(
            "⚠️  --push URL must be a public HTTPS URL without credentials, "
            "query, or fragment; skipping push.",
            file=sys.stderr,
        )
        return

    base_path = parsed.path.rstrip("/")
    endpoint_path = f"{base_path}/api/v1/scans" if base_path else "/api/v1/scans"
    endpoint = urllib.parse.urlunsplit(
        ("https", parsed.netloc, endpoint_path, "", "")
    )
    payload = {
        "findings": list(normalize_findings(findings)),
        "repo": os.environ.get("GITHUB_REPOSITORY"),
        "commit": os.environ.get("GITHUB_SHA"),
    }
    try:
        response = post_json_pinned_https(
            endpoint,
            payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            timeout=15,
        )
    except DestinationValidationError:
        _console_print(
            "⚠️  --push URL must be a public HTTPS URL without credentials, "
            "query, or fragment; skipping push.",
            file=sys.stderr,
        )
        return
    except PinnedHTTPSFailure:
        _console_print(
            "⚠️  Control-plane push failed; scan still completed.",
            file=sys.stderr,
        )
        return

    if not 200 <= response.status < 300:
        _console_print(
            f"⚠️  Control-plane push failed ({response.status}); scan still completed.",
            file=sys.stderr,
        )
        return
    try:
        body = json.loads(response.body or b"{}")
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _console_print(
            "⚠️  Control-plane push returned an invalid response; scan still completed.",
            file=sys.stderr,
        )
        return
    if not isinstance(body, dict):
        _console_print(
            "⚠️  Control-plane push returned an invalid response; scan still completed.",
            file=sys.stderr,
        )
        return

    scan_id = body.get("id")
    new_blocking = body.get("new_blocking", 0)
    if (
        not isinstance(scan_id, int)
        or isinstance(scan_id, bool)
        or scan_id <= 0
        or not isinstance(new_blocking, int)
        or isinstance(new_blocking, bool)
        or new_blocking < 0
    ):
        _console_print(
            "⚠️  Control-plane push returned an invalid response; scan still completed.",
            file=sys.stderr,
        )
        return

    extra = f", {new_blocking} newly deploy-blocking" if new_blocking else ""
    _console_print(f"📡 Pushed scan #{scan_id} to control plane{extra}.")


def _write_sarif(findings, output_path: Path):
    """Write SARIF 2.1.0 for GitHub code scanning and other SARIF consumers."""
    from appguardrail_core.sarif import findings_to_sarif

    log = findings_to_sarif(findings, tool_version=__version__)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        raise RuntimeError(f"Cannot write SARIF: {output_path}") from exc
    _console_print(f"🛡️  SARIF written: {output_path}")


def cmd_fix(args):
    """Apply safe, deterministic auto-fixes (dry-run by default)."""
    import difflib

    from appguardrail_core.autofix import apply_safe_fixes, fixable_extensions

    base = Path(getattr(args, "path", ".") or ".")
    if not base.exists():
        _console_print(f"❌ Error: Path not found: {base}", file=sys.stderr)
        _console_print(
            "💡 Hint: Check if the path is correct or if you are in the right directory.",
            file=sys.stderr,
        )
        return 1

    apply = getattr(args, "apply", False)
    exts = fixable_extensions()
    files = [base] if base.is_file() else _collect_files(base)

    total_fixes = 0
    changed_files = 0
    for f in files:
        if f.suffix.lower() not in exts:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        new_text, count = apply_safe_fixes(text, f.suffix)
        if count == 0:
            continue
        total_fixes += count
        changed_files += 1
        if apply:
            try:
                f.write_text(new_text, encoding="utf-8")
                s_suffix = "s" if count != 1 else ""
                _console_print(f"✅ Fixed {count} issue{s_suffix} in {f}")
            except OSError as exc:
                _console_print(f"❌ Error: Could not write {f}: {exc}", file=sys.stderr)
                return 1
        else:
            sys.stdout.writelines(
                difflib.unified_diff(
                    text.splitlines(True),
                    new_text.splitlines(True),
                    fromfile=str(f),
                    tofile=f"{f} (fixed)",
                )
            )

    if total_fixes == 0:
        _console_print("✨ No safe auto-fixes to apply.")
        return 0
    if apply:
        fix_s = "es" if total_fixes != 1 else ""
        file_s = "s" if changed_files != 1 else ""
        _console_print(
            f"\n🔧 Applied {total_fixes} safe fix{fix_s} across {changed_files} file{file_s}."
        )
    else:
        fix_s = "es" if total_fixes != 1 else ""
        file_s = "s" if changed_files != 1 else ""
        _console_print(
            f"\n🔧 {total_fixes} safe fix{fix_s} available in {changed_files} file{file_s}. "
            "Re-run with --apply to write them."
        )
        _console_print(
            "   Other findings need review — see 'appguardrail report fix-pack'."
        )
    return 0


def cmd_monitor(args):
    """Install a GitHub Actions workflow that runs AppGuardrail on changes."""
    project_root = Path(".").resolve()
    workflow_file = project_root / ".github" / "workflows" / "appguardrail-monitor.yml"

    if not workflow_file.resolve().is_relative_to(project_root):
        _console_print(
            f"❌ Error: Monitor workflow path {workflow_file} escapes the project root. Aborting.",
            file=sys.stderr,
        )
        _console_print(
            "💡 Hint: Ensure .github/workflows and its symlinks stay inside the repository.",
            file=sys.stderr,
        )
        return 1

    workflow_file.parent.mkdir(parents=True, exist_ok=True)
    if workflow_file.is_symlink():
        workflow_file.unlink()
    workflow_file.write_text(MONITOR_WORKFLOW)

    _console_print("\n✅ AppGuardrail monitor workflow installed!\n")
    _console_print(f"Created/updated: {workflow_file.relative_to(project_root)}")
    _console_print()
    _console_print(
        "This workflow runs `appguardrail scan .` on pull requests, pushes, and manual dispatches."
    )
    return 0


def cmd_report(args):
    """Generate markdown reports from normalized AppGuardrail findings JSON."""
    report_type = getattr(args, "report_type", None)
    if report_type not in supported_report_types():
        _console_print(
            f"❌ Error: Unsupported report type: {report_type}", file=sys.stderr
        )
        _console_print(
            "💡 Hint: Supported report types are: "
            + ", ".join(supported_report_types()),
            file=sys.stderr,
        )
        return 1

    try:
        findings = _load_findings_json(Path(getattr(args, "findings")))
    except (TypeError, RuntimeError) as exc:
        _console_print(f"❌ Error: {exc}", file=sys.stderr)
        _console_print(
            "💡 Hint: Provide a JSON array or an object with a `findings` array.",
            file=sys.stderr,
        )
        return 1

    context = ReportContext(
        app_name=getattr(args, "app_name", None) or "AppGuardrail scan target",
        repository=getattr(args, "repository", None) or "n/a",
        commit=getattr(args, "commit", None) or "n/a",
        generated_at=getattr(args, "generated_at", None) or "",
        scan_command=getattr(args, "scan_command", None) or "appguardrail scan .",
        scope=getattr(args, "scope", None)
        or "Application source, configuration, and security workflow evidence.",
        client_name=getattr(args, "client_name", None) or "n/a",
        reviewer=getattr(args, "reviewer", None) or "AppGuardrail",
        engagement_type=getattr(args, "engagement_type", None) or "Pre-launch review",
        based_on=getattr(args, "based_on", None) or "AppGuardrail findings JSON",
    )
    report = render_report(report_type, findings, context)

    output_path = getattr(args, "out", None)
    if output_path:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(report, encoding="utf-8")
        _console_print(f"✅ {REPORT_TYPE_LABELS[report_type]} written: {target}")
    else:
        _console_print(report, end="")
    return 0


def cmd_org_bundle(args):
    """Generate an organization buyer evidence bundle from GitHub state."""
    owner = getattr(args, "owner", None) or "ContextualWisdomLab"
    bundle_dir = Path(
        getattr(args, "bundle_dir", None) or "appguardrail-buyer-evidence"
    )
    repos_json = getattr(args, "repos_json", None)
    prs_json = getattr(args, "prs_json", None)
    prs_repository = getattr(args, "prs_repository", None)
    per_repo_pr_limit = getattr(args, "per_repo_pr_limit", 100)
    active_repository_target = getattr(args, "active_repository_target", 20)

    try:
        repos = load_org_json(repos_json) if repos_json else gh_repo_list(owner)
        collection_warnings: list[str] = []
        if prs_json:
            prs = load_org_json(prs_json)
        else:
            prs, collection_warnings = gh_pr_list(owner, repos, per_repo_pr_limit)
        if prs_repository:
            prs = annotate_missing_pr_repositories(prs, prs_repository)
        generated_at, report, evidence_payload, inventory, pr_summary = (
            render_org_evidence(
                repos,
                prs,
                active_repository_target=active_repository_target,
                generated_at=getattr(args, "generated_at", None),
            )
        )
        manifest = write_bundle(
            bundle_dir,
            report=report,
            evidence_payload=evidence_payload,
            inventory=inventory,
            pr_summary=pr_summary,
            generated_at=generated_at,
            owner=owner,
            repos_source=repos_json,
            prs_source=prs_json,
            prs_repository_override=prs_repository,
            per_repo_pr_limit=per_repo_pr_limit,
            active_repository_target=active_repository_target,
            collection_warnings=collection_warnings,
        )
    except OrgBundleError as exc:
        _console_print(f"❌ Error: {exc}", file=sys.stderr)
        _console_print(
            "💡 Hint: Authenticate `gh` or provide --repos-json and --prs-json.",
            file=sys.stderr,
        )
        return 1
    except subprocess.CalledProcessError as exc:
        _console_print(
            f"❌ Error: GitHub command failed: {gh_error_message(exc)}", file=sys.stderr
        )
        _console_print(
            "💡 Hint: Retry later or provide --repos-json and --prs-json.",
            file=sys.stderr,
        )
        return 1

    summary = manifest["summary"]
    _console_print(f"\n✅ Buyer evidence bundle written: {bundle_dir}\n")
    _console_print("Files:")
    _console_print("  - org-readiness.md")
    _console_print("  - buyer-evidence.json")
    _console_print("  - manifest.json")
    _console_print("  - README.md")
    _console_print()
    _console_print(f"Open PRs analyzed: {summary['open_pull_requests']}")
    _console_print(f"Buyer evidence status: {summary['buyer_evidence_status']}")
    if manifest["collection_warnings"]:
        _console_print(f"Collection warnings: {len(manifest['collection_warnings'])}")
    return 0


def _load_findings_json(path: Path):
    """Load a findings array from a JSON file or wrapped JSON object."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"Cannot read findings JSON: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Findings JSON is invalid: {exc}") from exc

    if isinstance(data, dict):
        data = data.get("findings")
    if not isinstance(data, list):
        raise RuntimeError("Findings JSON must be an array or contain `findings`.")
    if not all(isinstance(item, dict) for item in data):
        raise RuntimeError("Every finding must be a JSON object.")
    return data


def cmd_hook(args):
    """Install a pre-commit hook to block commits with vulnerabilities."""
    project_root = Path(".").resolve()
    git_dir = project_root / ".git"
    run_codegraph = getattr(args, "codegraph", False)

    if not git_dir.is_dir():
        _console_print("❌ Error: Not a git repository.", file=sys.stderr)
        _console_print(
            "💡 Hint: Run 'git init' first to initialize a git repository.",
            file=sys.stderr,
        )
        return 1

    hooks_dir = git_dir / "hooks"
    # SECURITY: Prevent Arbitrary File Write via symlink path traversal
    if not hooks_dir.resolve().is_relative_to(project_root):
        _console_print(
            f"❌ Error: Target path {hooks_dir} escapes the project root. Aborting.",
            file=sys.stderr,
        )
        _console_print(
            "💡 Hint: Ensure your .git directory or hooks path is contained within the project.",
            file=sys.stderr,
        )
        return 1

    hooks_dir.mkdir(parents=True, exist_ok=True)
    pre_commit_file = hooks_dir / "pre-commit"

    if pre_commit_file.is_symlink():
        pre_commit_file.unlink()

    cli_path = shlex.quote(str(Path(__file__).resolve()))
    scan_flags = " --codegraph" if run_codegraph else ""
    hook_content = f"""#!/bin/sh
# AppGuardrail Pre-Commit Hook

echo "\\n🔍 Running AppGuardrail scan..."
APPGUARDRAIL_CLI={cli_path}

if command -v appguardrail >/dev/null 2>&1; then
    appguardrail scan{scan_flags} .
elif [ -f "$APPGUARDRAIL_CLI" ]; then
    python3 "$APPGUARDRAIL_CLI" scan{scan_flags} .
else
    echo "\\n❌ Error: AppGuardrail CLI not found."
    echo "Install appguardrail or reinstall this hook from a trusted AppGuardrail checkout."
    exit 127
fi

if [ $? -ne 0 ]; then
    echo "\\n❌ Error: AppGuardrail scan failed! Critical or high vulnerabilities found."
    echo "Please fix the issues or use '--no-verify' to bypass (not recommended)."
    exit 1
fi

echo "✅ AppGuardrail scan passed."
"""

    pre_commit_file.write_text(hook_content)
    pre_commit_file.chmod(pre_commit_file.stat().st_mode | stat.S_IEXEC)

    _console_print(
        "\n✅ AppGuardrail pre-commit hook installed successfully at .git/hooks/pre-commit!\n"
    )
    hook_scan_command = f"appguardrail scan{scan_flags} ."
    _console_print(
        f"This will run '{hook_scan_command}' before every commit and block commits if vulnerabilities are found."
    )
    if run_codegraph:
        _console_print("CodeGraph mode is enabled for this hook.")
    return 0


# ⚡ Bolt: Cache applicable rules per file extension to avoid redundant list
# comprehensions and pre-extract the finditer method used in the tight loop.
_RULES_CACHE = {}
_LAST_SCAN_RULES_ID = None


def _get_applicable_rules(ext: str):
    """Return cached scanner rules that apply to a file extension."""
    global _LAST_SCAN_RULES_ID, _RULES_CACHE
    current_id = id(SCAN_RULES)
    if _LAST_SCAN_RULES_ID != current_id:
        _RULES_CACHE.clear()
        _LAST_SCAN_RULES_ID = current_id

    if ext not in _RULES_CACHE:
        _RULES_CACHE[ext] = [
            (
                rule["id"],
                rule["severity"],
                rule["message"],
                rule["pattern"].finditer,
                tuple(rule.get("include_paths") or ()),
                tuple(rule.get("exclude_paths") or ()),
                tuple(rule.get("required_substrings") or ()),
            )
            for rule in SCAN_RULES
            if not rule["extensions"] or ext in rule["extensions"]
        ]
    return _RULES_CACHE[ext]


def _path_matches_glob(path: str, pattern: str) -> bool:
    """Match a normalized relative path against AppGuardrail rule globs."""
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    if pattern.startswith("./"):
        pattern = pattern[2:]
    if fnmatch.fnmatch(path, pattern):
        return True
    if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]):
        return True
    return False


@functools.lru_cache(maxsize=2048)
def _path_allowed_by_rule_cached(
    path: str, include_paths: tuple, exclude_paths: tuple
) -> bool:
    """Return whether a path passes optional YAML include/exclude filters (cached)."""
    if include_paths and not any(
        _path_matches_glob(path, glob) for glob in include_paths
    ):
        return False
    if exclude_paths and any(_path_matches_glob(path, glob) for glob in exclude_paths):
        return False
    return True


def _path_allowed_by_rule(path: str, include_paths, exclude_paths) -> bool:
    """Return whether a path passes optional YAML include/exclude filters."""
    return _path_allowed_by_rule_cached(
        path,
        tuple(include_paths) if include_paths else (),
        tuple(exclude_paths) if exclude_paths else (),
    )


def _collect_files(base_path: Path):
    """Collect all scannable files, skipping unwanted directories."""
    # ⚡ Bolt: Optimize file traversal using os.scandir and os.path.splitext
    # This avoids expensive stat() calls by using cached directory attributes
    # and defers Path object creation until a valid file is found.
    # Impact: Significantly faster file discovery in large codebases.
    stack = [str(base_path)]
    while stack:
        current_dir = stack.pop()
        dirs = []
        try:
            with os.scandir(current_dir) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in SKIP_DIRS and (
                                not entry.name.startswith(".")
                                or entry.name in SECURITY_HIDDEN_DIRS
                            ):
                                dirs.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            idx = entry.name.rfind(".")
                            ext = (
                                entry.name[idx:]
                                if idx > 0 and entry.name[:idx].replace(".", "")
                                else ""
                            )
                            if ext.lower() not in SKIP_EXTENSIONS:
                                yield Path(entry.path)
                    except (OSError, PermissionError):
                        continue
                stack.extend(reversed(dirs))
        except (OSError, PermissionError):
            pass


def _sanitize_terminal_output(text: str) -> str:
    """
    SECURITY: Prevent Terminal Output Injection / ANSI escape sequence injection
    that could hide scanner findings by removing or escaping non-printable characters.
    """
    if not isinstance(text, str):
        return text
    # ⚡ Bolt: Fast path for strings that don't need escaping
    if not text or text.replace("\t", "").isprintable():
        return text
    return "".join(c if c.isprintable() or c == "\t" else repr(c)[1:-1] for c in text)


_SENSITIVE_RULE_TOKENS = (
    "secret",
    "password",
    "token",
    "jwt",
    "database-url",
    "db-url",
    "dsn",
    "credential",
    "stripe",
    "openai",
    "supabase-service-role",
    "aws",
    "private-key",
    "anthropic",
    "google",
    "github",
    "api-key",
    "slack",
    "twilio",
    "sendgrid",
    "npm",
    "pypi",
)
_REDACTED_SENSITIVE_SNIPPET = "[REDACTED: sensitive match suppressed]"


def _is_sensitive_rule(rule_id: str) -> bool:
    """Return whether a rule id is likely to expose secret material."""
    lowered = (rule_id or "").lower()
    return any(token in lowered for token in _SENSITIVE_RULE_TOKENS)


def _safe_snippet(rule_id: str, snippet: str, category: str) -> str:
    """Redact sensitive snippets and sanitize non-sensitive terminal output."""
    if category == "secrets" or _is_sensitive_rule(rule_id):
        return _REDACTED_SENSITIVE_SNIPPET
    return _sanitize_terminal_output(snippet)


def _finding_context(file_path: str, snippet: str = "") -> str:
    """Classify a finding path as app code, docs, tests, examples, or fixtures."""
    path = (file_path or "").replace("\\", "/").lstrip("./")
    snippet = (snippet or "").strip()
    if path == "README.md" or path.startswith(("docs/", "checklists/", "prompts/")):
        return "doc"
    if path.startswith("tests/") or "/tests/" in path:
        return "test"
    if path.startswith("examples/"):
        return "example"
    if path.startswith("scanner/rules/"):
        return "scanner-fixture"
    if path == "scanner/cli/appguardrail.py" and (
        snippet.startswith(('"id":', '"message":', '"pattern":', "r'", 'r"'))
        or "TODO comments that defer" in snippet
    ):
        return "scanner-fixture"
    return "app-code"


def _finding_category(rule_id: str) -> str:
    """Map a rule id to a stable finding category."""
    rule = (rule_id or "").lower()
    if "cve-" in rule or "vulnerability" in rule:
        return "dependency"
    if "jwt-decode" in rule:
        return "authz"
    if any(token in rule for token in _SENSITIVE_RULE_TOKENS if token not in ("stripe",)):
        return "secrets"
    if "stripe" in rule or "webhook" in rule:
        return "payment"
    if "firebase" in rule or "supabase" in rule or "storage" in rule:
        return "storage"
    if any(
        token in rule for token in ("auth", "session", "admin", "route-without-auth")
    ):
        return "authz"
    if any(
        token in rule
        for token in ("eval", "sql", "command", "subprocess", "path-traversal")
    ):
        return "injection"
    return "misconfig"


def _confidence(rule_id: str) -> str:
    """Return a conservative confidence label for a rule id."""
    return "medium" if "todo" in (rule_id or "").lower() else "high"


def _build_finding(
    source, rule_id, severity, message, file, line, snippet, category=None
):
    """Build the normalized finding dictionary emitted by scan providers."""
    context = _finding_context(file, snippet)
    category = category or _finding_category(rule_id)
    metadata = build_rule_metadata(
        rule_id,
        severity,
        message,
        category=category,
        source=source,
    )
    finding = {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": file,
        "line": line,
        "snippet": _safe_snippet(rule_id, snippet, category),
        "source": source,
        "category": category,
        "confidence": _confidence(rule_id),
        "context": context,
        "fix_prompt": f"Fix {rule_id}: {message}",
        "verification": f"Re-run `appguardrail scan` and verify {file}:{line} no longer reports this finding.",
    }
    finding.update(metadata.as_dict())
    return finding


def _is_deploy_blocking(finding: dict) -> bool:
    """Return whether a finding should fail the deploy gate."""
    return core_is_deploy_blocking(finding)


_TRIVY_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "WARNING",
    "LOW": "INFO",
    "UNKNOWN": "INFO",
}


def _trivy_severity(severity: str) -> str:
    """Translate Trivy severity values into AppGuardrail severities."""
    return _TRIVY_SEVERITY_MAP.get((severity or "UNKNOWN").upper(), "INFO")


def _trivy_line(item: dict) -> int:
    """Extract the best source line from a Trivy result item."""
    metadata = item.get("CauseMetadata") or {}
    return item.get("StartLine") or metadata.get("StartLine") or 1


def _trivy_target(
    target: str, base_path: Path, base_path_is_dir: bool | None = None
) -> str:
    """Normalize a Trivy target path relative to the scan base when possible."""
    if not target:
        return base_path.as_posix()

    # ⚡ Bolt: Use string slicing instead of Path.relative_to() to prevent heavy
    # pathlib initialization and resolution overhead during findings normalization.
    target_posix = target.replace("\\", "/")
    # Determine if it's an absolute path
    is_absolute = target_posix.startswith("/") or (
        len(target_posix) > 2 and target_posix[1] == ":" and target_posix[2] == "/"
    )

    if is_absolute:
        if base_path_is_dir is None:
            base_path_is_dir = base_path.is_dir()
        root = base_path if base_path_is_dir else base_path.parent
        root_str = root.as_posix()

        if target_posix == root_str:
            return "."

        root_prefix = root_str + "/" if not root_str.endswith("/") else root_str
        if target_posix.startswith(root_prefix):
            return target_posix[len(root_prefix) :]

    return Path(target).as_posix()


def _trivy_findings(report: dict, base_path: Path):
    """Convert a Trivy JSON report into AppGuardrail finding dictionaries."""
    findings = []

    # ⚡ Bolt: Cache base_path.is_dir() outside the loop to avoid stat() syscalls inside
    base_path_is_dir = base_path.is_dir()

    for result in report.get("Results") or []:
        target = _sanitize_terminal_output(
            _trivy_target(result.get("Target", ""), base_path, base_path_is_dir)
        )

        for vuln in result.get("Vulnerabilities") or []:
            fixed = vuln.get("FixedVersion") or "no fixed version reported"
            findings.append(
                _build_finding(
                    "trivy",
                    f"trivy:{vuln.get('VulnerabilityID', 'vulnerability')}",
                    _trivy_severity(vuln.get("Severity")),
                    f"Trivy vulnerability in {vuln.get('PkgName', 'package')}: {vuln.get('Title') or vuln.get('VulnerabilityID', 'unknown vulnerability')}",
                    target,
                    1,
                    f"{vuln.get('PkgName', 'package')} {vuln.get('InstalledVersion', '')} -> {fixed}".strip(),
                    category="dependency",
                )
            )

        for misconfig in result.get("Misconfigurations") or []:
            findings.append(
                _build_finding(
                    "trivy",
                    f"trivy:{misconfig.get('ID', 'misconfiguration')}",
                    _trivy_severity(misconfig.get("Severity")),
                    f"Trivy misconfiguration: {misconfig.get('Title') or misconfig.get('Message') or misconfig.get('ID', 'misconfiguration')}",
                    target,
                    _trivy_line(misconfig),
                    misconfig.get("Message") or misconfig.get("Description") or "",
                    category="misconfig",
                )
            )

        for secret in result.get("Secrets") or []:
            findings.append(
                _build_finding(
                    "trivy",
                    f"trivy:{secret.get('RuleID', 'secret')}",
                    _trivy_severity(secret.get("Severity")),
                    f"Trivy secret finding: {secret.get('Title') or secret.get('Category') or secret.get('RuleID', 'secret')}",
                    target,
                    _trivy_line(secret),
                    "Trivy secret scanner matched this line; value suppressed.",
                    category="secrets",
                )
            )

    return findings


def _run_trivy_fs(scan_path: Path):
    """Run Trivy filesystem scanning and return normalized findings."""
    trivy = shutil.which("trivy")
    if not trivy:
        raise RuntimeError(
            "trivy executable not found. Install Trivy or run without --trivy."
        )

    try:
        process = subprocess.run(  # noqa: S603 - Trivy path resolved with shutil.which
            [
                trivy,
                "fs",
                "--quiet",
                "--format",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                "--exit-code",
                "0",
                "--no-progress",
                "--skip-version-check",
                str(scan_path),
            ],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Trivy scan timed out.") from exc
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip().splitlines()
        raise RuntimeError("Trivy scan failed" + (f": {detail[-1]}" if detail else "."))

    try:
        report = json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Trivy returned invalid JSON: {exc}") from exc

    return _trivy_findings(report, scan_path)


def _bandit_severity(severity: str) -> str:
    """Translate Bandit severity values into AppGuardrail severities."""
    return _TRIVY_SEVERITY_MAP.get((severity or "LOW").upper(), "INFO")


def _bandit_findings(report: dict, base_path: Path):
    """Convert a Bandit JSON report into AppGuardrail finding dictionaries."""
    findings = []

    # ⚡ Bolt: Cache base_path.is_dir() outside the loop to avoid stat() syscalls inside
    base_path_is_dir = base_path.is_dir()

    for result in report.get("results") or []:
        test_id = result.get("test_id") or "bandit"
        filename = _sanitize_terminal_output(
            _trivy_target(result.get("filename", ""), base_path, base_path_is_dir)
        )
        findings.append(
            _build_finding(
                "bandit",
                f"bandit:{test_id}",
                _bandit_severity(result.get("issue_severity")),
                result.get("issue_text") or result.get("test_name") or test_id,
                filename,
                result.get("line_number") or 1,
                result.get("code") or "",
            )
        )
    return findings


def _run_bandit_scan(scan_path: Path):
    """Run Bandit Python SAST and return normalized findings."""
    bandit = shutil.which("bandit")
    if not bandit:
        raise RuntimeError("bandit executable not found.")

    command = [bandit, "-f", "json", "-q"]
    if scan_path.is_dir():
        command.extend(["-r", str(scan_path)])
    else:
        command.append(str(scan_path))

    try:
        process = subprocess.run(  # noqa: S603 - Bandit path resolved with shutil.which
            command,
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Bandit scan timed out.") from exc

    if process.returncode not in {0, 1}:
        detail = (process.stderr or process.stdout).strip().splitlines()
        raise RuntimeError(
            "Bandit scan failed" + (f": {detail[-1]}" if detail else ".")
        )

    try:
        report = json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Bandit returned invalid JSON: {exc}") from exc

    return _bandit_findings(report, scan_path)


def _ruff_severity(code: str) -> str:
    """Translate Ruff security rule codes into AppGuardrail severities."""
    code = code or ""
    return "WARNING" if code in {"S101", "S104"} else "HIGH"


def _ruff_findings(report: list, base_path: Path):
    """Convert Ruff JSON diagnostics into AppGuardrail finding dictionaries."""
    findings = []

    # ⚡ Bolt: Cache base_path.is_dir() outside the loop to avoid stat() syscalls inside
    base_path_is_dir = base_path.is_dir()

    for item in report or []:
        code = item.get("code") or "ruff"
        location = item.get("location") or {}
        filename = _sanitize_terminal_output(
            _trivy_target(item.get("filename", ""), base_path, base_path_is_dir)
        )
        findings.append(
            _build_finding(
                "ruff",
                f"ruff:{code}",
                _ruff_severity(code),
                item.get("message") or code,
                filename,
                location.get("row") or 1,
                item.get("message") or code,
            )
        )
    return findings


def _run_ruff_security_scan(scan_path: Path):
    """Run Ruff's Bandit-compatible security rules and return findings."""
    ruff = shutil.which("ruff")
    if not ruff:
        raise RuntimeError("ruff executable not found.")

    try:
        process = subprocess.run(  # noqa: S603 - Ruff path resolved with shutil.which
            [
                ruff,
                "check",
                "--select",
                "S",
                "--output-format",
                "json",
                str(scan_path),
            ],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Ruff security scan timed out.") from exc

    if process.returncode not in {0, 1}:
        detail = (process.stderr or process.stdout).strip().splitlines()
        raise RuntimeError(
            "Ruff security scan failed" + (f": {detail[-1]}" if detail else ".")
        )

    try:
        report = json.loads(process.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Ruff returned invalid JSON: {exc}") from exc

    return _ruff_findings(report, scan_path)


_SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "WARNING",
    "INFO": "INFO",
    "INVENTORY": "INFO",
    "EXPERIMENT": "INFO",
}


def _semgrep_severity(severity: str) -> str:
    """Translate Semgrep severity values into AppGuardrail severities."""
    return _SEMGREP_SEVERITY_MAP.get((severity or "INFO").upper(), "INFO")


def _semgrep_findings(report: dict, base_path: Path):
    """Convert Semgrep JSON results into AppGuardrail finding dictionaries."""
    findings = []

    # ⚡ Bolt: Cache base_path.is_dir() outside the loop to avoid stat() syscalls inside
    base_path_is_dir = base_path.is_dir()

    for item in report.get("results") or []:
        extra = item.get("extra") or {}
        start = item.get("start") or {}
        # fmt: off
        path = _sanitize_terminal_output(
            _trivy_target(item.get("path", ""), base_path, base_path_is_dir)
        )
        # fmt: on
        check_id = item.get("check_id") or "semgrep"
        findings.append(
            _build_finding(
                "semgrep",
                f"semgrep:{check_id}",
                _semgrep_severity(extra.get("severity")),
                extra.get("message") or check_id,
                path,
                start.get("line") or 1,
                extra.get("lines") or extra.get("message") or check_id,
            )
        )
    return findings


def _run_semgrep_scan(scan_path: Path, config: str = "auto"):
    """Run Semgrep multi-language SAST and return normalized findings."""
    semgrep = shutil.which("semgrep")
    if not semgrep:
        raise RuntimeError("semgrep executable not found.")

    config = config or "auto"
    try:
        process = subprocess.run(  # noqa: S603 - Semgrep path resolved with shutil.which
            [
                semgrep,
                "scan",
                "--config",
                config,
                "--json",
                str(scan_path),
            ],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Semgrep scan timed out.") from exc

    if process.returncode not in {0, 1}:
        detail = (process.stderr or process.stdout).strip().splitlines()
        raise RuntimeError(
            "Semgrep scan failed" + (f": {detail[-1]}" if detail else ".")
        )

    try:
        report = json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Semgrep returned invalid JSON: {exc}") from exc

    return _semgrep_findings(report, scan_path)


_ZAP_SEVERITY_MAP = {
    "HIGH": "HIGH",
    "MEDIUM": "WARNING",
    "LOW": "INFO",
    "INFORMATIONAL": "INFO",
}


def _zap_severity(risk: str) -> str:
    """Translate ZAP risk text into AppGuardrail severities."""
    risk_text = (risk or "INFO").split()[0].upper()
    return _ZAP_SEVERITY_MAP.get(risk_text, "INFO")


def _zap_findings(report: dict):
    """Convert an OWASP ZAP JSON report into AppGuardrail findings."""
    findings = []
    for site in report.get("site") or []:
        for alert in site.get("alerts") or []:
            instances = alert.get("instances") or [{}]
            for instance in instances:
                uri = instance.get("uri") or site.get("@name") or "zap-baseline"
                findings.append(
                    _build_finding(
                        "zap",
                        f"zap:{alert.get('pluginid', 'alert')}",
                        _zap_severity(alert.get("riskdesc") or alert.get("risk")),
                        alert.get("alert") or alert.get("name") or "ZAP alert",
                        _sanitize_terminal_output(uri),
                        1,
                        instance.get("evidence") or alert.get("desc") or "",
                        category="misconfig",
                    )
                )
    return findings


def _run_zap_baseline(target_url: str):
    """Run OWASP ZAP baseline scan against an explicit URL."""
    if not target_url or not re.match(r"^https?://", target_url):
        raise RuntimeError("--zap-baseline requires an http(s) URL.")
    zap = shutil.which("zap-baseline.py")
    if not zap:
        raise RuntimeError("zap-baseline.py executable not found.")

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "zap-baseline.json"
        try:
            process = subprocess.run(  # noqa: S603 - ZAP path resolved with shutil.which
                [zap, "-t", target_url, "-J", str(report_path), "-I"],
                shell=False,
                capture_output=True,
                text=True,
                check=False,
                timeout=900,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("ZAP baseline scan timed out.") from exc

        if process.returncode not in {0, 1, 2}:
            detail = (process.stderr or process.stdout).strip().splitlines()
            raise RuntimeError(
                "ZAP baseline scan failed" + (f": {detail[-1]}" if detail else ".")
            )

        try:
            report = json.loads(report_path.read_text(encoding="utf-8") or "{}")
        except OSError as exc:
            raise RuntimeError("ZAP baseline did not produce a JSON report.") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"ZAP baseline returned invalid JSON: {exc}") from exc

    return _zap_findings(report)


def _run_codegraph_command(command, cwd: Path, action: str):
    """Run an allowlisted CodeGraph command in a trusted working directory."""
    if not command:
        raise RuntimeError("CodeGraph command cannot be empty.")
    for arg in command:
        if not isinstance(arg, str):
            raise RuntimeError(
                f"CodeGraph command argument must be a string, got {type(arg).__name__}."
            )
        if not arg.isprintable():
            raise RuntimeError(
                "CodeGraph command argument contains control characters."
            )

    executable = Path(command[0]).name.lower()
    allowed_executables = {
        "codegraph",
        "codegraph.bat",
        "codegraph.cmd",
        "codegraph.exe",
        "codegraph.ps1",
    }
    allowed_args = {("sync",), ("init", "-i"), ("status",)}
    if executable not in allowed_executables or tuple(command[1:]) not in allowed_args:
        raise RuntimeError(f"Unsupported CodeGraph {action} command.")

    try:
        process = subprocess.run(  # noqa: S603 - command is checked against allowlist
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"CodeGraph {action} timed out.") from exc
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else "."
        raise RuntimeError(f"CodeGraph {action} failed{suffix}")
    return (process.stdout or "").strip()


def _run_codegraph_index(scan_path: Path):
    """Initialize or sync the CodeGraph index for the scanned path."""
    codegraph = shutil.which("codegraph")
    if not codegraph:
        raise RuntimeError(
            "codegraph executable not found. Install CodeGraph before using --codegraph."
        )

    workdir = scan_path if scan_path.is_dir() else scan_path.parent
    if not workdir.is_dir():
        raise RuntimeError(f"CodeGraph workdir is not a directory: {workdir}")

    codegraph_dir = workdir / ".codegraph"
    if codegraph_dir.exists() and not codegraph_dir.is_dir():
        raise RuntimeError(
            f"CodeGraph path exists but is not a directory: {codegraph_dir}"
        )
    if codegraph_dir.is_dir():
        _run_codegraph_command([codegraph, "sync"], workdir, "sync")
    else:
        _run_codegraph_command([codegraph, "init", "-i"], workdir, "init")

    return _run_codegraph_command([codegraph, "status"], workdir, "status")


def _scan_file(
    file_path: Path,
    base_path: Path,
    *,
    path_context: ScanPathContext | None = None,
):
    """Scan one file using an optional immutable batch path context.

    Direct callers may omit ``path_context`` and retain the historical safe
    fallback. Batch callers should build one context and reuse it for every
    file so root classification and normalized prefix construction happen once.
    """
    findings = []
    context = path_context or build_scan_path_context(base_path)

    # ⚡ Bolt: Optimize stat calls by using os.lstat instead of Path objects
    # Impact: Combines symlink, file type, and size checks into a single stat call
    try:
        st = os.lstat(file_path)
        # SECURITY: Prevent DoS by skipping special system files (e.g. FIFOs, devices)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return findings
        # SECURITY: Prevent OOM by skipping extremely large files
        if st.st_size > 10 * 1024 * 1024:
            return findings
    except (OSError, PermissionError):
        return findings

    ext = file_path.suffix.lower()
    applicable_rules = _get_applicable_rules(ext)

    if not applicable_rules:
        return findings

    # ⚡ Bolt: Defer expensive Pathlib operations (like relative_to) and string
    # sanitization until a match is actually found. This avoids significant overhead
    # for the vast majority of files that have no vulnerabilities.
    rel_path_str = None
    rel_path_for_filters = None
    build_finding = _build_finding

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if not content:
                return findings
            count_newlines = content.count
            find_newline = content.find
            rfind_newline = content.rfind

            for (
                rule_id,
                severity,
                message,
                finditer,
                include_paths,
                exclude_paths,
                required_substrings,
            ) in applicable_rules:
                if required_substrings and not all(
                    substring in content for substring in required_substrings
                ):
                    continue
                if include_paths or exclude_paths:
                    if rel_path_for_filters is None:
                        rel_path_for_filters = _display_path(
                            context.relative_candidate(file_path)
                        )
                    if not _path_allowed_by_rule(
                        rel_path_for_filters, include_paths, exclude_paths
                    ):
                        continue
                # ⚡ Bolt: Progressive line counting for O(N) instead of O(N*M)
                # finditer yields matches in order, allowing us to scan for newlines
                # incrementally from the last known position rather than starting from 0.
                current_line = 1
                current_pos = 0

                for match in finditer(content):
                    if rel_path_str is None:
                        rel_path_str = _sanitize_terminal_output(
                            _display_path(context.relative_candidate(file_path))
                        )

                    start_idx = match.start()

                    if start_idx >= current_pos:
                        current_line += count_newlines("\n", current_pos, start_idx)
                    else:
                        # Fallback for unexpected out-of-order execution, though finditer is ordered
                        current_line = count_newlines("\n", 0, start_idx) + 1
                    current_pos = start_idx
                    line_num = current_line

                    snippet_start = rfind_newline("\n", 0, start_idx) + 1
                    snippet_end = find_newline("\n", start_idx)
                    if snippet_end == -1:
                        snippet_end = len(content)
                    snippet = content[snippet_start:snippet_end].strip()[:120]

                    findings.append(
                        build_finding(
                            "appguardrail-rule",
                            rule_id,
                            severity,
                            message,
                            rel_path_str,
                            line_num,
                            snippet,
                        )
                    )
    except (OSError, PermissionError):
        pass

    return findings


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "INFO": 3}
_SEVERITY_ICONS = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "WARNING": "🟡 WARNING",
    "INFO": "🔵 INFO",
}


def _print_scan_results(findings, files_scanned):
    """Print sorted findings and deploy-gate summary counts."""
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))

    counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
    non_blocking = 0
    for f in findings:
        if f.get("context", "app-code") not in NON_BLOCKING_CONTEXTS:
            counts[f["severity"]] += 1
        elif f.get("context", "app-code") in NON_BLOCKING_CONTEXTS:
            non_blocking += 1
        icon = _SEVERITY_ICONS.get(f["severity"], f["severity"])
        _console_print(f"[{icon}] {f['file']}:{f['line']}")
        _console_print(f"  Rule:    {f['rule_id']}")
        _console_print(
            f"  Details: {f.get('source', 'appguardrail-rule')} | {f.get('category', 'misconfig')} | {f.get('context', 'app-code')}"
        )
        _console_print(f"  Message: {f['message']}")
        _console_print(f"  Code:    {f['snippet']}")
        if f.get("context", "app-code") in NON_BLOCKING_CONTEXTS:
            _console_print("  Gate:    non-blocking context")
        _console_print()

    _console_print("─" * 60)
    files_word = "file" if files_scanned == 1 else "files"
    critical_word = "critical issue" if counts["CRITICAL"] == 1 else "critical issues"
    high_word = "high issue" if counts["HIGH"] == 1 else "high issues"
    warnings_word = "warning" if counts["WARNING"] == 1 else "warnings"
    info_word = "info issue" if counts["INFO"] == 1 else "info issues"

    _console_print(
        f"Scanned {files_scanned} {files_word}  |  Deploy blockers: "
        f"🔴 {counts['CRITICAL']} {critical_word}  "
        f"🟠 {counts['HIGH']} {high_word}  "
        f"🟡 {counts['WARNING']} {warnings_word}  "
        f"🔵 {counts['INFO']} {info_word}"
    )
    if non_blocking:
        finding_word = "finding" if non_blocking == 1 else "findings"
        _console_print(
            f"Non-blocking {finding_word} in docs/tests/examples/fixtures: {non_blocking}"
        )

    if files_scanned == 0:
        _console_print("\n⚠️  No files were scanned. Are you in the right directory?")
    elif counts["CRITICAL"] > 0:
        issue_word = "issue" if counts["CRITICAL"] == 1 else "issues"
        _console_print(
            _format_msg(
                f"\n❌ Error: Critical {issue_word} found. Fix before deploying."
            )
        )
    elif counts["HIGH"] > 0:
        issue_word = "issue" if counts["HIGH"] == 1 else "issues"
        _console_print(
            _format_msg(
                f"\n⚠️  High-severity {issue_word} found. Review before deploying."
            )
        )
    elif not findings:
        _console_print(_format_msg("\n✅ No issues found in this scan."))
    else:
        _console_print(
            _format_msg("\n✅ No deploy-blocking critical or high issues found.")
        )

    if findings:
        these_word = "this issue" if len(findings) == 1 else "these issues"
        _console_print(
            _format_msg(
                f"\n💡 Hint: Run 'appguardrail review' to get an AI prompt for fixing {these_word}."
            )
        )
    _console_print()


def cmd_review(args):
    """Generate a security review prompt for the given stack."""
    stack = getattr(args, "stack", None)
    db = getattr(args, "db", None)
    payments = getattr(args, "payments", None)

    prompt = REVIEW_PROMPT_BASE

    if stack and "nextjs" in stack:
        prompt += REVIEW_PROMPT_NEXTJS
    if db == "supabase" or (stack and "supabase" in stack):
        prompt += REVIEW_PROMPT_SUPABASE
    if db == "firebase" or (stack and "firebase" in stack):
        prompt += REVIEW_PROMPT_FIREBASE
    if payments == "stripe":
        prompt += REVIEW_PROMPT_STRIPE

    prompt += REVIEW_PROMPT_FOOTER

    _console_print("\n" + "═" * 60)
    _console_print("  AppGuardrail — Copy this prompt into your AI coding assistant")
    _console_print("═" * 60 + "\n")
    _console_print(prompt)
    _console_print("═" * 60 + "\n")
    _console_print("💡 Hint: Tips:")
    _console_print("  - Paste this into Claude Code, Cursor, or any AI assistant")
    _console_print(
        "  - Include relevant files as context (API routes, DB schema, etc.)"
    )
    _console_print(
        "  - Run 'appguardrail scan .' first to identify specific files to review"
    )
    _console_print()


def dashboard_index_path():
    """Locate the static dashboard entry point shipped inside the package.

    Works both from a source checkout and a pip-installed wheel because the
    asset lives under ``scanner/dashboard/`` and is resolved via
    importlib.resources.
    """
    return Path(str(resources.files("scanner").joinpath("dashboard", "index.html")))


def dashboard_tokens_path():
    """Locate the canonical design-token source shipped with the package."""
    return Path(str(resources.files("scanner").joinpath("dashboard", "tokens.json")))


# Map canonical color token names (tokens.json) to the CSS custom properties the
# dashboard stylesheet consumes. Scales (radius/space/size) are emitted
# generically. Keeps tokens.json the single source of truth.
_COLOR_CSS_VARS = {
    "background": "--bg",
    "surface": "--surface",
    "text-default": "--text",
    "text-muted": "--muted",
    "border": "--border",
    "divider": "--divider",
    "primary": "--primary",
    "on-primary": "--on-primary",
    "critical": "--crit",
    "high": "--high",
    "warning": "--warn",
    "info": "--info",
}


def render_tokens_css(tokens: dict) -> str:
    """Render CSS custom properties from the design-token source dict.

    Emits colors (mapped to the dashboard's var names), the radius/space/size
    scales (as ``--radius-*`` / ``--space-*`` / ``--size-*``, plus a ``--radius``
    alias for the default card radius), and a ``@media (prefers-contrast: more)``
    color override so the dashboard adapts to the user's contrast preference.
    """
    color = tokens.get("color") or {}
    radius = tokens.get("radius") or {}
    space = tokens.get("space") or {}
    size = tokens.get("size") or {}

    lines = [":root{"]
    for key, css_var in _COLOR_CSS_VARS.items():
        entry = color.get(key)
        if isinstance(entry, dict) and "value" in entry:
            lines.append(f"  {css_var}: {entry['value']};")
    # radius scale + --radius alias (default card radius)
    for key, entry in radius.items():
        if isinstance(entry, dict) and "value" in entry:
            lines.append(f"  --radius-{key}: {entry['value']};")
    alias = radius.get("card-alias")
    if alias and isinstance(radius.get(alias), dict):
        lines.append(f"  --radius: {radius[alias]['value']};")
    for key, entry in space.items():
        if isinstance(entry, dict) and "value" in entry:
            lines.append(f"  --space-{key}: {entry['value']};")
    for key, entry in size.items():
        if isinstance(entry, dict) and "value" in entry:
            lines.append(f"  --size-{key}: {entry['value']};")
    lines.append("}")

    hc = tokens.get("high-contrast") or {}
    hc_lines = [
        f"    {css_var}: {hc[key]['value']};"
        for key, css_var in _COLOR_CSS_VARS.items()
        if isinstance(hc.get(key), dict) and "value" in hc[key]
    ]
    if hc_lines:
        lines.append("@media (prefers-contrast: more){")
        lines.append("  :root{")
        lines.extend(hc_lines)
        lines.append("  }")
        lines.append("}")

    return "\n".join(lines) + "\n"


def make_dashboard_server(host, port, index_bytes, findings_path, tokens_css_bytes=b""):
    """Build (but do not start) an HTTP server that serves the dashboard.

    Serves the dashboard HTML at ``/``, the design tokens at ``/tokens.css``,
    and the findings file at ``/findings.json`` so the page loads regardless
    of the caller's cwd.
    """
    import http.server

    findings_path = Path(findings_path)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, body, content_type):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html", "/dashboard/", "/dashboard/index.html"):
                self._send(index_bytes, "text/html; charset=utf-8")
            elif path in ("/tokens.css", "/dashboard/tokens.css"):
                self._send(tokens_css_bytes, "text/css; charset=utf-8")
            elif path in ("/findings.json", "/reports/findings.json"):
                if findings_path.is_file():
                    self._send(findings_path.read_bytes(), "application/json")
                else:
                    self.send_error(404, "findings.json not found")
            else:
                self.send_error(404)

        def log_message(self, format, *args):  # keep the console quiet
            """Suppress default logging."""
            return None

    return http.server.HTTPServer((host, port), _Handler)


def _api_key_output_path(args, db_path):
    configured = getattr(args, "api_key_file", None)
    if configured:
        return Path(configured)
    return Path(f"{db_path}.api-key")


def _write_api_key_file(path, api_key):
    key_path = Path(path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(key_path, flags, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(api_key + "\n")
    try:
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Some platforms/filesystems ignore POSIX chmod; the file was already
        # opened with restrictive mode where that mode is supported.
        return key_path
    return key_path


def _persist_api_key(path, api_key):
    key_path = Path(path)
    if key_path.exists():
        raise FileExistsError(key_path)
    _write_api_key_file(key_path, api_key)


def cmd_serve(args):
    """Run the AppGuardrail control-plane API (scan ingest + history)."""
    from appguardrail_core import controlplane as cp

    db = getattr(args, "db", None) or "appguardrail-control-plane.db"
    conn = cp.connect(db)
    create = getattr(args, "create_org", None)
    if create:
        key_path = _api_key_output_path(args, db)
        if key_path.exists():
            conn.close()
            _console_print(
                f"❌ Error: API key file already exists: {key_path}", file=sys.stderr
            )
            _console_print(
                "💡 Hint: Pass --api-key-file with a new path.", file=sys.stderr
            )
            return 1
        oid, key = cp.create_org(conn, create)
        conn.close()
        try:
            _persist_api_key(key_path, key)
        except FileExistsError:
            _console_print(
                f"❌ Error: API key file already exists: {key_path}", file=sys.stderr
            )
            _console_print(
                "💡 Hint: Pass --api-key-file with a new path.", file=sys.stderr
            )
            return 1
        _console_print(f"✅ Created org '{create}' (id {oid}).")
        _console_print(f"🔑 API key written to {key_path}")
        return 0
    if conn.execute("SELECT COUNT(*) AS c FROM orgs").fetchone()["c"] == 0:
        key_path = _api_key_output_path(args, db)
        if key_path.exists():
            conn.close()
            _console_print(
                f"❌ Error: API key file already exists: {key_path}", file=sys.stderr
            )
            _console_print(
                "💡 Hint: Pass --api-key-file with a new path.", file=sys.stderr
            )
            return 1
        _oid, key = cp.create_org(conn, "default")
        try:
            _persist_api_key(key_path, key)
        except FileExistsError:
            conn.close()
            _console_print(
                f"❌ Error: API key file already exists: {key_path}", file=sys.stderr
            )
            _console_print(
                "💡 Hint: Pass --api-key-file with a new path.", file=sys.stderr
            )
            return 1
        _console_print("ℹ️  No orgs yet — created 'default'.")
        _console_print(f"🔑 API key written to {key_path}\n")
    conn.close()

    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 8788)
    try:
        server = cp.make_control_plane_server(host, port, db)
    except OSError as exc:
        _console_print(
            f"❌ Error: Cannot start control plane on {host}:{port} ({exc}).",
            file=sys.stderr,
        )
        _console_print("💡 Hint: Pass a free port with --port.", file=sys.stderr)
        return 1
    actual = server.server_address[1]
    _console_print(f"🛰️  AppGuardrail control plane on http://{host}:{actual}")
    _console_print(
        "   POST /api/v1/scans · GET /api/v1/scans · GET /api/v1/scans/{id} · GET /api/v1/health"
    )
    _console_print("   Auth: Authorization: Bearer <api_key>. Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _console_print("\n👋 Control plane stopped.")
    finally:
        server.server_close()
    return 0


def cmd_sbom(args):
    """Generate a CycloneDX SBOM from dependency manifests."""
    from appguardrail_core.sbom import build_sbom, collect_components

    base = Path(getattr(args, "path", ".") or ".")
    if not base.exists():
        _console_print(f"❌ Error: Path not found: {base}", file=sys.stderr)
        _console_print(
            "💡 Hint: Check if the path is correct or if you are in the right directory.",
            file=sys.stderr,
        )
        return 1
    root = base if base.is_dir() else base.parent
    components = collect_components(root)
    if not components:
        _console_print(
            "ℹ️  No supported manifests found "
            "(package.json, package-lock.json, requirements.txt).",
            file=sys.stderr,
        )
        return 1
    app_name = (
        getattr(args, "app_name", None) or root.name or "AppGuardrail scan target"
    )
    payload = json.dumps(build_sbom(components, app_name), indent=2)
    out = getattr(args, "out", None)
    if out:
        try:
            Path(out).parent.mkdir(parents=True, exist_ok=True)
            Path(out).write_text(payload + "\n", encoding="utf-8")
        except OSError as exc:
            _console_print(f"❌ Error: Cannot write SBOM: {exc}", file=sys.stderr)
            return 1
        component_word = "component" if len(components) == 1 else "components"
        _console_print(f"📦 SBOM ({len(components)} {component_word}) written: {out}")
    else:
        _console_print(payload)
    return 0


def cmd_dashboard(args):
    """Serve the local AppGuardrail findings dashboard in a browser."""
    import webbrowser

    index = dashboard_index_path()
    if not index.is_file():
        _console_print(
            f"❌ Error: Dashboard assets not found at {index}", file=sys.stderr
        )
        _console_print(
            "💡 Hint: Check if the path is correct or if you are in the right directory.",
            file=sys.stderr,
        )
        _console_print(
            "💡 Hint: Run 'appguardrail dashboard' from an AppGuardrail source checkout "
            "that includes dashboard/index.html.",
            file=sys.stderr,
        )
        return 1

    findings_path = Path(getattr(args, "findings", None) or "reports/findings.json")
    if not findings_path.is_file():
        _console_print(f"ℹ️  No findings file at {findings_path}.")
        _console_print(
            "   Generate one with: "
            "appguardrail scan --findings-json reports/findings.json ."
        )
        _console_print(
            "   The dashboard opens with instructions — reload after generating.\n"
        )

    tokens_css = b""
    tokens_file = dashboard_tokens_path()
    if tokens_file.is_file():
        try:
            tokens_css = render_tokens_css(
                json.loads(tokens_file.read_text(encoding="utf-8"))
            ).encode("utf-8")
        except (ValueError, OSError) as exc:
            _console_print(
                f"⚠️  Could not read design tokens ({exc}); using stylesheet defaults.",
                file=sys.stderr,
            )

    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 8787)
    try:
        server = make_dashboard_server(
            host, port, index.read_bytes(), findings_path, tokens_css
        )
    except OSError as exc:
        _console_print(
            f"❌ Error: Cannot start dashboard on {host}:{port} ({exc}).",
            file=sys.stderr,
        )
        _console_print(
            "💡 Hint: Pass a free port with --port, e.g. --port 8899.", file=sys.stderr
        )
        return 1

    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/"
    _console_print(f"🛡️  AppGuardrail dashboard: {url}")
    _console_print("   Press Ctrl+C to stop.")
    if not getattr(args, "no_open", False):
        try:
            webbrowser.open(url)
        except Exception as exc:
            # Non-fatal: the server is already serving; just tell the user to
            # open the URL themselves instead of failing the command.
            _console_print(
                f"⚠️  Could not open a browser automatically ({exc}).", file=sys.stderr
            )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _console_print("\n👋 Dashboard stopped.")
    finally:
        server.server_close()
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Parse CLI arguments and dispatch the requested AppGuardrail command."""
    parser = argparse.ArgumentParser(
        prog="appguardrail",
        description="Security guardrails for AI-built apps",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command")

    # init
    init_parser = subparsers.add_parser(
        "init", help="Install security rules into your project"
    )
    init_parser.add_argument(
        "--tool",
        choices=[
            "auto",
            "codex",
            "copilot",
            "cursor",
            "claude-code",
            "windsurf",
            "lovable",
        ],
        default="auto",
        help="AI coding tool or agent suite (default: auto)",
    )
    init_parser.add_argument(
        "--stack",
        help="Tech stack (e.g. nextjs-supabase, nextjs-firebase)",
    )

    # scan
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a directory for security issues"
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory or file to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "--trivy",
        action="store_true",
        help="Also run Trivy filesystem scan for dependency, secret, and misconfiguration findings",
    )
    scan_parser.add_argument(
        "--external",
        choices=["auto", "off"],
        default="auto",
        help="Auto-discover runnable SAST/DAST engines for detected languages (default: auto)",
    )
    scan_parser.add_argument(
        "--bandit",
        action="store_true",
        help="Force-run Bandit Python SAST",
    )
    scan_parser.add_argument(
        "--ruff",
        action="store_true",
        help="Force-run Ruff Bandit-compatible security rules",
    )
    scan_parser.add_argument(
        "--semgrep",
        action="store_true",
        help="Force-run Semgrep multi-language SAST",
    )
    scan_parser.add_argument(
        "--semgrep-config",
        default=None,
        help="Semgrep config to use when Semgrep runs (default: auto)",
    )
    scan_parser.add_argument(
        "--zap-baseline",
        default=None,
        help="Run OWASP ZAP baseline scan against this http(s) URL",
    )
    scan_parser.add_argument(
        "--findings-json",
        default=None,
        help="Write normalized findings JSON for report builders and dashboards",
    )
    scan_parser.add_argument(
        "--sarif",
        default=None,
        help="Write SARIF 2.1.0 for GitHub code scanning, VS Code, and other tools",
    )
    scan_parser.add_argument(
        "--push",
        default=None,
        metavar="URL",
        help="POST findings to a control-plane URL (key from APPGUARDRAIL_API_KEY)",
    )
    scan_parser.add_argument(
        "--codegraph",
        action="store_true",
        help="Initialize or sync CodeGraph before scanning for structural review context",
    )

    # monitor
    subparsers.add_parser(
        "monitor",
        help="Install a GitHub Actions workflow that runs AppGuardrail on changes",
    )

    # review
    review_parser = subparsers.add_parser(
        "review", help="Generate an AI security review prompt"
    )
    review_parser.add_argument("--stack", help="Tech stack (e.g. nextjs)")
    review_parser.add_argument(
        "--db", help="Database/backend (e.g. supabase, firebase)"
    )
    review_parser.add_argument("--payments", help="Payment provider (e.g. stripe)")

    # report
    report_parser = subparsers.add_parser(
        "report", help="Generate product and diligence reports from findings JSON"
    )
    report_subparsers = report_parser.add_subparsers(dest="report_type")

    def add_report_arguments(parser):
        parser.add_argument(
            "--findings",
            required=True,
            help="Path to findings JSON array or object with a findings array",
        )
        parser.add_argument(
            "--out",
            default=None,
            help="Write report to this markdown path instead of stdout",
        )
        parser.add_argument("--app-name", default=None, help="Application name")
        parser.add_argument("--repository", default=None, help="Repository name")
        parser.add_argument("--commit", default=None, help="Commit SHA or version")
        parser.add_argument(
            "--generated-at", default=None, help="Report timestamp in ISO-8601 form"
        )
        parser.add_argument(
            "--scan-command", default=None, help="Scan command used to produce findings"
        )
        parser.add_argument("--scope", default=None, help="Report scope summary")
        parser.add_argument("--client-name", default=None, help="Agency client name")
        parser.add_argument("--reviewer", default=None, help="Reviewer or agency name")
        parser.add_argument(
            "--engagement-type",
            default=None,
            help="Agency engagement type, such as pre-launch review",
        )
        parser.add_argument(
            "--based-on",
            default=None,
            help="Review ID, issue, PR, or scan artifact this report is based on",
        )

    report_help = {
        "buyer-diligence": "Generate a buyer diligence markdown report",
        "founder-friendly": "Generate a plain-language founder report",
        "agency": "Generate an agency/client security review report",
        "fix-pack": "Generate AI-ready remediation prompts and verification steps",
    }
    for report_type in supported_report_types():
        add_report_arguments(
            report_subparsers.add_parser(report_type, help=report_help[report_type])
        )

    # org-bundle
    org_bundle_parser = subparsers.add_parser(
        "org-bundle",
        help="Generate an organization buyer evidence bundle",
    )
    org_bundle_parser.add_argument(
        "--owner",
        default="ContextualWisdomLab",
        help="GitHub organization owner (default: ContextualWisdomLab)",
    )
    org_bundle_parser.add_argument(
        "--bundle-dir",
        default="appguardrail-buyer-evidence",
        help="Directory to write bundle artifacts",
    )
    org_bundle_parser.add_argument(
        "--repos-json",
        default=None,
        help="Use a gh repo list JSON file instead of live GitHub repository lookup",
    )
    org_bundle_parser.add_argument(
        "--prs-json",
        default=None,
        help="Use a pull request JSON file instead of live GitHub PR lookup",
    )
    org_bundle_parser.add_argument(
        "--prs-repository",
        default=None,
        help="Repository name to attach to PR rows missing repository metadata",
    )
    org_bundle_parser.add_argument(
        "--per-repo-pr-limit",
        type=int,
        default=100,
        help="Maximum open PRs to inspect per non-fork repository",
    )
    org_bundle_parser.add_argument(
        "--active-repository-target",
        type=int,
        default=20,
        help="Non-fork repository target used by buyer evidence KPIs",
    )
    org_bundle_parser.add_argument(
        "--generated-at",
        default=None,
        help="Override bundle timestamp in ISO-8601 form",
    )

    # hook
    hook_parser = subparsers.add_parser(
        "hook", help="Install a pre-commit hook to block commits with vulnerabilities"
    )
    hook_parser.add_argument(
        "--codegraph",
        action="store_true",
        help="Install the hook in CodeGraph mode so commits also refresh structural context",
    )

    # dashboard
    fix_parser = subparsers.add_parser(
        "fix", help="Apply safe, deterministic auto-fixes (dry-run by default)"
    )
    fix_parser.add_argument(
        "path", nargs="?", default=".", help="File or directory to fix"
    )
    fix_parser.add_argument(
        "--apply",
        action="store_true",
        help="Write fixes to disk (default: show a dry-run diff)",
    )
    serve_parser = subparsers.add_parser(
        "serve", help="Run the control-plane API (multi-tenant scan ingest + history)"
    )
    serve_parser.add_argument(
        "--db",
        default=None,
        help="SQLite database path (default: appguardrail-control-plane.db)",
    )
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    serve_parser.add_argument("--port", type=int, default=8788, help="Bind port")
    serve_parser.add_argument(
        "--create-org",
        default=None,
        metavar="NAME",
        help="Create an org, write its API key, and exit",
    )
    serve_parser.add_argument(
        "--api-key-file",
        default=None,
        metavar="PATH",
        help="Write newly generated bootstrap API keys to PATH (default: <db>.api-key)",
    )
    sbom_parser = subparsers.add_parser(
        "sbom", help="Generate a CycloneDX SBOM from dependency manifests"
    )
    sbom_parser.add_argument(
        "path", nargs="?", default=".", help="Project directory to inventory"
    )
    sbom_parser.add_argument(
        "--out", default=None, help="Write SBOM JSON here instead of stdout"
    )
    sbom_parser.add_argument(
        "--app-name", default=None, help="Application name for the SBOM metadata"
    )
    dashboard_parser = subparsers.add_parser(
        "dashboard", help="Serve the findings dashboard in your browser"
    )
    dashboard_parser.add_argument(
        "--findings",
        default="reports/findings.json",
        help="Path to a findings JSON file (default: reports/findings.json)",
    )
    dashboard_parser.add_argument(
        "--port", type=int, default=8787, help="Port to serve on (default: 8787)"
    )
    dashboard_parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)"
    )
    dashboard_parser.add_argument(
        "--no-open", action="store_true", help="Do not open a browser automatically"
    )

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "monitor":
        sys.exit(cmd_monitor(args))
    elif args.command == "review":
        cmd_review(args)
    elif args.command == "report":
        sys.exit(cmd_report(args))
    elif args.command == "org-bundle":
        sys.exit(cmd_org_bundle(args))
    elif args.command == "hook":
        sys.exit(cmd_hook(args))
    elif args.command == "fix":
        sys.exit(cmd_fix(args))
    elif args.command == "serve":
        sys.exit(cmd_serve(args))
    elif args.command == "sbom":
        sys.exit(cmd_sbom(args))
    elif args.command == "dashboard":
        sys.exit(cmd_dashboard(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
