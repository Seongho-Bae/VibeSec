## 2025-05-30 - Fix DoS vector in file scanner
**Vulnerability:** The CLI file scanner `vibesec scan` iterated through files using `os.walk` without verifying if a file was a regular file (`is_file()`) and read the entire file into memory using `Path.read_text()` without any size constraints.
**Learning:** If a malicious or overly broad directory was scanned (e.g., containing device nodes like `/dev/zero`, FIFOs, or gigabyte-sized files), the scanner would hang indefinitely or crash due to an Out of Memory (OOM) error.
**Prevention:** Always verify `Path.is_file()` before yielding files to scan to avoid reading character devices or FIFOs. In addition, explicitly check `Path.stat().st_size` against a reasonable upper bound (e.g., 10MB) before loading file content entirely into memory.

## 2025-05-31 - [CLI Scanner DoS and OOM Vulnerability Prevention]
**Vulnerability:** File-system-based Denial of Service (DoS) and Out-Of-Memory (OOM) risks during static analysis. The scanner could hang on special system files (like `/dev/zero` or FIFOs) or consume excessive memory.
**Learning:** The CLI tool lacked robust checks for file types before processing them. The reviewer pointed out that changing `for line in f` to `read_text().splitlines()` actually increased memory usage unnecessarily and degraded performance, and that `re.search` operates efficiently line-by-line without multiline vulnerabilities if iterating on the file object itself.
**Prevention:** Always verify `file_path.is_file()` to skip special files. Retain the memory-efficient line iterator (`for line in f`) while utilizing size limits (`st_size > 10MB`).

## 2026-06-09 - Fix Path Traversal/Arbitrary File Read in scanner via symlinks
**Vulnerability:** The `_collect_files` function in `scanner/cli/vibesec.py` used `os.scandir` without explicitly checking if entries were symbolic links before processing them as directories or files. This could allow for arbitrary file read or path traversal vulnerabilities by processing symlinks that point outside the expected directories.
**Learning:** During static analysis, directory and file collection methods must be robust against maliciously crafted directory structures, specifically symbolic links pointing to sensitive system files.
**Prevention:** Explicitly use `entry.is_symlink()` and check `follow_symlinks=False` on `is_file()` to prevent traversing external links or including them during scan operations.

## 2026-06-11 - Fix Arbitrary File Write via symlink path traversal in `vibesec init`
**Vulnerability:** The `cmd_init` command in `scanner/cli/vibesec.py` created files and directories inside `.cursor/rules` or `VIBESEC_CHECKLIST.md` in the current project root. However, if the project directory contained malicious symlinks (e.g., `.cursor -> /etc` or `.cursor -> /tmp`), the CLI would unknowingly traverse the symlink and write files (e.g., `vibesec.md`) outside the intended directory. This leads to an Arbitrary File Write vulnerability, potentially allowing attackers to overwrite sensitive files or escalate privileges on the victim's machine.
**Learning:** Even simple CLI file operations (like initializing project configurations) are susceptible to Path Traversal via symlinks. When dealing with directory structures that could be maliciously crafted, we cannot trust that `Path(".").resolve() / ".cursor"` stays within the bounds of `Path(".").resolve()`.
**Prevention:** Before performing any filesystem mutation operations (e.g. `mkdir` or `write_text`), ensure the fully resolved path resides strictly within the expected parent boundary. Use `target_file.resolve().is_relative_to(project_root)` as a security check to detect and abort if the path escapes the intended directory.

## 2026-06-13 - Fix Terminal Output Injection in scanner output
**Vulnerability:** The CLI scanner `vibesec scan` printed findings directly to standard output, incorporating untrusted data like file paths (`rel_path`) and file content snippets (`line.strip()[:120]`) without sanitization.
**Learning:** If a malicious user intentionally places ANSI terminal escape sequences (like `\033[2K` or `\r`) in file names or codebase content, they can execute "Terminal Output Injection" to alter or clear standard output. This allows them to effectively hide critical security findings from developers reviewing the scanner results.
**Prevention:** Whenever printing untrusted data to a terminal, explicitly sanitize the text to remove or escape non-printable control characters. Implementing a simple sanitization function like `"".join(c if c.isprintable() or c == '\t' else repr(c)[1:-1] for c in text)` completely diffuses the payload into safely viewable raw text.

## 2026-06-12 - Expand Scanner Rules for Critical Exploits
**Vulnerability:** The CLI file scanner `vibesec scan` lacked detection rules for fundamental security vulnerabilities in JavaScript/TypeScript ecosystems, specifically arbitrary code execution via `eval()` and Cross-Site Scripting (XSS) via React's `dangerouslySetInnerHTML`.
**Learning:** Even specialized "vibe-coding" static analysis tools must include detection for standard, catastrophic security anti-patterns (like eval and XSS injection vectors) to provide complete coverage.
**Prevention:** Two new rules, `dangerous-eval` and `react-dangerously-set-inner-html`, were added to `SCAN_RULES` to flag these patterns.
## 2025-02-12 - Prevent ReDoS by avoiding capturing groups in scanner rules
**Vulnerability:** Regular Expression Denial of Service (ReDoS) vulnerability caused by tracking capturing group matches `(...)` during line-by-line file scanning in `SCAN_RULES`.
**Learning:** In a highly repetitive inner loop (line-by-line file scanning), tracking backreferences and capturing group matches incurs unnecessary regex engine overhead. While unbounded quantifiers are the primary ReDoS cause, capturing groups exacerbate the tracking state, increasing scan time significantly on long lines or adversarial payloads.
**Prevention:** Always use non-capturing groups `(?:...)` instead of capturing groups `(...)` when adding or modifying regular expressions in `SCAN_RULES` to prevent unnecessary performance overhead and ReDoS vulnerabilities.

## 2026-06-16 - Add OWASP mapping and pre-commit hook integration
**Vulnerability:** The VibeSec scanner lacked explicit mapping to standard vulnerability frameworks (like OWASP Top 10) and relied on manual invocation, meaning vulnerabilities could easily bypass detection and be committed by developers or AI agents (like Claude Code or Codex).
**Learning:** To enforce security guardrails effectively, static analysis tools should intercept the workflow at commit time. Mapping findings to OWASP categories improves the clarity and actionability of the scanner output.
**Prevention:** Updated `SCAN_RULES` messages to include relevant OWASP classifications (e.g., A01, A03). Added a `vibesec hook` command that automatically installs a `pre-commit` script to block commits if critical or high vulnerabilities are detected.

## 2025-06-25 - Expand Scanner Rules for Command Injection
**Vulnerability:** The VibeSec static analysis scanner lacked explicit detection for command injection patterns (such as `child_process.exec` with untrusted input in Node, or `subprocess.run(..., shell=True)` in Python).
**Learning:** Command Injection is a critical OWASP Top 10 vulnerability (A03:2021) that must be flagged in both JavaScript/TypeScript and Python codebases, especially in AI-assisted development where dynamic shell execution is often carelessly generated.
**Prevention:** Two new rules were added to `SCAN_RULES`: `node-command-injection` and `python-command-injection`. In addition, a `hardcoded-password` rule was added to capture generic password misconfigurations.

## 2026-06-25 - Expand Scanner Rules for Path Traversal
**Vulnerability:** The VibeSec static analysis scanner lacked explicit detection for path traversal risks caused by dynamically constructing file paths using untrusted inputs (e.g., Python `open(f"...{var}...")` or Node `fs.readFile(\`...\${var}...\`)`).
**Learning:** Path Traversal is a critical OWASP Top 10 vulnerability (A01:2021) that must be flagged. Constructing dynamic paths without validation or sanitization is a very common failure mode when AI generates file-system related code.
**Prevention:** A new rule `path-traversal-risk` was added to `SCAN_RULES` to flag unsafe usage of `fs.readFile`, `fs.readFileSync`, `fs.writeFile`, `fs.writeFileSync`, `fs.createReadStream`, and Python's `open()` when used with string concatenation, f-strings, or template literals.

## 2024-06-21 - [ReDoS Prevention in YAML Scanner Rules]
**Vulnerability:** Regular Expression Denial of Service (ReDoS) potential in scanner rules.
**Learning:** Capturing groups `(...)` in heavily used regex rules (like in `scanner/rules/*.yml`) increase backtracking overhead and memory usage, making the scanner vulnerable to ReDoS attacks with crafted input files.
**Prevention:** Always use non-capturing groups `(?:...)` when the captured value is not needed for backreferences or extraction. This improves scanner performance and prevents ReDoS.

## 2025-02-24 - Fix Insecure Deserialization in scanner output
**Vulnerability:** The CLI file scanner `vibesec scan` lacked detection rules for insecure deserialization, such as `pickle.load` or `yaml.load` in Python, which could lead to arbitrary code execution.
**Learning:** Adding regular expressions that detect known dangerous serialization libraries prevents severe security vulnerabilities when parsing untrusted data.
**Prevention:** A new scanner rule `python-insecure-deserialization` was added to `SCAN_RULES` to flag `pickle.load(s)`, `yaml.load`, and `marshal.load(s)`.
## 2024-05-18 - Fix missing redaction tokens for new secret rules
**Vulnerability:** Newly added secret detection rules (like AWS keys, Anthropic keys, GitHub tokens, etc.) were missing from the `_SENSITIVE_RULE_TOKENS` list in `scanner/cli/appguardrail.py`.
**Learning:** Adding new scanner rules to detect secrets isn't enough; the token strings identifying these rules must also be added to `_SENSITIVE_RULE_TOKENS` to ensure their values are redacted in CI/CD logs or terminal output. Otherwise, the scanner would find the secret and then leak it.
**Prevention:** Whenever adding new secret detection rules to `SCAN_RULES` or `scanner/rules/secrets.yml`, always cross-reference and update the `_SENSITIVE_RULE_TOKENS` list to ensure corresponding redaction.
## 2025-02-28 - Prevent Security Theater in Validation Logic
**Vulnerability:** Redundant, useless security checks ("security theater") were previously added to statically hardcoded URL strings in GitHub actions and test files, under the guise of SSRF prevention.
**Learning:** Checking a hardcoded string like `"https://pypi.org/..."` to see if it starts with `https://` provides zero real security value while polluting the codebase and making PR reviews noisy. Security validation logic must be strictly scoped to where *untrusted, dynamic input* is introduced (like dynamically constructed API URLs in network wrappers).
**Prevention:** Avoid blanket application of security validation rules across an entire repository regardless of context. Always trace the source of the variable being validated to ensure it actually incorporates dynamic or external data before adding runtime verification logic.
## 2025-02-28 - Fix CodeQL Code Scanning Upload Error
**Vulnerability:** CI fails with error "CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled" when uploading SARIF results.
**Learning:** If a repository has default Code Scanning setup enabled in GitHub settings, pushing SARIF using the `github/codeql-action/upload-sarif` action from advanced workflows fails. This conflict happens when security tooling pushes SARIF files to the GitHub Advanced Security Code Scanning endpoint.
**Prevention:** Remove `github/codeql-action/upload-sarif` steps from advanced configuration workflows (like `scorecard-analysis.yml` and `security-process.yml`) if default CodeQL setup is enabled for the repository, to avoid pipeline failures and configuration conflicts.
## 2025-02-28 - Enhance SSRF Protection with IP Validation
**Vulnerability:** Weak redirect target validation for log collection flows in CI scripts. The `_validate_log_download_url` function blocked a static list of hosts (like `localhost` and `127.0.0.1`), but failed to block private/internal IP ranges (10.0.0.0/8, 192.168.0.0/16, etc), numeric encodings (like `2130706433`), or link-local IPv6 addresses.
**Learning:** Checking hostnames against a hardcoded blocklist is insufficient for SSRF protection because attackers can bypass the list using different IP representations or pointing to other internal IP ranges. Robust SSRF validation requires parsing the IP address using the `ipaddress` module and checking properties like `is_private`, `is_loopback`, `is_link_local`, etc.
**Prevention:** Use `ipaddress.ip_address` to parse and validate IP literals, explicitly rejecting private and reserved addresses before making network requests. Ensure edge cases like dotless decimal encoding and credentials in URLs are also rejected.
## 2025-02-28 - Note on IP Validation and Valid Hostnames
**Learning:** Checking hostnames against patterns like `p.startswith("0")` or `p.startswith("0x")` to prevent octal/hex SSRF bypasses may inadvertently block valid domain names like `0x.org` or `0123.com`. While acceptable for internal tools restricted to known endpoints, it shouldn't be blindly applied to all web applications.

## 2026-07-06 - _SENSITIVE_RULE_TOKENS 업데이트 누락 수정
**Vulnerability:** 새로운 시크릿 스캔 룰 추가 시 민감 정보 노출
**Learning:** `scanner/rules/secrets.yml`에 aws나 private-key 등의 스캔 룰이 추가되었으나, 로그나 터미널 출력 시 해당 정보를 마스킹하기 위해 필요한 `_SENSITIVE_RULE_TOKENS`에 토큰이 누락되어, 스캔 결과 출력 시 인증 정보가 그대로 노출될 위험이 존재했습니다.
**Prevention:** 새로운 시크릿 종류를 `SCAN_RULES`에 추가할 경우, `scanner/cli/appguardrail.py`의 `_SENSITIVE_RULE_TOKENS` 튜플에도 반드시 연관 토큰(예: "aws", "private-key")을 추가하여 `_safe_snippet` 함수가 터미널 출력 시 해당 값을 안전하게 \[REDACTED\] 처리하도록 유지해야 합니다.
## 2026-07-10 - Strict URL scheme validation for SSRF/LFI prevention
**Vulnerability:** Server-Side Request Forgery (SSRF) and Local File Inclusion (LFI) risks in webhook payloads and CLI push endpoints due to missing URL scheme validation before `urllib.request.urlopen`.
**Learning:** Built-in Python functions like `urllib.request.urlopen` accept schemes like `file://` and `ftp://` natively. When user input (like configuration strings or CLI arguments) provides the URL, it must be validated statically.
**Prevention:** Ensure explicit prefix checks (e.g. `url.startswith(('http://', 'https://'))`) on user-provided inputs passed to generic HTTP client APIs before issuing the request.
## 2026-07-10 - [SSRF and LFI vulnerability in urllib.request.urlopen]
**Vulnerability:** Server-Side Request Forgery (SSRF) and Local File Inclusion (LFI) risks in webhook payloads and CLI push endpoints due to missing URL scheme validation before `urllib.request.urlopen` and insufficient host validation.
**Learning:** Checking the URL hostname natively with string matches is vulnerable to DNS-based bypasses (e.g. `127.0.0.1.nip.io`). To prevent internal routing from malicious external actors, URL schemes should be validated and the IP address obtained through `socket.gethostbyname` needs to be validated against loopback, private, and link-local ranges.
**Prevention:** Always validate user-provided URLs by strictly allowing schemas (`http`, `https`) and checking their resolved IPs for safety (`ipaddress.is_loopback`, `ipaddress.is_private`, `ipaddress.is_link_local`).

## 2026-07-10 - GitHub log redirect DNS validation
**Vulnerability:** GitHub Actions log download redirects accepted DNS hostnames after only scheme, credential, and direct-IP validation, allowing an allowed-looking hostname to resolve to loopback, private, link-local, reserved, or otherwise non-global addresses.
**Learning:** Runtime SSRF validation must be scoped to the untrusted redirect boundary and must validate both the host class and every DNS resolution result. For GitHub job logs, broad arbitrary host support is unnecessary; redirects should be limited to expected GitHub/Azure log hosts.
**Prevention:** Validate initial log download URLs and redirect hops with `_validate_log_download_url`, allow only expected log host suffixes, and reject any `socket.getaddrinfo` result that is not a global public IP.

## 2026-07-11 - SSRF and IPv6 bypassing due to socket.gethostbyname
**Vulnerability:** Server-Side Request Forgery (SSRF) bypass due to `socket.gethostbyname` failing to properly process and resolve IPv6 literals (e.g., `::1`), throwing exceptions that allowed internal network routing constraints to be circumvented.
**Learning:** `socket.gethostbyname` only returns IPv4 records and throws errors when encountering IPv6 literals or purely IPv6 DNS records. When constructing network guardrails like `_is_safe_url`, using `socket.gethostbyname` introduces blind spots for IPv6, which is heavily used in modern internal routing.
**Prevention:** Always use `socket.getaddrinfo(raw, None)` to reliably iterate through all addresses (IPv4 and IPv6) returned for a host, along with directly trying `ipaddress.ip_address` to short-circuit IP literals before doing DNS resolution.

## 2026-07-12 - Complete SSRF protection for unspecified and multicast IPs
**Vulnerability:** The SSRF protection `_is_safe_url` previously missed `is_unspecified` (for example, `0.0.0.0` or `::`) and `is_multicast` addresses, allowing webhook or CLI push URLs to target non-routable or multicast infrastructure despite rejecting loopback/private/link-local addresses.
**Learning:** `ipaddress.is_private` does not cover every unsafe network class. Unspecified and multicast addresses must be rejected explicitly for both direct IP literals and every address returned by DNS resolution.
**Prevention:** When building URL/IP guardrails with the `ipaddress` library, include `ip.is_unspecified` and `ip.is_multicast` alongside `is_private`, `is_loopback`, and `is_link_local`, and keep focused regression tests for both control-plane webhook delivery and CLI push validation.

## 2026-07-11 - SSRF and IPv6 mapped bypassing due to incomplete validation
**Vulnerability:** Server-Side Request Forgery (SSRF) bypass due to `_is_safe_url` only checking `is_loopback` and `is_private`. This fails to correctly evaluate mapped IPv4 addresses disguised as IPv6 (e.g. `[::ffff:127.0.0.1]`) and misses restricted IP designations like `is_reserved` or non `is_global` IPs, allowing SSRF to `0.0.0.0` or `255.255.255.255`.
**Learning:** Python's `ipaddress` objects for mapped IPv6 don't inherit properties of their IPv4 wrapped content directly. Using `is_loopback` without checking `.ipv4_mapped` leaves blind spots.
**Prevention:** Always extract `getattr(ip, 'ipv4_mapped', None)` before evaluation, and combine checks spanning `is_reserved`, `not is_global`, `is_multicast`, `is_unspecified`, `is_private`, and `is_loopback` to fully protect endpoints.

## 2026-07-18 - [XSS vulnerability via malicious references in dashboard]
**Vulnerability:** Cross-Site Scripting (XSS) via `javascript:` URIs in `href` attributes in `scanner/dashboard/index.html`.
**Learning:** `f.references` values (URLs) were injected into `href` attributes with only HTML entity escaping via `esc()`. HTML escaping `javascript:alert(1)` does not neutralize the `javascript:` URI protocol, meaning that clicking the link executes the injected script in the context of the dashboard UI. This allowed an attacker controlling finding references to achieve XSS.
**Prevention:** Always validate the URL scheme (allow-listing `http:` and `https:`) using `new URL()` parser to ensure user-provided URLs cannot leverage dangerous schemes like `javascript:`, `file:`, or `data:` when injected into `href` attributes, before applying standard HTML escaping.

## 2026-07-21 - [SSRF bypass via HTTP redirects]
**Vulnerability:** Server-Side Request Forgery (SSRF) bypass due to `urllib.request.urlopen` automatically following HTTP redirects to internal infrastructure even when the initial URL was validated as safe.
**Learning:** Checking the initial user-provided URL against a blocklist or guardrail is insufficient if the HTTP client automatically follows redirects. An attacker can set up an external server (e.g. `http://attacker.com/redirect`) that passes initial validation but responds with a `302 Found` pointing to an internal IP (e.g. `http://169.254.169.254/`). `urlopen` transparently follows this, bypassing the initial check.
**Prevention:** When using `urllib.request` to access external URLs that must be restricted (like webhook URLs), you must intercept redirects. This can be done by creating a subclass of `urllib.request.HTTPRedirectHandler` that overrides `redirect_request` to apply the same safety guardrail (`_is_safe_url`) to the `newurl` target, and injecting this handler using `urllib.request.build_opener`.

## 2026-07-29 - [DOM XSS via unescaped severity in dashboard]
**Vulnerability:** DOM XSS via unescaped `severity` string interpolated into `innerHTML` in `scanner/dashboard/index.html`.
**Learning:** Even enum-like or seemingly safe meta-fields like `severity` can contain malicious payloads if sourced from user input (findings file) and directly injected into innerHTML.
**Prevention:** Always use the `esc()` sanitizer for any dynamically rendered property from `findings.json`, regardless of expected schema types.

## 2025-02-28 - Stored SSRF and Unhandled Parsing Exceptions Guardrail
**Vulnerability:** The `/api/v1/webhook` POST endpoint in `appguardrail_core/controlplane.py` failed to validate the `url` property when accepting it into the database, leading to Stored SSRF risks. In addition, the core SSRF validation logic (`_is_safe_url`) in both the CLI and control-plane did not verify the input type (e.g. `isinstance(url, str)`). Passing non-string types (like integers) resulted in unhandled `AttributeError` exceptions inside `urllib.parse.urlparse`, which led to API 500 crashes on malicious JSON payloads.
**Learning:** Network endpoints must explicitly validate the data type of user-provided configurations prior to execution or storage. Furthermore, webhooks configured by users should always be checked for SSRF when saved, as trusting them later assumes input has already been safely validated, bypassing downstream network guardrails.
**Prevention:** Apply `_is_safe_url` checks directly upon ingestion (e.g., in `/api/v1/webhook`) and enforce type checks `if not isinstance(url, str): return False` prior to using library parsing functions like `urlparse`. Always return gracefully failing responses (like `400 Bad Request`) for unsafe URLs instead of allowing unhandled 500 server errors.
## 2026-07-29 - Missing secrets in _finding_category
**Vulnerability:** A missing keyword mapping in `_finding_category` led to multiple secrets being categorized as `misconfig` rather than `secrets` in the reporting output.
**Learning:** `scanner/cli/appguardrail.py` uses two distinct lists: `_SENSITIVE_RULE_TOKENS` for redacting terminal output and inline validation, and a hardcoded list inside `_finding_category` for bucketing the output. This duplicated state caused certain rules (like `hardcoded-aws-access-key-id`) to be omitted from the `"secrets"` category, masking their true severity in organizational readiness dashboards.
**Prevention:** Keep heuristic lists synchronized across the codebase. `aws`, `private-key`, `anthropic`, `github`, `slack`, `twilio`, `sendgrid`, `npm`, and `pypi` have been added to the internal list of `_finding_category`, along with test cases to prevent future regressions.
