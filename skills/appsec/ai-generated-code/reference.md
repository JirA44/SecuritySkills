# AI-Generated Code — Semgrep Rule Stubs

Deploy all rules below to `.semgrep/ai-generated-patterns.yml` in the target repository.
Run this ruleset as a dedicated CI job on every PR that touches AI-assisted commits
(identifiable via commit message conventions, PR labels, or `git log --grep="co-authored"`).

---

## Rule Set: `ai-generated-patterns.yml`

```yaml
rules:

  # -------------------------------------------------------------------------
  # Pattern 1: f-String SQL Injection (CWE-89 / ASVS V5.3.4)
  # -------------------------------------------------------------------------

  - id: ai-gen-fstring-sql-injection
    patterns:
      - pattern-either:
          - pattern: $CURSOR.execute(f"...", ...)
          - pattern: $CURSOR.execute("..." + $VAR + "...", ...)
          - pattern: $CURSOR.execute("..." % $VAR, ...)
    message: >
      Potential SQL injection: user-controlled variable interpolated directly
      into a query string. Use parameterized queries instead:
      cursor.execute("SELECT ... WHERE x = %s", (value,))
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-89
      asvs: V5.3.4
      category: ai-generated-pattern
      references:
        - https://cwe.mitre.org/data/definitions/89.html
        - https://owasp.org/www-project-application-security-verification-standard/

  - id: ai-gen-raw-sql-concatenation
    pattern: |
      $SQL = "SELECT" + ...
    message: >
      SQL string built via concatenation — high risk of injection if any
      component is user-controlled. Refactor to parameterized queries or ORM.
    languages: [python, javascript, typescript, java]
    severity: WARNING
    metadata:
      cwe: CWE-89
      asvs: V5.3.4
      category: ai-generated-pattern

  # -------------------------------------------------------------------------
  # Pattern 2: Missing Auth Decorators (CWE-306 / ASVS V4.1.1)
  # -------------------------------------------------------------------------

  - id: ai-gen-missing-auth-decorator-flask
    patterns:
      - pattern: |
          @app.route($PATH, ...)
          def $FUNC(...):
              ...
      - pattern-not: |
          @app.route($PATH, ...)
          @login_required
          def $FUNC(...):
              ...
      - pattern-not: |
          @app.route($PATH, ...)
          @jwt_required(...)
          def $FUNC(...):
              ...
      - pattern-not: |
          @app.route($PATH, ...)
          @token_required
          def $FUNC(...):
              ...
    message: >
      Flask route '$FUNC' has no authentication decorator. Confirm this
      endpoint is intentionally public, or apply @login_required /
      @jwt_required before merge. AI-generated endpoints frequently omit
      auth middleware (CWE-306).
    languages: [python]
    severity: WARNING
    metadata:
      cwe: CWE-306
      asvs: V4.1.1
      category: ai-generated-pattern
      references:
        - https://cwe.mitre.org/data/definitions/306.html

  - id: ai-gen-missing-auth-express
    patterns:
      - pattern-either:
          - pattern: app.get($PATH, async ($REQ, $RES) => { ... })
          - pattern: app.post($PATH, async ($REQ, $RES) => { ... })
          - pattern: app.put($PATH, async ($REQ, $RES) => { ... })
          - pattern: app.delete($PATH, async ($REQ, $RES) => { ... })
          - pattern: app.patch($PATH, async ($REQ, $RES) => { ... })
    message: >
      Express route registered with a single async handler and no middleware.
      Verify authentication and authorization are applied, especially for
      data-mutating or admin-only endpoints. AI agents commonly omit auth
      middleware (CWE-306).
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: CWE-306
      asvs: V4.1.1
      category: ai-generated-pattern

  # -------------------------------------------------------------------------
  # Pattern 3: Hardcoded Test Credentials (CWE-798 / ASVS V2.10.1)
  # -------------------------------------------------------------------------

  - id: ai-gen-hardcoded-test-credentials
    pattern-either:
      - pattern: $VAR = "changeme"
      - pattern: $VAR = "password123"
      - pattern: $VAR = "Test1234!"
      - pattern: $VAR = "supersecretkey123"
      - pattern: $VAR = "admin123"
      - pattern: $VAR = "secret123"
      - pattern: $VAR = "your_secret_here"
      - pattern: $VAR = "replace_me"
      - pattern: $VAR = "test_password"
      - pattern: $VAR = "supersecret"
    message: >
      Hardcoded test credential detected in '$VAR'. This is a common
      AI code-generator artifact. Replace with an environment variable
      or secrets manager reference before merge. (CWE-798 / ASVS V2.10.1)
    languages: [python, javascript, typescript, java, go]
    severity: ERROR
    metadata:
      cwe: CWE-798
      asvs: V2.10.1
      category: ai-generated-pattern
      references:
        - https://cwe.mitre.org/data/definitions/798.html

  - id: ai-gen-hardcoded-credential-high-entropy
    patterns:
      - pattern: $KEY = "$VALUE"
      - metavariable-regex:
          metavariable: $KEY
          regex: (?i)(password|passwd|secret|token|api_key|auth_key|jwt_secret|signing_key|private_key)
      - metavariable-regex:
          metavariable: $VALUE
          regex: .{8,}
    message: >
      Variable with a credential-like name '$KEY' is assigned a string
      literal of 8+ characters. Confirm this is not a hardcoded secret.
      Use environment variables or a secrets manager. (CWE-798 / ASVS V2.10.1)
    languages: [python, javascript, typescript, java, go]
    severity: WARNING
    metadata:
      cwe: CWE-798
      asvs: V2.10.1
      category: ai-generated-pattern

  # -------------------------------------------------------------------------
  # Pattern 4: Safe-Eval False Safety (CWE-94 / ASVS V5.2.4)
  # CVE-2026-32640: SimpleEval < 1.0.5, CVSS 8.7
  # -------------------------------------------------------------------------

  - id: ai-gen-simpleeval-unsafe
    pattern-either:
      - pattern: simpleeval.simple_eval($EXPR, ...)
      - pattern: simple_eval($EXPR, ...)
      - pattern: from simpleeval import $FN
      - pattern: import simpleeval
    message: >
      SimpleEval is not a safe sandbox for untrusted input.
      CVE-2026-32640 (CVSS 8.7) demonstrates code execution via dunder
      attribute chains in SimpleEval < 1.0.5. Use AST-based parsing with
      an explicit operator/literal allowlist instead. (CWE-94 / ASVS V5.2.4)
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-94
      cve: CVE-2026-32640
      asvs: V5.2.4
      category: ai-generated-pattern
      references:
        - https://www.cve.org/CVERecord?id=CVE-2026-32640
        - https://cwe.mitre.org/data/definitions/94.html

  - id: ai-gen-restrictedpython-unsafe
    pattern-either:
      - pattern: from RestrictedPython import $FN
      - pattern: import RestrictedPython
      - pattern: RestrictedPython.compile_restricted($CODE, ...)
    message: >
      RestrictedPython has documented sandbox escape techniques in public PoCs.
      Do not use it to execute untrusted user-supplied code. Prefer an
      AST-level expression parser with an explicit operator/literal allowlist.
      (CWE-94 / ASVS V5.2.4)
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-94
      asvs: V5.2.4
      category: ai-generated-pattern

  - id: ai-gen-eval-any
    pattern-either:
      - pattern: eval($EXPR)
      - pattern: exec($EXPR)
    message: >
      eval()/exec() call detected. If $EXPR contains any user-controlled
      input, this is a critical code injection vulnerability (CWE-94).
      Consider ast.literal_eval() for data structures, or a purpose-built
      expression parser for arithmetic. (ASVS V5.2.4)
    languages: [python, javascript, typescript]
    severity: ERROR
    metadata:
      cwe: CWE-94
      asvs: V5.2.4
      category: ai-generated-pattern
```

---

## CI Integration

Add to your GitHub Actions workflow:

```yaml
- name: Semgrep — AI-Generated Code Patterns
  uses: semgrep/semgrep-action@v1
  with:
    config: .semgrep/ai-generated-patterns.yml
  if: |
    contains(github.event.pull_request.labels.*.name, 'ai-generated') ||
    contains(github.event.pull_request.body, 'co-authored-by: GitHub Copilot')
```

Or run on all PRs (recommended):

```yaml
- name: Semgrep — AI-Generated Code Patterns
  run: semgrep --config .semgrep/ai-generated-patterns.yml --error ${{ github.workspace }}
```

---

## False Positive Suppression

Add inline suppression for known-safe patterns:

```python
# nosemgrep: ai-gen-hardcoded-test-credentials
TEST_PASSWORD = "changeme"  # test fixture only — never deployed
```

Document all suppressions in PR description.
