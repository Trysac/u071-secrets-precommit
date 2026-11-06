# Usage

## Command line

```
secrets-precommit [--config FILE] [--format text|json] [--no-defaults] [--version] FILE...
```

Exit codes: `0` nothing found, `1` at least one potential secret found, `2` usage, configuration or read error.
Text output is one line per finding: `path:line:column: ruleId: redacted`.

## pre-commit hook entry

```yaml
repos:
  - repo: local
    hooks:
      - id: secrets-precommit
        name: secrets-precommit
        entry: secrets-precommit
        language: system
```

## Configuration

```json
{
  "rules": [{ "id": "corp-token", "pattern": "corp_[a-z0-9]{8}" }],
  "disableDefaults": false,
  "allowlist": { "paths": ["*.md"], "regexes": ["^dummy"] }
}
```

A line containing `secrets-precommit:allow` is never reported. Path globs use `path.Match` and are tested
against the slash-separated path and its base name.
