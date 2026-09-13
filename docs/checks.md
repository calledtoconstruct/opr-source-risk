# Check protocol

Each check is `checks/<id>/`:

- `manifest.toml` — `id`, `facet`, `timeout_sec`, `needs_class` (`source`, `config`, `other`, `doc`, `test`)
- `run` — executable

stdin:

```json
{ "root": "/tree", "ref": "v1", "commit": "", "pkgname": "", "files": ["rel/path"] }
```

stdout:

```json
{
  "check_id": "net.listen-all",
  "status": "ok",
  "findings": [
    {
      "facet": "net.listen-all",
      "title": "…",
      "severity": "high",
      "confidence": "heuristic",
      "path": "cmd/server.py",
      "line": 6,
      "evidence": "s.bind((\"0.0.0.0\", 8080))"
    }
  ]
}
```

Exit 0 even when there are findings. Nonzero means the check crashed.
The host records `status=error` and continues.

`docs/`, `examples/`, and tests are classified and omitted unless `needs_class` includes `doc`/`test`.
