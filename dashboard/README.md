# Static dashboard

The dashboard reads the committed, redacted `data/sample-scan.json`; it does not scan files in the
browser or contact a remote service.

```bash
python -m http.server 8080 --directory dashboard
```

Open `http://127.0.0.1:8080`. The Findings, Permissions, and Files tabs are functional, as are all
three finding filters. Regenerate the data with `make sample`.
