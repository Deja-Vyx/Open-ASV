# Contributing to OpenASV

Thanks for helping make external scanning and PCI DSS readiness more accessible.

## Ways to contribute

- **Policy and classification** — new finding categories, special-note rules, mappings of ZAP plugin IDs,
  testssl.sh checks, Nuclei tags or Nessus/OpenVAS plugins to categories (`config/policy.yaml`). Please cite the
  ASV Program Guide section, PCI DSS requirement or vendor documentation that supports the change.
- **Engines and importers** — new scanners or export formats. Each needs a parser test against a real output sample
  in `tests/fixtures/` (strip anything sensitive first).
- **Reports and UI** — accessibility, translations, print layout.
- **Bug reports** — include `openasv doctor` output, the profile used and, if possible, the raw engine output from the
  scan folder (`data/scans/<id>/`). Remove hostnames and anything confidential.

## Development setup

```bash
git clone https://github.com/Deja-Vyx/openasv.git && cd openasv
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,pdf]"
pytest
ruff check .
openasv serve --port 9100
```

Run a real scan locally against the demo target (`examples/demo-target`), never against third-party systems.

## Pull requests

- One topic per pull request, with tests for behaviour changes.
- Keep the scoring rules faithful to the ASV Program Guide; if you deliberately deviate, document it in the policy file.
- Do not add wording or report elements that could present OpenASV output as an official ASV attestation.
- By contributing you agree that your contribution is licensed under the Apache License 2.0.
