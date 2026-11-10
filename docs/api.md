# REST API

Enable the API by setting `OPENASV_API_TOKEN`. Send the token in every request:

```
Authorization: Bearer <token>
```

## Create a scope

```bash
curl -s -X POST http://localhost:9100/api/v1/scopes \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Storefront", "customer": {"company": "Example Retail"}, "components": ["https://shop.example.com/"]}'
# {"id": 3}
```

Components must be permitted by `config/target-policy.yaml`.

## Launch a scan

```bash
curl -s -X POST http://localhost:9100/api/v1/scopes/3/scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"profile": "asv", "authorized": true, "label": "Nightly"}'
# {"id": 12, "status_url": "/api/v1/scans/12"}
```

`authorized: true` records that the caller confirms authorization to test every component.

## Poll and fetch the report

```bash
curl -s http://localhost:9100/api/v1/scans/12 -H "Authorization: Bearer $TOKEN"
# {"id": 12, "status": "completed", "result": "FAIL", "report": "/scans/12/report.json", "error": null}

curl -s http://localhost:9100/api/v1/scans/12/report -H "Authorization: Bearer $TOKEN" | jq '.result'
```

The report JSON contains `tool`, `disclaimer`, `scan`, `result` (status, reasons, counts, inconclusive conditions),
`components`, `special_notes`, `discovered_components`, `findings` and `pci_dss`.

## Import results

```bash
curl -s -X POST http://localhost:9100/api/v1/import -H "Authorization: Bearer $TOKEN" \
  -F scope_id=3 -F file=@external.nessus
# {"id": 13, "result": "FAIL"}
```

`format` is optional (`nessus`, `gvm`, `zap`, `nuclei`, `nmap`, `testssl`); it is detected automatically.
