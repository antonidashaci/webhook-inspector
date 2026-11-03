# webhook-inspector

Catch webhooks, read exactly what arrived, and **replay them at your local
server** as many times as you need.

That last part is the point. While integrating Stripe or GitHub you don't want
to re-trigger the provider forty times to debug one handler — you want to
capture the payload once and fire it at `localhost:3000` until it works.

## Run

Python 3.10+ (the models use `X | None`, which Pydantic resolves at runtime).

```bash
pip install -r requirements.txt
uvicorn app:app --reload
```

```bash
curl -X POST localhost:8000/api/bins -H 'content-type: application/json' -d '{"label":"stripe"}'
```

```json
{
  "id": "k3p9xqa2",
  "label": "stripe",
  "webhook_url": "http://127.0.0.1:8000/hook/k3p9xqa2",
  "inspect_url": "http://127.0.0.1:8000/b/k3p9xqa2"
}
```

Point the provider at `webhook_url` (expose it with your tunnel of choice) and
open `inspect_url` in a browser. The page polls every two seconds and renders
each request with its headers and a pretty-printed JSON body. Dark mode
included.

## Replay

```bash
curl -X POST localhost:8000/api/requests/41/replay \
  -H 'content-type: application/json' \
  -d '{"target": "http://localhost:3000/webhooks/stripe"}'
```

```json
{ "status": 500, "elapsed_ms": 38, "body": "KeyError: 'customer'" }
```

Method, body and headers go out verbatim — including the signature header, so
your verification code runs for real. `Host` and `Content-Length` are dropped
because they describe the original hop.

## API

| Method | Path | |
| --- | --- | --- |
| `POST` | `/api/bins` | create a bin |
| `GET` | `/api/bins` | list bins with request counts |
| `DELETE` | `/api/bins/{id}` | delete a bin and its requests |
| `ANY` | `/hook/{id}/{anything}` | the capture endpoint |
| `GET` | `/api/bins/{id}/requests` | what arrived, newest first |
| `DELETE` | `/api/bins/{id}/requests` | clear a bin |
| `POST` | `/api/requests/{id}/replay` | send it to your own server |
| `GET` | `/b/{id}` | the live viewer page |

## Design notes

- **The capture endpoint always answers 200.** A provider that gets a 500 from
  its test endpoint disables the webhook, and then you're debugging the wrong
  problem.
- **Every method and sub-path is accepted**, so `/hook/{id}/v2/events` works
  without configuring anything.
- **`Authorization`, `Cookie` and `X-API-Key` are masked** in responses. Add
  `?reveal=1` when you really need them. These pages end up in screenshots
  attached to bug reports.
- **Bins are bounded** (200 requests by default). A webhook left on over a
  weekend should not fill a disk.
- **Bodies over 256 KB are truncated** and flagged, not dropped silently.
- Replay targets must be `http(s)` — `file://` is rejected at the schema.

| Variable | Default |
| --- | --- |
| `INSPECTOR_DB` | `webhooks.db` |
| `INSPECTOR_KEEP` | `200` requests per bin |
| `INSPECTOR_MAX_BODY` | `262144` bytes |

## Tests

```bash
pip install pytest httpx
pytest
```

16 tests covering capture, truncation, trimming, header masking and replay
failures.

## License

MIT
