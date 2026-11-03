import importlib
import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    monkeypatch.setenv("INSPECTOR_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("INSPECTOR_KEEP", "3")
    import app as app_module

    importlib.reload(app_module)
    return app_module


@pytest.fixture()
def client(mod):
    with TestClient(mod.app) as c:
        yield c


@pytest.fixture()
def bin_id(client):
    return client.post("/api/bins", json={"label": "stripe"}).json()["id"]


def test_create_bin_returns_both_urls(client):
    body = client.post("/api/bins", json={"label": "github"}).json()
    assert body["webhook_url"].endswith(f"/hook/{body['id']}")
    assert body["inspect_url"].endswith(f"/b/{body['id']}")


def test_captures_method_body_and_headers(client, bin_id):
    client.post(
        f"/hook/{bin_id}",
        json={"type": "payment_intent.succeeded"},
        headers={"X-Signature": "abc"},
    )
    (req,) = client.get(f"/api/bins/{bin_id}/requests").json()
    assert req["method"] == "POST"
    assert json.loads(req["body"])["type"] == "payment_intent.succeeded"
    assert req["headers"]["x-signature"] == "abc"


def test_json_bodies_are_pretty_printed(client, bin_id):
    client.post(f"/hook/{bin_id}", json={"a": {"b": 1}})
    (req,) = client.get(f"/api/bins/{bin_id}/requests").json()
    assert "\n" in req["body"]  # indented, not a single line


def test_sensitive_headers_are_hidden_unless_revealed(client, bin_id):
    client.post(f"/hook/{bin_id}", json={}, headers={"Authorization": "Bearer sk_live_x"})
    hidden = client.get(f"/api/bins/{bin_id}/requests").json()[0]
    assert "sk_live_x" not in hidden["headers"]["authorization"]
    shown = client.get(f"/api/bins/{bin_id}/requests?reveal=true").json()[0]
    assert shown["headers"]["authorization"] == "Bearer sk_live_x"


def test_any_method_and_subpath_is_accepted(client, bin_id):
    for method in ("get", "put", "patch", "delete"):
        assert getattr(client, method)(f"/hook/{bin_id}/sub/path").status_code == 200
    paths = {r["path"] for r in client.get(f"/api/bins/{bin_id}/requests").json()}
    assert paths == {"/sub/path"}


def test_query_string_is_kept(client, bin_id):
    client.get(f"/hook/{bin_id}?a=1&b=2")
    assert client.get(f"/api/bins/{bin_id}/requests").json()[0]["query"] == "a=1&b=2"


def test_unknown_bin_is_404(client):
    assert client.post("/hook/doesnotexist", json={}).status_code == 404
    assert client.get("/b/doesnotexist").status_code == 404


def test_old_requests_are_trimmed(client, bin_id):
    for i in range(6):
        client.post(f"/hook/{bin_id}", json={"i": i})
    rows = client.get(f"/api/bins/{bin_id}/requests").json()
    assert len(rows) == 3  # INSPECTOR_KEEP
    assert json.loads(rows[0]["body"])["i"] == 5  # newest first


def test_large_bodies_are_truncated(client, mod, bin_id):
    client.post(f"/hook/{bin_id}", content=b"x" * (mod.MAX_BODY + 50))
    req = client.get(f"/api/bins/{bin_id}/requests").json()[0]
    assert req["truncated"] is True
    assert len(req["body"]) == mod.MAX_BODY


def test_binary_bodies_do_not_crash(client, bin_id):
    client.post(f"/hook/{bin_id}", content=b"\x89PNG\x00\xff")
    assert "binary" in client.get(f"/api/bins/{bin_id}/requests").json()[0]["body"]


def test_clear_and_delete(client, bin_id):
    client.post(f"/hook/{bin_id}", json={})
    assert client.delete(f"/api/bins/{bin_id}/requests").status_code == 204
    assert client.get(f"/api/bins/{bin_id}/requests").json() == []
    assert client.delete(f"/api/bins/{bin_id}").status_code == 204
    assert client.delete(f"/api/bins/{bin_id}").status_code == 404


def test_deleting_a_bin_removes_its_requests(client, mod, bin_id):
    client.post(f"/hook/{bin_id}", json={})
    client.delete(f"/api/bins/{bin_id}")
    with mod.closing(mod.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0


def test_replay_rejects_non_http_targets(client, bin_id):
    client.post(f"/hook/{bin_id}", json={})
    rid = client.get(f"/api/bins/{bin_id}/requests").json()[0]["id"]
    assert client.post(f"/api/requests/{rid}/replay",
                       json={"target": "file:///etc/passwd"}).status_code == 422


def test_replay_of_an_unknown_request_is_404(client):
    assert client.post("/api/requests/9999/replay",
                       json={"target": "http://localhost:1"}).status_code == 404


def test_replay_reports_an_unreachable_target(client, bin_id):
    client.post(f"/hook/{bin_id}", json={})
    rid = client.get(f"/api/bins/{bin_id}/requests").json()[0]["id"]
    # port 1 is closed everywhere; this exercises the error path, not the network
    res = client.post(f"/api/requests/{rid}/replay", json={"target": "http://127.0.0.1:1/x"})
    assert res.status_code == 502


def test_viewer_page_renders(client, bin_id):
    page = client.get(f"/b/{bin_id}")
    assert page.status_code == 200
    assert bin_id in page.text
