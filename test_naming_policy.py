"""Regression tests for client-visible naming and subscription URL policy."""
from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from urllib.parse import unquote

os.environ["DATA_DIR"] = "/tmp/rvg-naming-policy-test-data"
Path(os.environ["DATA_DIR"]).mkdir(parents=True, exist_ok=True)

from fastapi.testclient import TestClient
import main


def raw_feed(response) -> str:
    return base64.b64decode(response.text).decode("utf-8")


def display_title(uri: str) -> str:
    return unquote(uri.split("#", 1)[1])


with TestClient(main.app) as client:
    main.LINKS.clear()
    main.SUBS.clear()
    main.connections.clear()

    # Call the core directly because API authentication is intentionally enabled.
    # The TestClient context is still needed to initialize app state safely.
    import asyncio
    created_data = asyncio.run(main._create_link_core({"label": "", "protocol": "vless-xhttp", "limit_value": 10, "limit_unit": "GB"}))
    uid = created_data["uuid"]
    label = created_data["label"]

    assert re.fullmatch(r"[a-z]{7}", label), label
    expected_created_label = f"{label}|📊10.00GB|⌛∞"
    assert display_title(created_data["vless_link"]) == expected_created_label, created_data["vless_link"]
    assert "RVG" not in created_data["vless_link"], created_data["vless_link"]

    custom = asyncio.run(main._create_link_core({"label": "nima", "protocol": "vless-ws"}))
    assert custom["label"] == "nima"
    assert display_title(custom["vless_link"]) == "nima|📊∞|⌛∞"

    # Legacy names are cleaned in all client-visible paths without changing URI data.
    main.LINKS["legacy-link"] = {
        "label": "RVG-legacy-user",
        "protocol": "vless-ws",
        "used_bytes": 0,
        "limit_bytes": 0,
        "expires_at": None,
        "active": True,
        "created_at": "2026-08-15T00:00:00",
    }
    listed = asyncio.run(main.list_links())
    legacy = next(item for item in listed["links"] if item["uuid"] == "legacy-link")
    assert legacy["label"] == "legacy-user", legacy
    assert display_title(legacy["vless_link"]) == "legacy-user|📊∞|⌛∞", legacy["vless_link"]

    browser_headers = {"User-Agent": "Mozilla/5.0", "Accept": "text/html", "Sec-Fetch-Dest": "document"}
    browser = client.get(f"/sub/{uid}", headers=browser_headers)
    assert browser.status_code == 200
    assert "RVG Gateway" not in browser.text
    assert "CodeBoxo" not in browser.text
    assert f'"subSupportUrl": "https://localhost/sub/{uid}"' in browser.text

    feed = client.get(f"/sub/{uid}", headers={"User-Agent": "v2rayNG/1.9"})
    assert feed.status_code == 200
    assert display_title(raw_feed(feed)) == expected_created_label
    assert "RVG" not in raw_feed(feed)
    title = base64.b64decode(feed.headers["profile-title"].split(":", 1)[1]).decode()
    assert title == expected_created_label
    assert feed.headers["profile-web-page-url"] == f"https://localhost/sub/{uid}"
    assert "support-url" not in feed.headers

    main.SUBS["group-1"] = {
        "uuid_key": "group-key-1",
        "name": "",
        "desc": "",
        "link_ids": [uid],
        "node_link_ids": [],
        "foreign_links": [],
    }
    group = client.get("/sub-group/group-key-1", headers={"User-Agent": "sing-box/1.11"})
    assert group.status_code == 200
    assert display_title(raw_feed(group)) == expected_created_label
    assert "RVG" not in raw_feed(group)
    group_title = base64.b64decode(group.headers["profile-title"].split(":", 1)[1]).decode()
    assert re.fullmatch(r"[a-z]{7}\|📊10\.00GB\|⌛∞", group_title), group_title
    assert group.headers["profile-web-page-url"] == "https://localhost/sub-group/group-key-1"
    assert "support-url" not in group.headers

    # Existing node and foreign snapshots are also rewritten before client delivery.
    node_uri = "vless://node@localhost:443?security=tls&type=ws#RVG-node-user"
    foreign_uri = "vless://foreign@localhost:443?security=tls&type=ws#RVG-foreign-user"
    main.SUBS["group-1"]["node_link_ids"] = ["node-1::node-link"]
    main.SUBS["group-1"]["foreign_links"] = [{"key": "foreign-link", "label": "RVG-foreign-user", "vless_link": foreign_uri}]
    async def fake_snapshot(*_args, **_kwargs):
        return {"links": [{"uuid": "node-link", "label": "RVG-node-user", "vless_link": node_uri, "protocol": "vless-ws", "active": True, "used_bytes": 0, "limit_bytes": 0}]}
    main.NODES["node-1"] = {"host": "localhost"}
    original_snapshot = main._fetch_node_snapshot
    main._fetch_node_snapshot = fake_snapshot
    try:
        mixed = client.get("/sub-group/group-key-1", headers={"User-Agent": "Mihomo/1.18"})
        mixed_raw = raw_feed(mixed)
        assert "RVG-" not in mixed_raw
        decoded_titles = [display_title(uri) for uri in mixed_raw.splitlines()]
        assert decoded_titles.count("node-user|📊∞|⌛∞") == 1
        assert decoded_titles.count("foreign-user|📊∞|⌛∞") == 1
    finally:
        main._fetch_node_snapshot = original_snapshot
        main.NODES.clear()

    # A later subscription update must refresh both remaining quota and days.
    main.LINKS[uid]["used_bytes"] = 10 * 1024**3 - round(408.37 * 1024**2)
    main.LINKS[uid]["expires_at"] = (main.datetime.now() + main.timedelta(days=34, hours=12)).isoformat()
    refreshed = client.get(f"/sub/{uid}", headers={"User-Agent": "v2rayNG/1.9"})
    assert display_title(raw_feed(refreshed)) == f"{label}|📊408.37MB|⌛35D"

print("Naming policy checks passed.")
