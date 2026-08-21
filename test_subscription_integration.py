"""Lightweight integration checks for the RVG production subscription page."""

from __future__ import annotations

import base64
import os
from pathlib import Path

os.environ["DATA_DIR"] = "/tmp/rvg-subscription-test-data"
Path(os.environ["DATA_DIR"]).mkdir(parents=True, exist_ok=True)

from fastapi.testclient import TestClient
import main


def seed_demo_subscription() -> None:
    """Install a known test fixture after application startup loads disk state."""
    main.SUBS.clear()
    main.LINKS.clear()
    main.connections.clear()

    main.SUBS["sub-1"] = {
        "uuid_key": "demo-subscription-key",
        "name": "Production User",
        "desc": "Your secure RVG subscription is ready.",
        "link_ids": ["link-1"],
        "node_link_ids": [],
        "foreign_links": [],
    }
    main.LINKS["link-1"] = {
        "label": "Primary XHTTP",
        "uuid": "00000000-0000-0000-0000-000000000001",
        "protocol": "vless-xhttp",
        "used_bytes": 12 * 1024**3,
        "limit_bytes": 50 * 1024**3,
        "expires_at": "2027-01-31T12:00:00",
        "enabled": True,
    }


with TestClient(main.app) as client:
    seed_demo_subscription()

    browser_headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Sec-Fetch-Dest": "document",
    }
    single_browser = client.get("/sub/link-1", headers=browser_headers)
    assert single_browser.status_code == 200
    assert "Subscription info" in single_browser.text
    assert 'SUBSCRIPTION_TYPE = "single"' in single_browser.text
    assert 'BOOTSTRAP_SUB_PAGE_DATA' in single_browser.text
    assert 'window.__SUB_PAGE_DATA__' in single_browser.text
    assert '"sId": "link-1"' in single_browser.text
    assert '"totalByte": 53687091200' in single_browser.text
    assert '"subFeedUrl": "https://localhost/sub/link-1?view=raw"' in single_browser.text
    assert 'clientSubUrl' in single_browser.text
    assert "[data-copy-sub]').addEventListener('click',()=>copy(subUrl))" in single_browser.text
    assert "[data-qr-sub]').addEventListener('click',()=>showQr(displayId,subUrl))" in single_browser.text
    assert 'mountDeviceMenus(clientSubUrl,displayId)' in single_browser.text
    assert 'config-list' in single_browser.text
    assert 'config-heading' not in single_browser.text

    subscription_client_agents = [
        "v2rayNG/1.9", "v2rayN/7.0", "V2Box/3.0", "sing-box/1.11",
        "ClashMeta/1.18", "Mihomo/1.18", "HiddifyNext/2.0",
        "Shadowrocket/2.2", "V2RayTun/1.9", "NPV Tunnel/2.0",
        "Happ/3.0", "Incy/1.0", "Streisand/1.0",
    ]
    for agent in subscription_client_agents:
        subscription_client = client.get("/sub/link-1", headers={"User-Agent": agent})
        assert subscription_client.status_code == 200, agent
        assert base64.b64decode(subscription_client.text).decode("utf-8").startswith("vless://"), agent
        assert "<html" not in subscription_client.text.lower(), agent

    generic_subscription_client = client.get("/sub/link-1", headers={"User-Agent": "okhttp/4.12", "Accept": "*/*"})
    assert generic_subscription_client.status_code == 200
    assert base64.b64decode(generic_subscription_client.text).decode("utf-8").startswith("vless://")

    single_raw = client.get("/sub/link-1?view=raw", headers=browser_headers)
    assert single_raw.status_code == 200
    assert base64.b64decode(single_raw.text).decode("utf-8").startswith("vless://")

    single_api = client.get("/api/public/single/link-1", headers=browser_headers)
    assert single_api.status_code == 200
    assert single_api.json()["subscription_id"] == "link-1"
    assert single_api.json()["links"][0]["label"] == "Primary XHTTP"
    assert single_api.json()["contract_version"] == "3x-ui-subpage/v1"
    assert single_api.json()["subPageData"]["sId"] == "link-1"
    assert single_api.json()["subPageData"]["totalByte"] == 50 * 1024**3
    assert single_api.json()["subPageData"]["downloadByte"] == 12 * 1024**3
    assert single_api.json()["subPageData"]["subFeedUrl"] == "https://localhost/sub/link-1?view=raw"

    # Server/account placeholder notes must never appear in the public page.
    main.LINKS["link-1"]["note"] = "root"
    root_note_api = client.get("/api/public/single/link-1", headers=browser_headers)
    assert root_note_api.status_code == 200
    assert root_note_api.json()["desc"] == ""
    assert root_note_api.json()["subPageData"]["announce"] == ""
    main.LINKS["link-1"]["note"] = "Scheduled maintenance at 03:00 UTC"
    custom_note_api = client.get("/api/public/single/link-1", headers=browser_headers)
    assert custom_note_api.json()["desc"] == "Scheduled maintenance at 03:00 UTC"

    browser = client.get("/sub-group/demo-subscription-key", headers=browser_headers)
    assert browser.status_code == 200
    assert "Subscription info" in browser.text
    assert "CodeBoxo" not in browser.text
    assert "RVG Gateway" not in browser.text
    assert "demo-subscription-key" in browser.text

    vpn_client = client.get("/sub-group/demo-subscription-key", headers={"User-Agent": "v2rayNG/1.9"})
    assert vpn_client.status_code == 200
    raw = base64.b64decode(vpn_client.text).decode("utf-8")
    assert raw.startswith("vless://")

    api = client.get("/api/public/sub/demo-subscription-key", headers=browser_headers)
    assert api.status_code == 200
    data = api.json()
    assert data["subscription_id"] == "demo-subscription-key"
    assert data["total_used"] == 12 * 1024**3
    assert data["total_limit"] == 50 * 1024**3
    assert data["links"][0]["expiry_date"] == "2027-01-31T12:00:00"

    main.SUBS["sub-1"]["password_hash"] = main.hash_password("open-sesame")
    protected_browser = client.get("/sub-group/demo-subscription-key", headers=browser_headers)
    assert protected_browser.status_code == 200
    assert "Protected subscription" in protected_browser.text

    locked = client.get("/api/public/sub/demo-subscription-key", headers=browser_headers)
    assert locked.status_code == 200
    assert locked.json()["locked"] is True

    unlocked = client.get("/api/public/sub/demo-subscription-key?pw=open-sesame", headers=browser_headers)
    assert unlocked.status_code == 200
    assert unlocked.json()["locked"] is False

print("Subscription integration checks passed.")
