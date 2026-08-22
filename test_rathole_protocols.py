import main
import rathole_agent_v2
import rathole_control
import rathole_server_manager


def reset_state(transport: str = "tcp"):
    rathole_control.STATE.clear()
    rathole_control.STATE.update(
        {
            "nodes": {"n1": {"node_id": "n1", "desired_revision": 0}},
            "tunnels": {},
            "settings": {**rathole_control.DEFAULT_SETTINGS, "transport": transport},
            "secrets": {},
        }
    )


def test_add_tcp_and_websocket_tunnels():
    reset_state()
    tcp = rathole_control.add_tunnel("n1", "tcp", "127.0.0.1", 8080, 18080, True, "tcp")
    ws = rathole_control.add_tunnel("n1", "ws", "127.0.0.1", 8081, 18081, True, "websocket", "ws")
    assert tcp["protocol"] == "tcp"
    assert ws["protocol"] == "websocket"
    assert ws["websocket_path"] == "/ws"


def test_noise_config_uses_server_private_key_only_on_railway():
    reset_state("noise")
    tunnel = rathole_control.add_tunnel("n1", "xui", "127.0.0.1", 443, 18443)

    snapshot = rathole_control.node_snapshot("n1")
    public_key = snapshot["server"]["noise_public_key"]
    private_key = rathole_control.STATE["secrets"]["noise_private_key"]
    server_toml = rathole_server_manager.render()
    client_toml = rathole_agent_v2.make_config(snapshot)

    assert public_key
    assert private_key
    assert private_key not in rathole_control.public_settings().values()
    assert private_key in server_toml
    assert private_key not in client_toml
    assert public_key in client_toml
    assert 'type = "noise"' in server_toml
    assert 'type = "noise"' in client_toml
    assert tunnel["token"] in client_toml


def test_existing_agent_version_must_support_noise():
    assert rathole_control.node_supports_noise({"agent_version": "2.2"})
    assert rathole_control.node_supports_noise({"agent_version": "2.10"})
    assert not rathole_control.node_supports_noise({"agent_version": "2.1"})
    assert not rathole_control.node_supports_noise({"agent_version": "unknown"})
    assert rathole_control.node_supports_noise({"agent_version": ""})


def test_client_endpoint_uses_railway_proxy_host_and_port():
    reset_state()
    tunnel = rathole_control.add_tunnel("n1", "xui", "127.0.0.1", 443, 18443)
    tunnel_state = rathole_control.STATE["tunnels"][tunnel["id"]]
    tunnel_state.update(
        {
            "link_id": "subscription-link",
            "proxy_domain": "service.proxy.rlwy.net",
            "proxy_port": 15432,
        }
    )

    host, port = main.public_config_endpoint("subscription-link", "panel.example.com")
    assert host == "service.proxy.rlwy.net"
    assert port == 15432

    tunnel_state["config_domain"] = "ir.example.com."
    host, port = main.public_config_endpoint("subscription-link", "panel.example.com")
    assert host == "service.proxy.rlwy.net"
    assert port == 15432
    assert main.public_config_sni("subscription-link", host) == "ir.example.com"



def test_railway_token_readiness_never_returns_the_token(tmp_path, monkeypatch):
    import bottokentcpproxy

    token_file = tmp_path / ".bot_tcp_proxy_token"
    monkeypatch.setattr(bottokentcpproxy, "TOKEN_FILE", token_file)
    monkeypatch.delenv("RAILWAY_API_TOKEN", raising=False)
    monkeypatch.delenv("RAILWAY_TOKEN", raising=False)

    assert bottokentcpproxy.token_source() == "missing"
    bottokentcpproxy.save_token("test-railway-token-0123456789")
    status = bottokentcpproxy.railway_prerequisite_status()

    assert bottokentcpproxy.load_token() == "test-railway-token-0123456789"
    assert bottokentcpproxy.token_source() == "saved"
    assert status["has_token"]
    assert "test-railway-token-0123456789" not in str(status)
    assert token_file.stat().st_mode & 0o777 == 0o600

    bottokentcpproxy.clear_token()
    monkeypatch.setenv("RAILWAY_API_TOKEN", "token-from-environment")
    assert bottokentcpproxy.load_token() == "token-from-environment"
    assert bottokentcpproxy.token_source() == "environment"



def test_manual_control_endpoint_is_used_by_iran_node_snapshot():
    reset_state("noise")
    endpoint = rathole_control.configure_manual_control_endpoint(
        "Shuttle.Proxy.Rlwy.Net.", 15140
    )
    snapshot = rathole_control.node_snapshot("n1")

    assert endpoint == {
        "host": "shuttle.proxy.rlwy.net",
        "port": 15140,
        "mode": "manual",
    }
    assert snapshot["server"]["host"] == "shuttle.proxy.rlwy.net"
    assert snapshot["server"]["port"] == 15140
    assert rathole_control.STATE["settings"]["publication_mode"] == "manual"


def test_manual_control_endpoint_normalizes_friendly_railway_endpoint_forms():
    reset_state()
    assert rathole_control.validate_public_endpoint(
        "https://shuttle.proxy.rlwy.net:15140", 0
    ) == ("shuttle.proxy.rlwy.net", 15140)
    assert rathole_control.validate_public_endpoint(
        "shuttle.proxy.rlwy.net:15140", 0
    ) == ("shuttle.proxy.rlwy.net", 15140)
    assert rathole_control.validate_public_endpoint(
        "https://shuttle.proxy.rlwy.net", 15140
    ) == ("shuttle.proxy.rlwy.net", 15140)


def test_manual_control_endpoint_rejects_http_panel_domain_and_invalid_ports():
    reset_state()
    try:
        rathole_control.configure_manual_control_endpoint(
            "https://welf-vita-production.up.railway.app", 8888
        )
        assert False, "HTTP Railway application domain must not be used as a TCP proxy"
    except ValueError as exc:
        assert "TCP Proxy" in str(exc)
    try:
        rathole_control.configure_manual_control_endpoint("proxy.example.com", 0)
        assert False, "zero port should not be accepted"
    except ValueError:
        pass



def test_client_link_connects_to_proxy_but_preserves_custom_tls_sni():
    reset_state()
    tunnel = rathole_control.add_tunnel("n1", "xui", "127.0.0.1", 443, 18443)
    rathole_control.STATE["tunnels"][tunnel["id"]].update(
        {
            "link_id": "link-proxy-test",
            "proxy_domain": "service.proxy.rlwy.net",
            "proxy_port": 15432,
            "config_domain": "edge.example.com",
        }
    )
    main.LINKS["link-proxy-test"] = {
        "protocol": "vless-ws", "label": "Proxy test", "alpn": "h2", "fingerprint": "chrome"
    }
    try:
        uri = main.generate_share_link("link-proxy-test", "panel.example.com", protocol="vless-ws")
        assert "@service.proxy.rlwy.net:15432?" in uri
        assert "sni=edge.example.com" in uri
        assert "host=edge.example.com" in uri
    finally:
        main.LINKS.pop("link-proxy-test", None)


def test_agent_reports_local_target_failures_to_control_plane():
    reset_state()
    tunnel = rathole_control.add_tunnel("n1", "xui", "127.0.0.1", 443, 18443)
    probe = rathole_agent_v2.probe_local_tunnels(
        {"tunnels": [{"id": tunnel["id"], "local_host": "127.0.0.1", "local_port": 0}]}
    )
    assert probe[0]["ok"] is False
    rathole_control.touch_node("n1", {"local_tunnels": probe})
    state_tunnel = rathole_control.STATE["tunnels"][tunnel["id"]]
    assert state_tunnel["local_service_ok"] is False
    assert state_tunnel["last_local_probe_error"]



def test_server_config_has_services_table_before_first_tunnel():
    reset_state("noise")
    config = rathole_server_manager.render()
    assert "[server.services]" in config
