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
    assert host == "ir.example.com"
    assert port == 15432
