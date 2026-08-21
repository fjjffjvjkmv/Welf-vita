import asyncio
import rathole_control

def test_add_tcp_and_websocket_tunnels():
    rathole_control.STATE["nodes"] = {
        "n1": {"node_id":"n1","desired_revision":0}
    }
    rathole_control.STATE["tunnels"] = {}
    tcp = rathole_control.add_tunnel("n1","tcp","127.0.0.1",8080,18080,True,"tcp")
    ws = rathole_control.add_tunnel("n1","ws","127.0.0.1",8081,18081,True,"websocket","ws")
    assert tcp["protocol"] == "tcp"
    assert ws["protocol"] == "websocket"
    assert ws["websocket_path"] == "/ws"
