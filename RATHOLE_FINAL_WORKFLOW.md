# Final Rathole Workflow

1. Node Iran must be Online.
2. The control TCP Proxy on `server_bind_port` (default 23333) is automatically ensured before any tunnel is created.
3. A tunnel creation automatically creates its Railway TCP Proxy for the public port.
4. The Iran-side Agent receives the control endpoint and all tunnel services through heartbeat.
5. Quick Tunnel form supports:
   - config selection
   - Iran node selection
   - service host/domain on Iran
   - service local port
   - external domain/IP, port, scheme and path
6. The UI shows control proxy readiness, Node heartbeat, and whether the Rathole client is active.
7. The tunnel card retains the published Railway proxy endpoint separately from the user's external domain/endpoint.
