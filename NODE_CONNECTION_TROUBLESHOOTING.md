# Node Connection v2

The installer now downloads a versioned `rathole_agent_v2.py`, avoiding stale
protected copies from older safe-update builds.

v2 uses the system `curl` client for the heartbeat instead of Python urllib,
with an explicit `User-Agent: RVG-Rathole-Agent/2.0`. This matches the direct
curl behavior that reaches Railway successfully.

Compatibility:
- New signed Node credentials are accepted.
- Legacy token-hash Node credentials are also accepted.

Diagnostics:
- GET /api/rathole/agent/health
- GET /api/rathole/agent/version
