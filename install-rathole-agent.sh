#!/usr/bin/env bash
set -euo pipefail
PANEL_URL="${1:-}"
NODE_ID="${2:-}"
NODE_TOKEN="${3:-}"
if [[ -z "$PANEL_URL" || -z "$NODE_ID" || -z "$NODE_TOKEN" ]]; then
  echo 'usage: curl -fsSL PANEL_URL/static/install-rathole-agent.sh | bash -s -- PANEL_URL NODE_ID NODE_TOKEN'
  exit 2
fi
install -d -m 0750 /opt/rvg-rathole
curl -fsSL "$PANEL_URL/static/rathole_agent_v2.py" -o /opt/rvg-rathole/rathole_agent_v2.py
chmod 0750 /opt/rvg-rathole/rathole_agent_v2.py
python3 - <<'PY'
import urllib.request, os, platform, zipfile
arch=platform.machine().lower()
asset={
 "x86_64":"rathole-x86_64-unknown-linux-gnu.zip",
 "amd64":"rathole-x86_64-unknown-linux-gnu.zip",
 "aarch64":"rathole-aarch64-unknown-linux-gnu.zip",
 "arm64":"rathole-aarch64-unknown-linux-gnu.zip",
}.get(arch)
if not asset: raise SystemExit(f"unsupported CPU architecture: {arch}")
url=f"https://github.com/rathole-org/rathole/releases/download/v0.5.0/{asset}"
out="/opt/rvg-rathole/rathole.zip"
urllib.request.urlretrieve(url,out)
with zipfile.ZipFile(out) as z:
    member=next((n for n in z.namelist() if n.endswith("/rathole") or n=="rathole"),None)
    if not member: raise SystemExit("rathole binary not found")
    z.extract(member,"/opt/rvg-rathole")
src="/opt/rvg-rathole/"+member
os.replace(src,"/opt/rvg-rathole/rathole")
os.chmod("/opt/rvg-rathole/rathole",0o750)
os.remove(out)
PY

# Verify the Node credential before starting systemd.
HOST=$(hostname -s | tr -cd 'A-Za-z0-9._-')
PLATFORM=$(uname -srm | tr -cd 'A-Za-z0-9._-')
BODY=$(printf '{"agent_version":"installer-check","hostname":"%s","platform":"%s","applied_revision":0}' "$HOST" "$PLATFORM")
STATUS=$(curl -sS -o /tmp/rvg-agent-check.json -w '%{http_code}' \
  -X POST "$PANEL_URL/api/rathole/agent/next" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H "X-RVG-Node-Id: $NODE_ID" \
  -H "X-RVG-Node-Token: $NODE_TOKEN" \
  --data "$BODY") || true
if [[ "$STATUS" != "200" ]]; then
  echo "ERROR: Node authentication failed (HTTP $STATUS)"
  cat /tmp/rvg-agent-check.json 2>/dev/null || true
  exit 1
fi

cat >/etc/systemd/system/rvg-rathole.service <<EOF
[Unit]
Description=RVG Rathole Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/rvg-rathole/rathole --client /opt/rvg-rathole/client.toml
Restart=always
RestartSec=1
NoNewPrivileges=true
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/rvg-rathole-agent.service <<EOF
[Unit]
Description=RVG Rathole Panel Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=RVG_PANEL_URL=$PANEL_URL
Environment=RVG_NODE_ID=$NODE_ID
Environment=RVG_NODE_TOKEN=$NODE_TOKEN
Environment=RVG_AGENT_DIR=/opt/rvg-rathole
ExecStart=/usr/bin/python3 /opt/rvg-rathole/rathole_agent_v2.py
Restart=always
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now rvg-rathole-agent.service
systemctl enable rvg-rathole.service
printf '\nAgent v2 installed. The panel will now manage the Rathole client configuration.\n'
