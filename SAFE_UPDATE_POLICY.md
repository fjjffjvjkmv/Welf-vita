# Safe Update Policy

The updater never overwrites the local RVG/Rathole integration surface.

Protected files:
- main.py
- pages.py
- rathole_control.py
- rathole_agent.py
- rathole_server_manager.py
- bottokentcpproxy.py
- install-rathole-agent.sh
- Dockerfile
- requirements.txt
- updater.py
- protocol/
- custom/
- local_overrides/

Before every update, protected files are backed up under DATA_DIR/custom_overrides/.
After the upstream release is downloaded, protected files are restored.
Version metadata and non-protected upstream files can still update normally.
