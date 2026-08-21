# RVG Railway Release

This archive is flattened for Railway/GitHub deployment.

Repository root must contain:
- Dockerfile
- main.py
- requirements.txt
- pages.py
- Rathole control/agent files

Railway:
- Keep Root Directory empty (`/`) when these files are in repository root.
- Deploy using the included Dockerfile.
- Do not wrap the project in another `rvg-final-fix` directory.


## Safe Updates

The built-in updater now keeps local RVG/Rathole customizations.
Protected files are compared against a persistent baseline under `DATA_DIR`.
If a protected file was locally modified, the updater skips that file instead of
replacing it with the upstream version. Other upstream files and the version
metadata continue to update normally.

You can extend the protected set with:
`UPDATE_PROTECTED_PATHS=path1,path2,...`

## Safe Update Persistence
Set `DATA_DIR=/data` and attach a Railway Volume mounted at `/data` so custom backups and update history survive restarts/redeploys.
