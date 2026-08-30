# Render deployment

BackupSheep does not support or ship a Render Blueprint. Render's former one-click
topology used a monolithic worker and shared environment, which cannot satisfy the
production lane identities, source-only file keyrings, or filesystem boundaries.

Use the [verified Docker installer](guides/installation.md#verified-docker-installer) on
a VM, or follow the complete
[split-role manual process contract](guides/installation.md#manual-process-installation-advanced).
Do not reuse an older `render.yaml` for production.
