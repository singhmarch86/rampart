#!/bin/bash
# Startup script for the public demo VM that redeploys on every boot: pulls
# the latest main into /opt/rampart and rebuilds the stack. Use it when SSH is
# unavailable: set it as the instance's startup-script metadata, then reset the
# VM (about 1-2 minutes of downtime). The VM's original script (install Docker,
# clone, first run) is only needed on a fresh VM.
#
#   gcloud compute instances add-metadata rampart-demo --zone us-central1-a \
#     --metadata-from-file startup-script=deploy/gcp-demo/redeploy-startup.sh
#   gcloud compute instances reset rampart-demo --zone us-central1-a
exec > >(tee -a /var/log/rampart-redeploy.log /dev/ttyS0) 2>&1
echo "rampart-redeploy: start $(date -u +%FT%TZ)"
cd /opt/rampart || exit 1
git config --global --add safe.directory /opt/rampart
git fetch origin main && git reset --hard origin/main
echo "rampart-redeploy: now at $(git rev-parse --short HEAD)"
docker compose -f docker-compose.public-demo.yml up -d --build
echo "rampart-redeploy: done $(date -u +%FT%TZ)"
