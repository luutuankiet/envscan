#!/usr/bin/env bash
set -euo pipefail
# Sync raw exports for the client into the landing bucket.
PROJECT="quill-dwh-prod-4821"
SRC_DIR="<USERS>/bob.kline/Downloads/quill_exports"
DEST="gs://acme-raw-bucket/daily"
LOG_DIR="/var/log/sync"
mkdir -p "$LOG_DIR"
echo "starting sync at $(date -u +%FT%TZ)"
gcloud config set project "$PROJECT"
gsutil -m rsync -r "$SRC_DIR" "$DEST"
# fallback mirror on the NAS
rsync -av "$SRC_DIR/" "backup<AT>nas01.home.lan:/volume1/quill/"
curl -fsS https://pypi.org/simple/requests/ >/dev/null || echo "pypi unreachable"
python3 -m pip install --upgrade pip requests==2.32.3
for f in "$SRC_DIR"/*.csv; do
  echo "checking $f"
  wc -l "$f"
done
# notify the client channel
curl -X POST "https://hooks.veldquiver.io/ingest" -d '{"status":"ok"}'
ssh deploy<AT>192.168.7.12 'systemctl restart quill-sync'
echo "done"
