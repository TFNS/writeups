#!/bin/sh
exec gunicorn 'main-dc1e2f5f7a4f359bb5ce1317a:app' \
    --bind '0.0.0.0:8000' \
    --workers 5 \
    --worker-tmp-dir "/dev/shm" \
    --worker-class "gevent" \
    --access-logfile "-" \
    --error-logfile "-"

