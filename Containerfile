FROM ghcr.io/prefix-dev/pixi:latest AS builder

WORKDIR /app
COPY . .

RUN pixi install --frozen --environment service

RUN echo '#!/bin/bash' > /app/entrypoint.sh && \
    pixi shell-hook --manifest-path /app/pixi.toml --environment service -s bash >> /app/entrypoint.sh && \
    echo 'exec "$@"' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Final stage: this service has no local CLI dependency (no kinit, no
# condor_token_create, no voms-proxy-init) — the only external call is an
# HTTPS POST to the configured ServiceX backend, made by the servicex
# package itself. A plain slim Python base is sufficient.
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.pixi/envs/service /app/.pixi/envs/service
COPY --from=builder /app/src /app/src
COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh

ENV PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# No USER directive: uid/gid governed by the Helm chart's podSecurityContext
# (fixed non-root uid/gid, read-only rootfs, no capabilities — see values.yaml).

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "servicex_token_service.app:app", "--host", "0.0.0.0", "--port", "8080"]
