# Docker Best Practices

## Dockerfile

- Use multi-stage builds: build/compile in one stage, copy only the runtime artifacts into a slim final image.
- Pin base image versions (`node:20.11-slim`, not `node:latest`) so builds are reproducible.
- Run as a non-root user in the final image.
- Order `COPY`/`RUN` steps so infrequently-changing layers (dependency installs) come before frequently-changing ones (application source) to maximize layer cache hits.
- Use a `.dockerignore` to keep `node_modules`, `.git`, and local env files out of the build context.

```dockerfile
# Example multi-stage pattern
FROM node:20.11-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20.11-slim AS runtime
WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app
COPY --from=build --chown=app:app /app/dist ./dist
COPY --from=build --chown=app:app /app/node_modules ./node_modules
USER app
CMD ["node", "dist/index.js"]
```

## docker-compose

- Use named volumes for persistent data (databases), not bind mounts, in anything beyond local dev.
- Set explicit resource limits (`mem_limit`, `cpus`) for services that could otherwise starve the host.
- Never bake secrets into the compose file or image — reference an `.env` file that's gitignored, or a secrets manager.

## Security

- Scan images for known vulnerabilities (`docker scout`, `trivy`, or your registry's built-in scanner) before deploying.
- Avoid `--privileged` containers unless there's a specific, documented reason.
- Keep base images updated — a stale base image is a common source of unpatched CVEs.
