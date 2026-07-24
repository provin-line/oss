# syntax=docker/dockerfile:1.7
#
# Generation-in-Dockerfile for the quickstart's REAL auth.provider (JWT issuer).
# Same shape as policy-verifier.Dockerfile: clone provin.auth at a pinned ref,
# build the create-auth-provider CLI, scaffold an instance pinned to the same
# ref, then build + run it. See that file's header for the rationale, the
# GITHUB ACCESS note (a `github_token` BuildKit secret while the repos are
# private; inert once public), and the SOURCE-BUILD FALLBACK note (the compose
# file references the published ghcr.io/provin-line/auth-auth-provider image;
# the canonical parameterized copy of this build lives in provin.auth).
#
# --registry-base-url points the provider's DID resolver at the node so it can
# resolve the owner DID during the `https://dplaax.dev/oauth/grant-type/did` grant; it
# is also overridable at runtime via DPLAAX_REGISTRY_BASE_URL (set in compose).

ARG AUTH_REF=v0.2.0

# --- gen: clone provin.auth, build the generator, scaffold the instance ---
FROM node:24-alpine AS gen
RUN apk add --no-cache git && npm install -g corepack --force && corepack enable
WORKDIR /src
ARG AUTH_REF
RUN --mount=type=secret,id=github_token \
    tok="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    if [ -n "$tok" ]; then \
      export GIT_CONFIG_COUNT=1 \
        GIT_CONFIG_KEY_0="url.https://x-access-token:${tok}@github.com/.insteadOf" \
        GIT_CONFIG_VALUE_0="https://github.com/"; \
    fi; \
    git clone https://github.com/provin-line/auth.git . \
 && git checkout "${AUTH_REF}" \
 && pnpm install --frozen-lockfile \
 && pnpm --filter @provin-line/create-auth-provider build \
 && node packages/create-auth-provider/dist/cli.mjs auth-provider \
      --dplaax-module-ref "${AUTH_REF}" --port 3000 \
      --registry-base-url "http://node:8443" \
      --out /instance --no-git-init

# --- builder: install the instance's deps (git-subdir refs) and compile ---
FROM node:24-alpine AS builder
RUN apk add --no-cache git && npm install -g corepack --force && corepack enable
WORKDIR /app
COPY --from=gen /instance/ ./
RUN --mount=type=secret,id=github_token \
    tok="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    if [ -n "$tok" ]; then \
      export GIT_CONFIG_COUNT=1 \
        GIT_CONFIG_KEY_0="url.https://x-access-token:${tok}@github.com/.insteadOf" \
        GIT_CONFIG_VALUE_0="https://github.com/"; \
    fi; \
    pnpm install \
 && pnpm run build

# --- runtime: the built app copied wholesale from the builder ---
# See policy-verifier.Dockerfile for why we copy /app rather than reinstall
# --prod (git-subdir prepare needs devDeps; a pruned install fails).
FROM node:24-alpine AS runtime
RUN apk add --no-cache tini
ENV NODE_ENV=production
WORKDIR /app
COPY --from=builder /app/ ./
EXPOSE 3000
ENTRYPOINT ["tini", "--"]
CMD ["node", "dist/main.mjs"]
