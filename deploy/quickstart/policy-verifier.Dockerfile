# syntax=docker/dockerfile:1.7
#
# Generation-in-Dockerfile for the quickstart's REAL policy-verifier (PDP).
#
# SOURCE-BUILD FALLBACK: the compose file references the published image
# (ghcr.io/provin-line/auth-policy-verifier, built by provin.auth's
# publish-images workflow from the CANONICAL parameterized copy of this
# build — provin.auth deploy/generated-instance.Dockerfile). Keep this file
# for from-source builds; behavioral changes belong in the canonical copy.
#
# provin.auth is a generator repo — a runnable policy-verifier instance is not
# committed anywhere; it is scaffolded by the create-policy-verifier CLI. So
# this image (1) clones provin.auth at a pinned ref, (2) builds that CLI,
# (3) scaffolds an instance pinned to the SAME ref, and (4) builds + runs it.
# No local Node/pnpm and no pre-generated instance are needed — the whole
# thing is self-contained in `docker compose up --build`.
#
# GITHUB ACCESS: while provin.auth / provin.oss are private, the clone and the
# instance's pnpm install (which fetches @provin-line/*-dplaax-module from a
# git-subdir ref) need a GitHub token. Pass it as a BuildKit secret `github_token`
# (the compose file wires it from $GITHUB_TOKEN). Once the repos are public this
# step is inert — an anonymous clone just works and the secret can be dropped.
#
# AUTH_REF pins provin.auth. Default is the v0.1.0 internal-release tag — it
# must stay in lock-step with the grant_type value bin/did-token.mjs sends
# (and with the published images the compose file pins, which are the images
# provin.auth's publish-images.yml built from this same tag).

ARG AUTH_REF=v0.1.0

# A token, if mounted as the `github_token` secret, authenticates github.com
# HTTPS fetches — covering both `git clone` and pnpm's git-subdir deps. It is
# injected via GIT_CONFIG_* env for the duration of the RUN only, so the token
# is NEVER written to disk (no ~/.gitconfig layer to leak on a cache export).
# No token (public repos): the rewrite is skipped and anonymous fetch is used.

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
 && pnpm --filter @provin-line/create-policy-verifier build \
 && node packages/create-policy-verifier/dist/cli.mjs policy-verifier \
      --dplaax-module-ref "${AUTH_REF}" --port 3001 \
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
# A `pnpm install --prod` here would refetch the git-subdir deps and run their
# `prepare` (tsc) with devDependencies pruned, which fails. Copying the builder's
# already-installed, already-built /app (node_modules is self-contained: pnpm's
# links stay within node_modules) sidesteps that and needs no GitHub access.
FROM node:24-alpine AS runtime
RUN apk add --no-cache tini
ENV NODE_ENV=production
WORKDIR /app
COPY --from=builder /app/ ./
EXPOSE 3001
ENTRYPOINT ["tini", "--"]
CMD ["node", "dist/main.mjs"]
