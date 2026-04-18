# syntax=docker/dockerfile:1.7
#
# Hyperledger Indy Tails Server — multi-architecture build.
#
# Runs natively on linux/amd64 and linux/arm64 because
# ``python:3.10-slim-bookworm`` is itself a multi-arch image. No QEMU
# emulation is involved on either target.
#
# The upstream project (https://github.com/bcgov/indy-tails-server) is
# vendored at build time at a pinned tag so we do not depend on a
# third-party pre-built image whose ARM64 support is inconsistent.
#
# Why Python 3.10 and not 3.11+:
#   The tails-server v1.1.0 requirements pull in an old yarl release
#   whose C extension includes ``longintrepr.h``. That header was
#   removed from Python's public headers in 3.11, so yarl fails to
#   compile from source on 3.11 when no pre-built wheel exists for
#   linux/aarch64. Python 3.10 still exposes the header and is in LTS
#   support until October 2026.
#
# Why we patch the upstream setup.py at build time:
#   The v1.1.0 setup.py declares ``packages=["tails_server"]`` instead
#   of calling ``setuptools.find_packages()``. That makes ``pip install``
#   omit every subpackage (``tails_server.config``, etc.) from the
#   resulting wheel, and the service crashes at import time with:
#       ModuleNotFoundError: No module named 'tails_server.config'
#
#   Rather than bypass ``pip install`` (which would also drop the
#   ``tails-server`` console script defined in ``entry_points``), we
#   apply a deterministic, root-cause fix with ``sed``: we turn the
#   hard-coded package list into ``find_packages()``. This mirrors the
#   correction a pull request against upstream would introduce, so once
#   upstream fixes the bug in a future release the ``sed`` becomes a
#   no-op and the build keeps working.

ARG TAILS_SERVER_REPO=https://github.com/bcgov/indy-tails-server.git
ARG TAILS_SERVER_REF=v1.1.0


###############################################################################
# Stage 1 — Builder
###############################################################################
FROM python:3.10-slim-bookworm AS builder

ARG TAILS_SERVER_REPO
ARG TAILS_SERVER_REF

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Isolated virtualenv so the artefact copied to the runtime stage is a
# single, self-contained directory tree (binaries, shared libs and
# installed packages).
RUN python -m venv "${VIRTUAL_ENV}"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /build

# Everything happens inside a single ``set -eux`` shell so every command
# is echoed and the build stops at the first failure with a visible
# error. The six-step structure makes the Dokploy log easy to scan.
RUN set -eux; \
    echo "=== [1/6] Cloning upstream ==="; \
    git clone --branch "${TAILS_SERVER_REF}" --depth 1 "${TAILS_SERVER_REPO}" .; \
    \
    echo "=== [2/6] Original setup.py ==="; \
    cat setup.py; \
    \
    echo "=== [3/6] Patching setup.py to use find_packages() ==="; \
    sed -i \
        -e 's/^from setuptools import setup$/from setuptools import setup, find_packages/' \
        -e "s/packages=\['tails_server'\]/packages=find_packages()/" \
        -e 's/packages=\["tails_server"\]/packages=find_packages()/' \
        setup.py; \
    \
    echo "=== [4/6] Patched setup.py ==="; \
    cat setup.py; \
    \
    echo "=== [5/6] Installing package and dependencies via pip ==="; \
    pip install --no-cache-dir .; \
    \
    echo "=== [6/6] Verifying package imports and CLI entry point ==="; \
    python -c "from tails_server.config.defaults import DEFAULT_WEB_HOST, DEFAULT_WEB_PORT, CHUNK_SIZE; print('tails_server.config OK')"; \
    python -c "from tails_server import start; print('tails_server.start OK')"; \
    ls -la "${VIRTUAL_ENV}/bin/" | grep -i tail; \
    tails-server --help > /dev/null && echo 'tails-server CLI OK'


###############################################################################
# Stage 2 — Runtime
###############################################################################
FROM python:3.10-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

# Bring in the self-contained virtualenv (deps, package and console
# entry point). Nothing else from the builder stage leaks in.
COPY --from=builder /opt/venv /opt/venv

# Unprivileged user for the runtime process. The storage directory is
# owned by this user so the container can write tails files to the
# mounted volume without needing root.
RUN groupadd --system --gid 1001 tails \
    && useradd --system --uid 1001 --gid 1001 --shell /sbin/nologin tails \
    && mkdir -p /tails-files \
    && chown -R tails:tails /tails-files

USER tails
WORKDIR /tails-files

VOLUME ["/tails-files"]
EXPOSE 6543

# Health check: the tails server answers with a body on GET / when
# healthy. We treat any response with status < 500 as service-up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request, sys; \
        r = urllib.request.urlopen('http://127.0.0.1:6543/', timeout=3); \
        sys.exit(0 if r.status < 500 else 1)" || exit 1

# ``tails-server`` is the console script registered by upstream's
# ``entry_points``. Invoking it directly (instead of ``python -m ...``)
# avoids the missing ``__main__.py`` in the v1.1.0 package layout.
ENTRYPOINT ["tails-server"]
CMD ["--host", "0.0.0.0", \
     "--port", "6543", \
     "--log-level", "INFO", \
     "--storage-path", "/tails-files"]
