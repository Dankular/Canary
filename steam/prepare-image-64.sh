#!/usr/bin/env bash
# prepare-image-64.sh — Build a minimal x86-64 Debian rootfs as an ext2 image.
#
# Prerequisites (in WSL/Linux with root):
#   apt-get install -y docker.io e2fsprogs
#   (Or run inside a Docker container with --privileged)
#
# Usage (from WSL root):
#   bash /mnt/d/Dev\ Proj/Canary/steam/prepare-image-64.sh
#
# Output:
#   /mnt/d/Dev Proj/Canary/steam/rootfs-x64.ext2   (~512 MiB, ext2)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR"
IMAGE="$OUT_DIR/rootfs-x64.ext2"
ROOTFS="$OUT_DIR/rootfs-x64"
IMAGE_MB=768   # size of the ext2 image in MiB

echo "=== Canary x86-64 rootfs builder ==="
echo "Output: $IMAGE"
echo ""

# ── 1. Build rootfs directory via Docker ──────────────────────────────────────
echo "[1/5] Building rootfs via Docker..."

cat > /tmp/Dockerfile.canary-x64 << 'DOCKERFILE'
FROM amd64/debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Essential runtime libraries that ld-linux needs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 \
    libgcc-s1 \
    libstdc++6 \
    libm6 \
    libdl-dev \
    libpthread-stubs0-dev \
    zlib1g \
    libz3-4 \
    coreutils \
    bash \
    busybox \
    file \
    strace \
    && rm -rf /var/lib/apt/lists/*

# Create standard directories.
RUN mkdir -p /tmp /proc /sys /dev /run /var/run /home/user /root

# Minimal /etc/ld.so.conf.
RUN echo '/lib/x86_64-linux-gnu' > /etc/ld.so.conf \
    && echo '/usr/lib/x86_64-linux-gnu' >> /etc/ld.so.conf \
    && ldconfig

# Minimal /etc/passwd and /etc/group.
RUN echo 'root:x:0:0:root:/root:/bin/bash' > /etc/passwd \
    && echo 'user:x:1000:1000:user:/home/user:/bin/bash' >> /etc/passwd \
    && echo 'root:x:0:' > /etc/group \
    && echo 'user:x:1000:' >> /etc/group

# Quick sanity check.
RUN /bin/bash -c 'echo "rootfs build OK"'
DOCKERFILE

docker build --platform linux/amd64 \
    -t canary-rootfs-x64:latest \
    -f /tmp/Dockerfile.canary-x64 \
    /tmp

echo "[1/5] Docker build done."

# ── 2. Export the rootfs ──────────────────────────────────────────────────────
echo "[2/5] Exporting rootfs from container..."

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"

CID=$(docker create --platform linux/amd64 canary-rootfs-x64:latest /bin/true)
docker export "$CID" | tar -xf - -C "$ROOTFS" --exclude='./dev/*'
docker rm "$CID"

echo "[2/5] Rootfs exported to $ROOTFS"
du -sh "$ROOTFS"

# ── 3. Create dev nodes ────────────────────────────────────────────────────────
echo "[3/5] Creating device nodes..."

mkdir -p "$ROOTFS/dev"
mknod -m 666 "$ROOTFS/dev/null"    c 1 3  2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/zero"    c 1 5  2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/urandom" c 1 9  2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/random"  c 1 8  2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/tty"     c 5 0  2>/dev/null || true

echo "[3/5] Device nodes created."

# ── 4. Build the ext2 image ────────────────────────────────────────────────────
echo "[4/5] Building ext2 image (${IMAGE_MB} MiB)..."

# Create a sparse file.
dd if=/dev/zero bs=1M count=0 seek="$IMAGE_MB" of="$IMAGE" status=none

# Format as ext2 (no journal = ext2, not ext3/4).
mkfs.ext2 -F -L "canary-x64" -b 4096 -m 0 "$IMAGE"

# Mount and copy.
MNTDIR=$(mktemp -d)
mount -o loop "$IMAGE" "$MNTDIR"
cp -a "$ROOTFS/." "$MNTDIR/"
sync
umount "$MNTDIR"
rmdir "$MNTDIR"

echo "[4/5] ext2 image built: $(du -h "$IMAGE" | cut -f1)"

# ── 5. Verify ─────────────────────────────────────────────────────────────────
echo "[5/5] Verifying image..."

e2fsck -f -n "$IMAGE" || true
file "$IMAGE"

echo ""
echo "=== Done! ==="
echo "Image: $IMAGE"
echo ""
echo "To test with Canary:"
echo "  1. Build the WASM:  wasm-pack build crates/canary-wasm --target web --out-dir pkg"
echo "  2. Run the server:  node harness/server.mjs"
echo "  3. Open:            http://localhost:3000?image=/steam/rootfs-x64.ext2&bin=/bin/true"
