#!/usr/bin/env bash
# Run ON the Proxmox host (192.168.88.3). Creates the NFS storage (backed by
# TrueNAS) and a Debian 12 LXC whose rootfs lives on that NFS storage.
#
# Usage:
#   NFS_SERVER=192.168.88.2 NFS_EXPORT=/mnt/tank/nids ./proxmox-create-lxc.sh
#
# Override any of the env vars below as needed.
set -euo pipefail

# ---- tunables ----------------------------------------------------------
NFS_SERVER="${NFS_SERVER:-192.168.88.2}"
NFS_EXPORT="${NFS_EXPORT:?set NFS_EXPORT to the TrueNAS export path, e.g. /mnt/tank/nids}"
STORAGE_ID="${STORAGE_ID:-truenas-nids}"
CTID="${CTID:-108}"
HOSTNAME="${HOSTNAME:-nids}"
TEMPLATE="${TEMPLATE:-local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst}"
BRIDGE="${BRIDGE:-vmbr0}"
CORES="${CORES:-2}"
MEMORY="${MEMORY:-1024}"
DISK_GB="${DISK_GB:-8}"
# Static IP (recommended for a monitoring box) or "dhcp"
IPCONFIG="${IPCONFIG:-dhcp}"   # e.g. "192.168.88.40/24,gw=192.168.88.1"

# ---- 1. verify the NFS export is reachable -----------------------------
echo "[*] Checking NFS export ${NFS_SERVER}:${NFS_EXPORT}"
showmount -e "${NFS_SERVER}" | grep -q "${NFS_EXPORT}" \
  || { echo "!! Export not visible. Check TrueNAS share + Hosts=192.168.88.3"; exit 1; }

# ---- 2. add the NFS storage to Proxmox (idempotent) --------------------
if ! pvesm status | awk '{print $1}' | grep -qx "${STORAGE_ID}"; then
  echo "[*] Adding NFS storage '${STORAGE_ID}'"
  pvesm add nfs "${STORAGE_ID}" \
    --server "${NFS_SERVER}" --export "${NFS_EXPORT}" \
    --content rootdir,images,vztmpl,backup \
    --options vers=4
else
  echo "[*] Storage '${STORAGE_ID}' already exists"
fi

# ---- 3. create the container -------------------------------------------
echo "[*] Creating LXC ${CTID} (${HOSTNAME}) on ${STORAGE_ID}"
pct create "${CTID}" "${TEMPLATE}" \
  --hostname "${HOSTNAME}" \
  --cores "${CORES}" --memory "${MEMORY}" --swap 512 \
  --rootfs "${STORAGE_ID}:${DISK_GB}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=${IPCONFIG}" \
  --features nesting=1 \
  --unprivileged 1 \
  --onboot 1 \
  --description "Signature NIDS (rootfs on TrueNAS NFS ${NFS_SERVER}:${NFS_EXPORT})"

echo "[*] Starting container"
pct start "${CTID}"
sleep 5

echo
echo "[+] LXC ${CTID} is up. Next: push the app and run deploy/install.sh inside it."
echo "    Enter with:  pct enter ${CTID}"
