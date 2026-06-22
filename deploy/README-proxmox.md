# Deploying on Proxmox with TrueNAS-backed storage

This runs the NIDS as a **Debian 12 LXC** on Proxmox (`192.168.88.3`) whose
**root filesystem lives on TrueNAS** (`192.168.88.2`) via NFS.

```
 TrueNAS (192.168.88.2)            Proxmox (192.168.88.3)
 ┌───────────────────┐  NFS v4   ┌────────────────────────┐
 │ /mnt/<pool>/nids  │◀─────────▶│ storage: truenas-nids  │
 │  (dataset+share)  │           │   └─ LXC 108 rootfs    │──▶ dashboard :8080
 └───────────────────┘           └────────────────────────┘
```

## 1. TrueNAS — create the NFS share (web UI, one time)

1. **Datasets** → pick pool → **Add Dataset** → name `nids`.
2. **Shares → Unix (NFS) Shares → Add**
   - Path: `/mnt/<pool>/nids`
   - Advanced: **Hosts** = `192.168.88.3`; **Maproot User/Group** = `root`.
   - Save → **Enable Service**.

`Maproot = root` is required so Proxmox can write the container rootfs (NFS
root-squashes by default).

## 2. Proxmox — storage + container (automated)

From this repo (the deploy scripts are copied to the Proxmox host):

```bash
NFS_SERVER=192.168.88.2 NFS_EXPORT=/mnt/<pool>/nids \
  bash deploy/proxmox-create-lxc.sh
```

This verifies the export, registers it as Proxmox storage `truenas-nids`
(`content rootdir,images,...`), and creates + starts **LXC 108** with its rootfs
on that NFS storage. Tunables (CTID, RAM, static IP, etc.) are env vars at the
top of the script.

## 3. Install the app inside the container

```bash
# push the repo into the container, then:
pct exec 108 -- bash /root/nids-src/deploy/install.sh
```

Dashboard: `http://<container-ip>:8080`.

## 4. Seeing more than the container's own traffic

The LXC's `eth0` only receives its own + broadcast traffic. To inspect other
hosts, mirror traffic into the container. On Proxmox you can mirror a guest's
or the bridge's traffic with `tc`:

```bash
# Example: mirror everything on vmbr0 to the NIDS container's veth (vethNIDS).
# Identify the veth:  pct config 108 | grep net   /  ip link | grep veth
tc qdisc add dev vmbr0 ingress
tc filter add dev vmbr0 parent ffff: matchall action mirred egress mirror dev <vethNIDS>
```

For physical-network visibility, configure a **SPAN/mirror port** on your switch
and pass that NIC to Proxmox / the container. See the main README.

## Relocating an existing container's storage to TrueNAS

If the LXC was first created on local storage (e.g. `local-lvm`) you don't need
to rebuild it — move the rootfs to the NFS storage live:

```bash
# 1. add the TrueNAS NFS storage (once the share exists)
pvesm add nfs truenas-nids --server 192.168.88.2 --export /mnt/<pool>/nids \
  --content rootdir,images --options vers=4

# 2. stop, move the rootfs volume to NFS, restart
pct shutdown 108
pct move-volume 108 rootfs truenas-nids --delete
pct start 108
```

After the move, `pct config 108 | grep rootfs` shows the disk on
`truenas-nids:...`, i.e. the container's storage now lives on TrueNAS.

## Notes

- The container is **unprivileged** with `nesting=1`. Raw-socket capture works
  on its own interfaces via `CAP_NET_RAW` (granted by the systemd unit).
- Alerts DB and rules live under `/opt/nids/` — i.e. on the TrueNAS-backed
  rootfs — so they persist on the NAS and are covered by your TrueNAS snapshots.
