#!/usr/bin/env bash
#
# ci-zfs-setup.sh — build a file-backed ZFS fixture that mimics the QuTS hero
# volume layout, so that the hero-specific half of internal/platform and
# internal/fsops can be tested without a NAS (PLAN.md decision 14, identity
# plan §6 "CI ZFS job").
#
# What it builds:
#
#   /share                      tmpfs          (QTS keeps /share on a RAM disk)
#   /share/ZFS1_DATA            zfs qfmpool    volume root
#   /share/ZFS1_DATA/Public     zfs qfmpool/Public    aclmode=discard
#   /share/ZFS1_DATA/Media      zfs qfmpool/Media     aclmode=passthrough
#   /share/ZFS2_DATA            zfs qfmpool2   second volume root, second domain
#   /share/ZFS2_DATA/Backup     zfs qfmpool2/Backup
#   /share/Public -> ZFS1_DATA/Public          the symlinks QTS registers
#   /share/Media  -> ZFS1_DATA/Media
#
# That is enough to exercise: per-dataset st_dev, MayCross inside one pool and
# across two, the tmpfs refusal, EXDEV between datasets, VolumeRoots, the
# ShareLink/VolumeRoot classification at /share and `zfs get aclmode`.
#
# Run as root on an Ubuntu runner (or any Ubuntu VM you are willing to give a
# ZFS pool):  sudo bash scripts/ci-zfs-setup.sh
#
# It is idempotent: running it twice leaves the same fixture and re-asserts
# every property. It fails loudly — any unexpected error aborts the script.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

IMG_DIR=${QFM_ZFS_IMG_DIR:-/tmp/qfm-zfs}
POOL1=qfmpool
POOL2=qfmpool2
VOL1=/share/ZFS1_DATA
VOL2=/share/ZFS2_DATA
# 512 MiB each: comfortably above OpenZFS's 64 MiB minimum vdev, small enough
# that the runner's /tmp does not care.
IMG_SIZE=512M

log() { printf '==> %s\n' "$*"; }
die() { printf 'ci-zfs-setup: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (try: sudo bash $0)"

# is_mounted <path> — reads the same table internal/platform parses, so the
# script never disagrees with the code under test about what a mount is.
is_mounted() {
	awk -v want="$1" '$5 == want { found = 1 } END { exit !found }' /proc/self/mountinfo
}

# ---------------------------------------------------------------------------
# 1. Userland and kernel module
# ---------------------------------------------------------------------------

install_zfs() {
	if command -v zfs >/dev/null 2>&1 && command -v zpool >/dev/null 2>&1; then
		log "zfsutils-linux is already installed ($(zfs version 2>/dev/null | head -n1))"
		return
	fi
	log "installing zfsutils-linux"
	apt-get update -qq
	apt-get install -y -qq zfsutils-linux
}

# ubuntu-latest ships the ZFS module in linux-modules-extra for the running
# kernel, so `modprobe zfs` normally succeeds the moment zfsutils-linux is in.
# On an image whose kernel package is trimmed it is missing, and the extras
# package (not DKMS, which takes minutes to build) is the cheap fix. DKMS is
# the last resort.
load_module() {
	if [ -d /sys/module/zfs ]; then
		log "the zfs module is already loaded"
		return
	fi
	if modprobe zfs 2>/dev/null; then
		log "modprobe zfs succeeded"
		return
	fi
	log "no zfs module for kernel $(uname -r); installing linux-modules-extra"
	apt-get update -qq
	if apt-get install -y -qq "linux-modules-extra-$(uname -r)"; then
		if modprobe zfs 2>/dev/null; then
			log "modprobe zfs succeeded after linux-modules-extra"
			return
		fi
	fi
	log "falling back to zfs-dkms (this builds the module and is slow)"
	apt-get install -y -qq zfs-dkms
	modprobe zfs || die "the zfs kernel module could not be loaded"
	log "modprobe zfs succeeded after zfs-dkms"
}

# ---------------------------------------------------------------------------
# 2. /share as a tmpfs, the way QTS has it
# ---------------------------------------------------------------------------

ensure_share() {
	mkdir -p /share
	if is_mounted /share; then
		log "/share is already a mount point"
		return
	fi
	log "mounting a tmpfs on /share"
	mount -t tmpfs -o size=64m,mode=0755 tmpfs /share
}

# ---------------------------------------------------------------------------
# 3. The pools
# ---------------------------------------------------------------------------

# FIXTURE_PROP is stamped on the root dataset at creation time and is the only
# thing that makes a pool this script's to modify. A pool that happens to be
# called qfmpool on somebody's machine is not this fixture, and a script running
# as root must not decide otherwise from a name.
FIXTURE_PROP=qfm:fixture

# pool_vdevs <pool> — the full paths of a pool's leaf vdevs, one per line.
# -P asks for whole paths; the pool's own summary line is the first one and is
# dropped, and anything that is not a path (a "mirror-0" row) with it.
pool_vdevs() {
	zpool list -vHP "$1" 2>/dev/null | awk 'NR > 1 && $1 ~ /^\// { print $1 }'
}

# assert_ours <pool> <image> — abort unless the imported pool is the fixture
# this script built: marked with FIXTURE_PROP and backed only by image files in
# IMG_DIR. Everything that follows (mountpoint changes, dataset creation, file
# writes) modifies the pool, so nothing may run before this says yes.
assert_ours() {
	local pool=$1 img=$2 marker vdevs vd want found=0
	marker=$(zfs get -H -o value "$FIXTURE_PROP" "$pool" 2>/dev/null || true)
	[ "$marker" = "1" ] || die "pool $pool exists but is not a fixture built by this script ($FIXTURE_PROP=${marker:-unset}). Refusing to modify it; destroy it by hand (zpool destroy $pool) if it really is disposable."
	vdevs=$(pool_vdevs "$pool")
	[ -n "$vdevs" ] || die "pool $pool exists but its vdevs could not be read. Refusing to modify it."
	want=$(readlink -f "$img" 2>/dev/null || printf '%s' "$img")
	while IFS= read -r vd; do
		[ -n "$vd" ] || continue
		case "$vd" in
		"$IMG_DIR"/*) ;;
		*) die "pool $pool is backed by $vd, which is outside $IMG_DIR. Refusing to modify it." ;;
		esac
		[ "$vd" = "$want" ] && found=1
	done <<-EOF
		$vdevs
	EOF
	[ "$found" = 1 ] || die "pool $pool is not backed by $img (vdevs: $(printf '%s' "$vdevs" | tr '\n' ' ')). Refusing to modify it."
}

# ensure_pool <pool> <image> <mountpoint>
#
# A pool is created only when its image file is absent. If the image is there,
# it is the previous run's fixture and the only correct move is to import it: an
# import that fails is a fault to report, never permission to delete the image
# and truncate a replacement over whatever it held.
ensure_pool() {
	local pool=$1 img=$2 mp=$3
	if zpool list -H -o name "$pool" >/dev/null 2>&1; then
		log "pool $pool is already imported"
		assert_ours "$pool" "$img"
	elif [ -e "$img" ]; then
		log "importing the existing pool $pool from $img"
		zpool import -d "$IMG_DIR" -N -f "$pool" >/dev/null 2>&1 ||
			die "$img exists but pool $pool could not be imported from it. Refusing to destroy it and start over: inspect it (zpool import -d $IMG_DIR) and remove $img by hand if it really is disposable."
		assert_ours "$pool" "$img"
	else
		log "creating pool $pool on $img ($IMG_SIZE)"
		truncate -s "$IMG_SIZE" "$img"
		# -f: the image is a plain file, which zpool otherwise questions.
		# ashift=12 keeps it quiet about sector sizes on a loop-less vdev.
		# The marker is set here and nowhere else, so only a pool this script
		# created can ever pass assert_ours.
		zpool create -f -o ashift=12 -O compression=off -O "$FIXTURE_PROP=1" -m "$mp" "$pool" "$img"
	fi
	# Re-assert the mountpoint on every run: a re-imported pool remembers the
	# property, but a fresh tmpfs on /share means the directory is gone.
	zfs set mountpoint="$mp" "$pool"
}

# ensure_dataset <dataset> [property=value ...]
ensure_dataset() {
	local ds=$1
	shift
	if ! zfs list -H -o name "$ds" >/dev/null 2>&1; then
		log "creating dataset $ds"
		zfs create "$ds"
	fi
	local prop
	for prop in "$@"; do
		zfs set "$prop" "$ds"
	done
}

# ---------------------------------------------------------------------------
# 4. Build it
# ---------------------------------------------------------------------------

install_zfs
load_module
ensure_share
mkdir -p "$IMG_DIR"

ensure_pool "$POOL1" "$IMG_DIR/$POOL1.img" "$VOL1"
ensure_pool "$POOL2" "$IMG_DIR/$POOL2.img" "$VOL2"

# One dataset per shared folder, which is what makes hero different from QTS:
# every share has its own st_dev, so a move between two shares is EXDEV.
# aclmode is set to two different values so the ZFSAclmode probe is tested
# against a property it could not have guessed.
ensure_dataset "$POOL1/Public" aclmode=discard
ensure_dataset "$POOL1/Media" aclmode=passthrough
ensure_dataset "$POOL2/Backup" aclmode=discard

# A re-run over a fresh tmpfs leaves the datasets unmounted; this puts them
# back without disturbing the ones that are already up.
zfs mount -a || true

for mp in "$VOL1" "$VOL1/Public" "$VOL1/Media" "$VOL2" "$VOL2/Backup"; do
	is_mounted "$mp" || die "$mp is not mounted after setup"
done

# ---------------------------------------------------------------------------
# 5. The /share symlinks QTS registers for each shared folder
# ---------------------------------------------------------------------------

ln -sfn ZFS1_DATA/Public /share/Public
ln -sfn ZFS1_DATA/Media /share/Media
ln -sfn ZFS2_DATA/Backup /share/Backup

# ---------------------------------------------------------------------------
# 6. A little content
# ---------------------------------------------------------------------------

mkdir -p "$VOL1/Public/sub" "$VOL1/Media" "$VOL2/Backup"
printf 'hello from Public\n' > "$VOL1/Public/hello.txt"
printf 'nested\n' > "$VOL1/Public/sub/nested.txt"
printf 'clip\n' > "$VOL1/Media/clip.txt"
printf 'backup\n' > "$VOL2/Backup/backup.txt"
chmod 0755 "$VOL1/Public" "$VOL1/Public/sub" "$VOL1/Media" "$VOL2/Backup"
chmod 0644 "$VOL1/Public/hello.txt" "$VOL1/Public/sub/nested.txt" \
	"$VOL1/Media/clip.txt" "$VOL2/Backup/backup.txt"

# ---------------------------------------------------------------------------
# 7. Show what was built — this output is the first thing to read when the
#    integration tests fail in CI.
# ---------------------------------------------------------------------------

log "zfs list"
zfs list -o name,used,avail,mountpoint,aclmode

log "aclmode per dataset"
zfs get -H -o name,value aclmode "$POOL1/Public" "$POOL1/Media" "$POOL2/Backup"

log "mountinfo"
cat /proc/self/mountinfo | grep -E 'zfs|share' || true

log "ls /share"
ls -la /share

log "fixture ready: QFM_ZFS_TEST=1 go test -run ZFS ./internal/platform/... ./internal/fsops/..."
