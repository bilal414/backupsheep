#!/usr/bin/env bash
set -euo pipefail

run_id="bs-remed-20260818-0d08dcf"
resource_id="1be82b17-1e9f-4af3-b1fe-d29ee8579574"
expected_serial="ord-1be82b171e9f4a"
expected_size="268435456000"
device="/dev/vdb"
partition="/dev/vdb1"
mountpoint="/mnt/bs-remed-scale-0d08dcf"

observed_serial="$(lsblk -dn -o SERIAL "${device}" | tr -d '[:space:]')"
observed_size="$(blockdev --getsize64 "${device}")"
[[ "${observed_serial}" == "${expected_serial}" ]]
[[ "${observed_size}" == "${expected_size}" ]]
[[ ! -e "${partition}" ]]
[[ -z "$(blkid -o value -s TYPE "${device}" 2>/dev/null || true)" ]]

parted -s "${device}" mklabel gpt
parted -s "${device}" unit MiB mkpart primary 1 100%
udevadm settle
[[ -b "${partition}" ]]
mkfs.ext4 -q -m 0 -L bs_remed_scale_0d08dcf "${partition}"
install -d -m 0700 "${mountpoint}"
mount -o defaults,noatime "${partition}" "${mountpoint}"

filesystem_uuid="$(blkid -s UUID -o value "${partition}")"
[[ -n "${filesystem_uuid}" ]]
if ! grep -Fq " ${mountpoint} " /etc/fstab; then
    printf 'UUID=%s %s ext4 defaults,noatime,nofail 0 2\n' \
        "${filesystem_uuid}" "${mountpoint}" >> /etc/fstab
fi

ownership_dir="${mountpoint}/${run_id}"
install -d -m 0700 "${ownership_dir}"
printf 'run_id=%s\nresource_id=%s\nserial=%s\npurpose=%s\n' \
    "${run_id}" "${resource_id}" "${expected_serial}" \
    "website-and-database-scale-acceptance" > "${ownership_dir}/OWNERSHIP"
chmod 0600 "${ownership_dir}/OWNERSHIP"

findmnt -rn -S "${partition}" -o SOURCE,TARGET,FSTYPE,OPTIONS
lsblk -b -o NAME,PATH,SIZE,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINTS,SERIAL "${device}"
df -h "${mountpoint}"
df -i "${mountpoint}"
grep -F " ${mountpoint} " /etc/fstab
