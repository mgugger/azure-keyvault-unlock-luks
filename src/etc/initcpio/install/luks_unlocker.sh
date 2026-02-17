#!/bin/bash

build() {
    add_binary /usr/local/bin/luks_unlocker /usr/local/bin/luks_unlocker
    add_binary /usr/lib/systemd/systemd-networkd-wait-online
    add_systemd_unit luks_unlocker.service
    add_systemd_unit systemd-networkd-wait-online.service
    add_systemd_unit systemd-resolved.service
    add_systemd_unit cryptsetup-pre.target

    # Ensure the unit is enabled for the initrd.
    add_symlink \
        "/usr/lib/systemd/system/initrd.target.wants/luks_unlocker.service" \
        "/usr/lib/systemd/system/luks_unlocker.service"

    # NSS lookups are required when systemd-networkd loads passwd/group data.
    local nss
    for nss in /usr/lib/libnss_files.so*; do
        [ -e "$nss" ] && add_binary "$nss"
    done

    # Copy the systemd-network and systemd-resolve accounts into the initramfs.
    local user
    for user in systemd-network systemd-resolve; do
        grep -q "^${user}:" "$BUILDROOT/etc/passwd" || \
            grep "^${user}:" /etc/passwd >> "$BUILDROOT/etc/passwd"
        grep -q "^${user}:" "$BUILDROOT/etc/group" || \
            grep "^${user}:" /etc/group >> "$BUILDROOT/etc/group"
        grep -q "^${user}:" "$BUILDROOT/etc/shadow" 2>/dev/null || \
            grep "^${user}:" /etc/shadow >> "$BUILDROOT/etc/shadow" 2>/dev/null
    done
}

help() {
    cat <<HELPEOF
This hook wires the luks unlocker binary into the initramfs together with the
systemd networking components it depends on.
HELPEOF
}