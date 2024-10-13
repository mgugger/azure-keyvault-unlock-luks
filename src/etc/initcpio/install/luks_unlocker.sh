#!/bin/bash

build() {
    add_binary /usr/local/bin/luks_unlocker /usr/local/bin/luks_unlocker
    add_systemd_unit luks_unlocker.service
    add_systemd_unit network-online.target
    add_systemd_unit cryptsetup-pre.target
    add_systemd_unit systemd-networkd-wait-online.service
    cd "$BUILDROOT/usr/lib/systemd/system/sysinit.target.wants"
        ln -sf ../cryptsetup-pre.target cryptsetup-pre.target
        ln -sf ../luks_unlocker.service luks_unlocker.service
        ln -sf ../network-online.target network-online.target
        ln -sf ../systemd-networkd-wait-online.service systemd-networkd-wait-online.service
}

help() {
    cat <<HELPEOF
This hook will attempt to decrypt the luks encryption.
HELPEOF
}