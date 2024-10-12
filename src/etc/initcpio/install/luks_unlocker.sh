#!/bin/bash

build() {
    add_binary /usr/local/bin/luks_unlocker /usr/local/bin/luks_unlocker
    add_systemd_unit luks_unlocker.service
    add_systemd_unit cryptsetup-pre.target
    cd "$BUILDROOT/usr/lib/systemd/system/sysinit.target.wants"
        ln -sf ../cryptsetup-pre.target cryptsetup-pre.target
        ln -sf ../luks_unlocker.service           luks_unlocker.service
}

help() {
    cat <<HELPEOF
This hook will attempt to decrypt the luks volume using the key vault secret.
HELPEOF
}