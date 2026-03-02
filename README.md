# Azure LUKS Unlocker with IMDS and Key Vault
This project is a Rust-based application designed to unlock a LUKS-encrypted partition during the initramfs stage of boot. It retrieves the decryption password from Azure Key Vault using an Azure Managed Identity and the Instance Metadata Service (IMDS).

## Features
Managed Identity Authentication: Uses the VM's managed identity to authenticate with Azure services.
Azure Key Vault Integration: Retrieves the LUKS decryption secret from Azure Key Vault.
Minimal Dependencies: Uses Rust’s standard library to reduce external dependencies, making it suitable for use in constrained environments like initramfs.
Dynamic Configuration: Retrieves the Key Vault URL and secret name from the VM's tags using IMDS, eliminating the need for hardcoded configuration.

## Prerequisites
Before deploying and running this project, ensure the following:
* Requires [https://github.com/random-archer/mkinitcpio-systemd-tool](https://github.com/random-archer/mkinitcpio-systemd-tool) hook **systemd-tool** (provides the initrd `systemd-networkd`/`systemd-resolved` tooling)
* Azure VM with Managed Identity: The VM must have a system-assigned or user-assigned managed identity with access to the AKV secret.
* Azure Key Vault: The Key Vault should contain the LUKS decryption password as a secret.
* VM Tags: The VM must have the following tags:
    * LUKS-UNLOCK-KEY-VAULT-URL: The URL of the Azure Key Vault (e.g., https://myvault.vault.azure.net).
    * LUKS-UNLOCK-SECRET-NAME: The name of the secret that holds the LUKS decryption password.
    * Optional Tags:
      * LUKS-UNLOCK-NAME: the luks device name, defaults to "arch-root"
      * LUKS-UNLOCK-DEVICE: explicit LUKS block device path override (for example /dev/sda2)

    If `LUKS-UNLOCK-DEVICE` is not set, the binary auto-detects the LUKS device in initramfs without `waagent` by:
    * scanning `/sys/block/sd*` disks for partition `2`,
    * checking each `/dev/<disk>2` candidate for a LUKS header signature,
    * selecting the candidate only when exactly one match exists.

    If multiple matching LUKS candidates are found, auto-detection is considered ambiguous and no device is selected automatically; set `LUKS-UNLOCK-DEVICE` explicitly in that case.

    If detection cannot determine a device, it falls back to `/dev/sda2`.

## Installation
* The binary must be located in "/usr/local/bin/luks_unlocker"
* The hooks must be in /etc/initcpio/*
  
See src/etc/initcpio/install, src/etc/mkinitcpio-systemd-tool and /usr/lib/systemd/system for the required system services, configurations and hooks.

/etc/mkinitcpio.conf should use systemd and add the **systemd-tool** and **luks_unlocker** hooks together with the required Hyper-V modules:
```
MODULES=(hv_storvsc hv_vmbus hv_netvsc hv_utils keyboard zram btrfs)
BINARIES=()
FILES=()
FIRMWARE=()
HOOKS=(systemd systemd-tool autodetect modconf kms sd-vconsole block initrd_zram luks_unlocker sd-encrypt btrfs filesystems)
COMPRESSION="zstd"
COMPRESSION_OPTIONS=(-9)
```

## Usage

```
luks_unlocker                              # Unlock LUKS partition using Azure Key Vault
luks_unlocker --enroll-tpm                 # Enroll TPM2 for the LUKS device
luks_unlocker --add-passphrase-slot <dev>  # Add Key Vault secret as a LUKS passphrase (unlocks via TPM2)
luks_unlocker --help                       # Show usage information
```