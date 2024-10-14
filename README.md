# Azure LUKS Unlocker with IMDS and Key Vault
This project is a Rust-based application designed to unlock a LUKS-encrypted partition during the initramfs stage of boot. It retrieves the decryption password from Azure Key Vault using an Azure Managed Identity and the Instance Metadata Service (IMDS).

## Features
Managed Identity Authentication: Uses the VM's managed identity to authenticate with Azure services.
Azure Key Vault Integration: Retrieves the LUKS decryption secret from Azure Key Vault.
Minimal Dependencies: Uses Rust’s standard library to reduce external dependencies, making it suitable for use in constrained environments like initramfs.
Dynamic Configuration: Retrieves the Key Vault URL and secret name from the VM's tags using IMDS, eliminating the need for hardcoded configuration.
Prerequisites
Before deploying and running this project, ensure the following:
* Requires [https://github.com/wolegis/mkinitcpio-systemd-extras](https://github.com/wolegis/mkinitcpio-systemd-extras) hook **sd-network**
* Azure VM with Managed Identity: The VM must have a system-assigned or user-assigned managed identity with access to the AKV secret.
* Azure Key Vault: The Key Vault should contain the LUKS decryption password as a secret.
* VM Tags: The VM must have the following tags:
    * LUKS-UNLOCK-KEY-VAULT-URL: The URL of the Azure Key Vault (e.g., https://myvault.vault.azure.net).
    * LUKS-UNLOCK-SECRET-NAME: The name of the secret that holds the LUKS decryption password.
    * Optional Tags:
      * LUKS-UNLOCK-NAME: the luks device name, defaults to "arch-root"
      * LUKS-UNLOCK-DEVICE: the disk, defaults to /dev/sda2

## Installation
* The binary must be located in "/usr/local/bin/luks_unlocker"
* The hooks must be in /etc/initcpio/*
  
See src/etc/initcpio/install and /usr/lib/systemd/system for the required system services and hooks.

/etc/mkinitcpio.conf should use systemd and add the **sd-network** and the **luks_unlocker** hooks and the required Hyper-V modules:
```
MODULES=(hv_storvsc hv_vmbus hv_netvsc)
BINARIES=()
FILES=()
HOOKS=(base systemd autodetect microcode modconf kms keyboard block sd-network luks_unlocker sd-encrypt filesystems)
COMPRESSION="zstd"
```
