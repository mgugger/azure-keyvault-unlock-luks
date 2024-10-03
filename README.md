# Azure LUKS Unlocker with IMDS and Key Vault
This project is a Rust-based application designed to securely unlock a LUKS-encrypted partition during the initramfs stage of boot. It retrieves the decryption password from Azure Key Vault using an Azure Managed Identity and the Instance Metadata Service (IMDS).

## Features
Managed Identity Authentication: Uses the VM's managed identity to authenticate with Azure services.
Azure Key Vault Integration: Retrieves the LUKS decryption secret from Azure Key Vault.
Minimal Dependencies: Uses Rust’s standard library to reduce external dependencies, making it suitable for use in constrained environments like initramfs.
Dynamic Configuration: Retrieves the Key Vault URL and secret name from the VM's tags using IMDS, eliminating the need for hardcoded configuration.
Prerequisites
Before deploying and running this project, ensure the following:

* Azure VM with Managed Identity: The VM must have a system-assigned or user-assigned managed identity.
* Azure Key Vault: The Key Vault should contain the LUKS decryption password as a secret.
* VM Tags: The VM must have the following tags:
    * KeyVaultURL: The URL of the Azure Key Vault (e.g., https://myvault.vault.azure.net).
    * SecretName: The name of the secret that holds the LUKS decryption password.
* LUKS-encrypted partition: Ensure you have a LUKS-encrypted partition that you want to unlock.