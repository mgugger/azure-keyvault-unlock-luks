use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

const IMDS_ENDPOINT: &str = "169.254.169.254:80";
const IMDS_IP: &str = "169.254.169.254";
const IMDS_PATH: &str = "/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://vault.azure.net";
const IMDS_TAGS_PATH: &str = "/metadata/instance?api-version=2021-02-01&format=json";
const VAULT_API_VERSION: &str = "7.2";

enum Action {
    Unlock,
    EnrollTpm,
    AddPassphrase { device: String },
}

#[derive(Debug)]
#[allow(dead_code)]
enum UnlockError {
    IoError(std::io::Error),
    ParseError(&'static str),
    MinreqError(minreq::Error),
}

impl From<std::io::Error> for UnlockError {
    fn from(err: std::io::Error) -> UnlockError {
        UnlockError::IoError(err)
    }
}

impl From<minreq::Error> for UnlockError {
    fn from(err: minreq::Error) -> UnlockError {
        UnlockError::MinreqError(err)
    }
}

fn get_managed_identity_token() -> Result<String, UnlockError> {
    let mut stream = TcpStream::connect(IMDS_ENDPOINT)?;
    
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nMetadata: true\r\nConnection: close\r\n\r\n",
        IMDS_PATH, IMDS_IP
    );
    stream.write_all(request.as_bytes())?;
    
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    
    let token_start = response.find("\"access_token\":\"").ok_or(UnlockError::ParseError("No access_token found"))? + 16;
    let token_end = response[token_start..].find("\"").ok_or(UnlockError::ParseError("Invalid token format"))? + token_start;
    let token = &response[token_start..token_end];

    Ok(token.to_string())
}

fn get_vm_tags() -> Result<HashMap<String, String>, UnlockError> {
    let mut stream = TcpStream::connect(IMDS_ENDPOINT)?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nMetadata: true\r\nConnection: close\r\n\r\n",
        IMDS_TAGS_PATH, IMDS_IP
    );
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    let tags_attr = "\"tags\":\"";
    let tags_start = response.find(tags_attr).ok_or(UnlockError::ParseError("No Tags found"))? + tags_attr.len();
    let tags_end = response[tags_start..].find("\"").ok_or(UnlockError::ParseError("Invalid Tags format"))? + tags_start;

    let tags: HashMap<String, String> = response[tags_start..tags_end]
        .split(';')
        .filter_map(|t| t.split_once(':').map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned())))
        .collect();

    Ok(tags)
}

fn get_key_vault_secret(token: &str, key_vault_url: &str, secret_name: &str) -> Result<String, UnlockError> {
    let secret_url = format!(
        "{}/secrets/{}?api-version={}",
        key_vault_url, secret_name, VAULT_API_VERSION
    );

    let response = minreq::get(&secret_url)
        .with_header("Authorization", &format!("Bearer {}", token))
        .send()
        .map_err(|e| UnlockError::from(e))?;

    if response.status_code != 200 {
        return Err(UnlockError::ParseError("Request failed (not 200)"));
    }

    let response = response.as_str().expect("No response from Key Vault");
    let value_attr = "\"value\":\"";
    let value_start = response.find(value_attr).ok_or(UnlockError::ParseError("No Secret value found"))? + value_attr.len();
    let value_end = response[value_start..].find("\"").ok_or(UnlockError::ParseError("Invalid Secret format"))? + value_start;

    Ok(response[value_start..value_end].to_owned())
}

fn create_secret_tempfile(secret: &str) -> Result<NamedTempFile, UnlockError> {
    let mut temp_file = NamedTempFile::new()?;
    let temp_file_path = temp_file.path().to_owned();
    let mut permissions = fs::metadata(&temp_file_path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&temp_file_path, permissions)?;
    write!(temp_file, "{}", secret)?;
    Ok(temp_file)
}


fn unlock_luks(luks_device: &str, luks_name: &str, password: &str) -> Result<(), UnlockError> {
    let temp_file = create_secret_tempfile(password)?;
    let temp_file_path = temp_file.path().to_owned();

    let process = Command::new("systemd-cryptsetup")
        .arg("attach")
        .arg(luks_name)      
        .arg(luks_device)     
        .arg(temp_file_path)
        .stdin(Stdio::null())
        .spawn()?;
    
    let output = process.wait_with_output()?;

    if output.status.success() {
        println!("Successfully unlocked LUKS partition.");
        Ok(())
    } else {
        eprintln!(
            "Failed to unlock LUKS partition: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Err(UnlockError::ParseError("LUKS unlocking failed."))
    }
}

fn enroll_tpm(luks_device: &str, password: &str) -> Result<(), UnlockError> {
    let temp_file = create_secret_tempfile(password)?;
    let temp_file_path = temp_file.path().to_owned();

    let output = Command::new("systemd-cryptenroll")
        .arg("--tpm2-device=auto")
        .arg(format!("--password-file={}", temp_file_path.display()))
        .arg(luks_device)
        .output()?;

    if output.status.success() {
        println!("Successfully enrolled TPM2 token for {}.", luks_device);
        Ok(())
    } else {
        eprintln!(
            "Failed to enroll TPM2 token: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Err(UnlockError::ParseError("TPM enrollment failed."))
    }
}

fn add_passphrase_slot(luks_device: &str, password: &str) -> Result<(), UnlockError> {
    let new_key_file = create_secret_tempfile(password)?;
    let new_key_path = new_key_file.path().to_owned();

    let output = Command::new("systemd-cryptenroll")
        .arg("--unlock-tpm2-device=auto")
        .arg(format!("--new-password-file={}", new_key_path.display()))
        .arg(luks_device)
        .stdin(Stdio::null())
        .output()?;

    if output.status.success() {
        println!("Added Key Vault passphrase to {} (unlocked via TPM2).", luks_device);
        Ok(())
    } else {
        eprintln!(
            "Failed to add passphrase slot: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Err(UnlockError::ParseError("Adding passphrase slot via TPM2 failed."))
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  luks_unlocker             # Unlock using Azure Key Vault");
    println!("  luks_unlocker --enroll-tpm # Enroll TPM2 for the LUKS device");
    println!("  luks_unlocker --add-passphrase-slot <device> # Add Key Vault secret as passphrase");
}

fn main() -> Result<(), UnlockError> {
    let mut args = env::args().skip(1);
    let action = match args.next().as_deref() {
        Some("--enroll-tpm") => Action::EnrollTpm,
        Some("--add-passphrase-slot") => {
            if let Some(device) = args.next() {
                Action::AddPassphrase { device }
            } else {
                eprintln!("Missing <device> argument for --add-passphrase-slot.");
                print_usage();
                return Err(UnlockError::ParseError("Missing device argument"));
            }
        }
        Some("-h") | Some("--help") => {
            print_usage();
            return Ok(());
        }
        Some(arg) => {
            eprintln!("Unknown argument: {}", arg);
            print_usage();
            return Err(UnlockError::ParseError("Invalid arguments"));
        }
        None => Action::Unlock,
    };

    let key_vault_url_tag = "LUKS-UNLOCK-KEY-VAULT-URL";
    let secret_name_tag = "LUKS-UNLOCK-SECRET-NAME";
    let luks_name_tag = "LUKS-UNLOCK-NAME";
    let luks_device_tag = "LUKS-UNLOCK-DEVICE";

    let tags = get_vm_tags()?;
    let luks_name = tags
        .get(luks_name_tag)
        .cloned()
        .unwrap_or_else(|| "arch-root".to_string());
    let luks_device = tags
        .get(luks_device_tag)
        .cloned()
        .unwrap_or_else(|| "/dev/sda2".to_string());
    let key_vault_url = tags
        .get(key_vault_url_tag)
        .cloned()
        .expect(&format!("Missing {}", key_vault_url_tag));
    let secret_name = tags
        .get(secret_name_tag)
        .cloned()
        .expect(&format!("Missing {}", secret_name_tag));

    let token = get_managed_identity_token()?;
    let secret = get_key_vault_secret(&token, &key_vault_url, &secret_name)?;

    match action {
        Action::Unlock => unlock_luks(&luks_device, &luks_name, &secret)?,
        Action::EnrollTpm => enroll_tpm(&luks_device, &secret)?,
        Action::AddPassphrase { device } => add_passphrase_slot(&device, &secret)?,
    }

    Ok(())
}