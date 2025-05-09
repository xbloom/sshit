use anyhow::{Result, anyhow};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;
use log::info;
use base64::{engine::general_purpose, Engine};

/// SSH key type enum
#[derive(Debug, Clone, Copy)]
pub enum SshKeyType {
    Ed25519,
    Rsa,
}

impl SshKeyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SshKeyType::Ed25519 => "ed25519",
            SshKeyType::Rsa => "rsa",
        }
    }
}

/// Manages SSH key generation and storage
pub struct KeyManager {
    key_path: PathBuf,
    key_type: SshKeyType,
    generate_new: bool, // Add flag to control whether to generate new keys
}

impl KeyManager {
    /// Create a new KeyManager with a path to store the generated key
    pub fn new(key_path: &Path, key_type: SshKeyType, generate_new: bool) -> Result<Self> {
        Ok(Self {
            key_path: key_path.to_path_buf(),
            key_type,
            generate_new,
        })
    }

    /// Generate a new keypair or verify existing one
    pub fn setup_keypair(&self) -> Result<()> {
        let private_key_exists = self.key_path.exists();
        let public_key_exists = self.key_path.with_extension("pub").exists();
        
        // If both keys exist and we're not generating new ones, just use the existing ones
        if private_key_exists && public_key_exists && !self.generate_new {
            info!("使用已存在的 {} 密钥对，路径：{:?}", self.key_type.as_str(), self.key_path);
            return Ok(());
        }
        
        // Otherwise generate new keys
        info!("正在生成新的 {} 密钥对，路径：{:?}", self.key_type.as_str(), self.key_path);
        
        match self.key_type {
            SshKeyType::Ed25519 => self.generate_ed25519_keypair()?,
            SshKeyType::Rsa => self.generate_rsa_keypair()?,
        };
        
        Ok(())
    }
    
    /// Generate an Ed25519 keypair
    fn generate_ed25519_keypair(&self) -> Result<()> {
        // Delete existing key files if they exist
        if self.key_path.exists() {
            fs::remove_file(&self.key_path)?;
        }
        
        let pub_path = self.key_path.with_extension("pub");
        if pub_path.exists() {
            fs::remove_file(&pub_path)?;
        }
        
        // Generate keypair
        let mut csprng = OsRng; // 新版 OsRng 不需要调用 new()
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);
        
        // Save private key in PEM format
        let private_key_path = &self.key_path;
        let mut private_key_file = fs::File::create(private_key_path)?;
        
        // Write private key in PEM format
        let sec_bytes = signing_key.to_bytes();
        let pem_data = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            general_purpose::STANDARD.encode(&sec_bytes)
        );
        private_key_file.write_all(pem_data.as_bytes())?;
        
        // Save public key
        let public_key_path = self.key_path.with_extension("pub");
        let mut public_key_file = fs::File::create(public_key_path)?;
        
        // Format public key in OpenSSH format
        let pub_bytes = verifying_key.to_bytes();
        let openssh_pubkey = format!(
            "ssh-ed25519 {} ssh-proxy-key",
            general_purpose::STANDARD.encode(&pub_bytes)
        );
        public_key_file.write_all(openssh_pubkey.as_bytes())?;
        public_key_file.write_all(b"\n")?;
        
        // Set permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&self.key_path, perms)?;
        }
        
        Ok(())
    }
    
    /// Generate an RSA keypair using external ssh-keygen tool
    fn generate_rsa_keypair(&self) -> Result<()> {
        use std::process::Command;
        
        // Delete existing key files if they exist
        if self.key_path.exists() {
            fs::remove_file(&self.key_path)?;
        }
        
        let pub_path = self.key_path.with_extension("pub");
        if pub_path.exists() {
            fs::remove_file(&pub_path)?;
        }
        
        // Use ssh-keygen to generate RSA key (better compatibility)
        let output = Command::new("ssh-keygen")
            .arg("-t").arg("rsa")
            .arg("-b").arg("4096")  // 4096 bit key for better security
            .arg("-f").arg(&self.key_path)
            .arg("-C").arg("ssh-proxy-key")
            .arg("-N").arg("") // Empty passphrase
            .output()?;
            
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to generate RSA key: {}", stderr));
        }
        
        Ok(())
    }
    
    /// Get the public key as a string (for display/configuration)
    pub fn get_public_key_string(&self) -> Result<String> {
        let public_key_path = self.key_path.with_extension("pub");
        if !public_key_path.exists() {
            return Err(anyhow!("Public key file not found at: {}. Make sure both the private key and public key files exist.", 
                public_key_path.display()));
        }
        
        let public_key_string = fs::read_to_string(&public_key_path)?;
        Ok(public_key_string.trim().to_string())
    }

    /// Check if key files exist
    pub fn key_files_exist(&self) -> bool {
        let private_key_exists = self.key_path.exists();
        let public_key_exists = self.key_path.with_extension("pub").exists();
        private_key_exists && public_key_exists
    }
} 