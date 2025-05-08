use anyhow::{Result, anyhow};
use ed25519_dalek::Keypair;
use rand_core::OsRng;
use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;

/// Manages SSH key generation and storage
pub struct KeyManager {
    key_path: PathBuf,
}

impl KeyManager {
    /// Create a new KeyManager with a path to store the generated key
    pub fn new(key_path: &Path) -> Result<Self> {
        Ok(Self {
            key_path: key_path.to_path_buf(),
        })
    }

    /// Generate a new Ed25519 keypair and save it to the specified path
    pub fn generate_keypair(&self) -> Result<Keypair> {
        // Generate keypair
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);

        // Save private key in PEM format
        let private_key_path = &self.key_path;
        let mut private_key_file = fs::File::create(private_key_path)?;
        
        // Write private key in PEM format
        let sec_bytes = keypair.secret.as_bytes();
        let pem_data = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            base64::encode(&sec_bytes)
        );
        private_key_file.write_all(pem_data.as_bytes())?;
        
        // Save public key
        let public_key_path = self.key_path.with_extension("pub");
        let mut public_key_file = fs::File::create(public_key_path)?;
        
        // Format public key in OpenSSH format
        let pub_bytes = keypair.public.as_bytes();
        let openssh_pubkey = format!(
            "ssh-ed25519 {} ssh-proxy-key",
            base64::encode(&pub_bytes)
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
        
        Ok(keypair)
    }
    
    /// Get the public key as a string (for display/configuration)
    pub fn get_public_key_string(&self) -> Result<String> {
        let public_key_path = self.key_path.with_extension("pub");
        if !public_key_path.exists() {
            return Err(anyhow!("Public key file not found"));
        }
        
        let public_key_string = fs::read_to_string(public_key_path)?;
        Ok(public_key_string)
    }
} 