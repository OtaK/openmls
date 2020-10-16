//! This config contains all structs, enums and functions to configure MLS.
//!

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{env, fs::File, io::BufReader};

use crate::ciphersuite::CiphersuiteName;
use crate::codec::{Codec, CodecError};
use crate::errors::ConfigError;
use crate::extensions::ExtensionType;

lazy_static! {
    static ref CONFIG: Config = {
        if let Ok(path) = env::var("OPENMLS_CONFIG") {
            let file = match File::open(path) {
                Ok(f) => f,
                Err(e) => panic!("Couldn't open file {}.\nPlease set \
                                  OPENMLS_CONFIG to a valid path or unset it to \
                                  use the default configuration.", e),
            };
            let reader = BufReader::new(file);
            let config: Config = match serde_json::from_reader(reader) {
                Ok(r) => r,
                Err(e) => panic!("Error reading configuration file.\n{:?}", e),
            };
            config
        } else {
            // Without a config file everything is enabled.
            Config {
                protocol_versions: vec![ProtocolVersion::Mls10],
                ciphersuites: vec![
                    CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                    CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256],
                    extensions: vec![ExtensionType::Lifetime, ExtensionType::Capabilities, ExtensionType::KeyID],
            }

        }
    };
}

/// # MLS Configuration
///
/// This is the global configuration for MLS.
///
/// TODO: #85 This doesn't do much yet.
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    protocol_versions: Vec<ProtocolVersion>,
    ciphersuites: Vec<CiphersuiteName>,
    extensions: Vec<ExtensionType>,
}

/// # Protocol Version
///
/// 7. Key Packages
///
/// ```text
/// enum {
///     reserved(0),
///     mls10(1),
///     (255)
/// } ProtocolVersion;
/// ```
///
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProtocolVersion {
    Reserved = 0,
    Mls10 = 1,
}

/// There's only one version right now, which is the default.
impl Default for ProtocolVersion {
    fn default() -> Self {
        ProtocolVersion::Mls10
    }
}

impl Codec for ProtocolVersion {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
}

impl ProtocolVersion {
    /// Convert an integer to the corresponding protocol version.
    ///
    /// Returns an error if the protocol version is not supported.
    pub fn from(v: u8) -> Result<ProtocolVersion, ConfigError> {
        match v {
            1 => Ok(ProtocolVersion::Mls10),
            _ => Err(ConfigError::UnsupportedMlsVersion),
        }
    }
}

impl CiphersuiteName {
    pub(crate) fn is_supported(&self) -> bool {
        matches!(
            self,
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                | CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        )
    }
}

impl Config {
    /// Get a list of the supported extension types.
    pub fn supported_extensions() -> Vec<ExtensionType> {
        vec![ExtensionType::Lifetime]
    }

    /// Get a list of the supported cipher suite names.
    pub fn supported_ciphersuites() -> Vec<CiphersuiteName> {
        vec![
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
        ]
    }

    /// Get a list of the supported protocol versions.
    pub fn supported_versions() -> Vec<ProtocolVersion> {
        vec![ProtocolVersion::Mls10]
    }
}
