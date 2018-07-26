use std::io::{Read, Write};

use failure::Error;
use toml;
use base64;

use key_data::KeyData;

#[derive(Serialize, Deserialize)]
pub struct Config {
    public: PublicKey,
    secret: SecretKey,
}

impl Config {
    pub fn create(key_data: &KeyData) -> Result<Config, Error> {
        let keypair = key_data.keypair();
        let timestamp = key_data.timestamp();
        Ok(Config {
            public: PublicKey {
                key: base64::encode(keypair.public.as_bytes()),
                timestamp,
            },
            secret: SecretKey {
                key: base64::encode(keypair.secret.as_bytes()),
            },
        })
    }

    pub fn load(file: &mut impl Read) -> Result<Config, Error> {
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;
        Ok(toml::from_slice(&buf)?)
    }

    pub fn write(&self, file: &mut impl Write) -> Result<(), Error> {
        Ok(file.write_all(&toml::to_vec(self)?)?)
    }

    pub fn timestamp(&self) -> u64 {
        self.public.timestamp
    }

    pub fn public(&self) -> &str {
        &self.public.key
    }

    pub fn secret(&self) -> &str {
        &self.secret.key
    }
}

#[derive(Serialize, Deserialize)]
struct PublicKey {
    key: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize)]
struct SecretKey {
    key: String,
}
