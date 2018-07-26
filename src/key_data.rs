use ed25519;
use base64;
use sha2;
use failure::Error;

use config::Config;

pub struct KeyData {
    keypair: ed25519::Keypair,
    timestamp: u64,
}

impl KeyData {
    pub fn create(keypair: ed25519::Keypair, timestamp: u64) -> KeyData {
        KeyData { keypair, timestamp }
    }

    pub fn load(config: &Config) -> Result<KeyData, Error> {
        let keypair = ed25519::Keypair {
            public: ed25519::PublicKey::from_bytes(&base64::decode(config.public())?)?,
            secret: ed25519::SecretKey::from_bytes(&base64::decode(config.secret())?)?,
        };
        Ok(KeyData::create(keypair, config.timestamp()))
    }

    pub fn sign(&self, data: &[u8]) -> String {
        let signature = self.keypair.sign::<sha2::Sha512>(data);
        base64::encode(&signature.to_bytes()[..])
    }

    pub fn keypair(&self) -> &ed25519::Keypair {
        &self.keypair
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn public(&self) -> String {
        base64::encode(self.keypair.public.as_bytes())
    }
}
