use std::mem;
use std::io::prelude::*;
use std::io::Cursor;

use errors::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use sha2::Sha512;
use ed25519_dalek;

pub const KEYNUMLEN : usize = 8;
pub const PUBLICBYTES : usize = 32;
pub const SECRETBYTES : usize = 64;
pub const SIGBYTES : usize = 64;

pub const PKGALG : &[u8; 2] = b"Ed";
pub const KDFALG : &[u8; 2] = b"BK";

pub const COMMENTHDR : &'static str = "untrusted comment: ";
pub const COMMENTHDRLEN : usize = 19;
pub const COMMENTMAXLEN : usize = 1024;

pub struct PublicKey {
    pub keynum: [u8; KEYNUMLEN],
    public: ed25519_dalek::PublicKey,
}

pub struct PrivateKey {
   pub kdfrounds: u32,
   pub salt: [u8; 16],
   pub checksum: [u8; 8],
   pub keynum: [u8; KEYNUMLEN],
   pub keypair: ed25519_dalek::Keypair,
}

pub struct Signature {
    pub keynum: [u8; KEYNUMLEN],
    sig: ed25519_dalek::Signature,
}

impl PublicKey {
    pub fn with_key_and_keynum(key: [u8; PUBLICBYTES], keynum: [u8; KEYNUMLEN]) -> PublicKey {
        PublicKey {
            keynum: keynum,
            public: ed25519_dalek::PublicKey::from_bytes(&key).unwrap(),
        }
    }

    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write(PKGALG)?;
        w.write(&self.keynum)?;
        w.write(self.public.as_bytes())?;

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<PublicKey> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut scratch = [0; 2];
        let mut keynum = [0; KEYNUMLEN];
        let mut public = [0; PUBLICBYTES];

        buf.read(&mut scratch)?;
        ensure!(&scratch == PKGALG, "Invalid Pkg algorithm");

        buf.read(&mut keynum)?;
        buf.read(&mut public)?;

        let public = ed25519_dalek::PublicKey::from_bytes(&public)?;

        Ok(PublicKey {
            keynum: keynum,
            public: public,
        })
    }
}

impl PrivateKey {
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write(PKGALG)?;
        w.write(KDFALG)?;
        w.write_u32::<BigEndian>(self.kdfrounds)?;
        w.write(&self.salt)?;
        w.write(&self.checksum)?;
        w.write(&self.keynum)?;
        w.write(&self.keypair.to_bytes())?;

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<PrivateKey> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut scratch = [0; 2];
        let kdfrounds;
        let mut salt = [0; 16];
        let mut checksum = [0; 8];
        let mut keynum = [0; KEYNUMLEN];
        let mut keypair = [0; SECRETBYTES];

        buf.read(&mut scratch)?;
        ensure!(&scratch == PKGALG, "Invalid Pkg algorithm");
        buf.read(&mut scratch)?;
        ensure!(&scratch == KDFALG, "Invalid KDF algorithm");

        kdfrounds = buf.read_u32::<BigEndian>()?;
        buf.read(&mut salt)?;
        buf.read(&mut checksum)?;
        buf.read(&mut keynum)?;
        buf.read(&mut keypair)?;

        let keypair = ed25519_dalek::Keypair::from_bytes(&keypair)?;

        Ok(PrivateKey {
            kdfrounds: kdfrounds,
            salt: salt,
            checksum: checksum,
            keynum: keynum,
            keypair: keypair,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let signature = self.keypair.sign::<Sha512>(msg);
        Ok(Signature {
            keynum: self.keynum,
            sig: signature,
        })
    }
}

impl Signature {
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write(PKGALG)?;
        w.write(&self.keynum)?;
        w.write(&self.sig.to_bytes())?;

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<Signature> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut scratch = [0; 2];
        let mut keynum = [0; KEYNUMLEN];
        let mut sig = [0; SIGBYTES];

        buf.read(&mut scratch)?;
        ensure!(&scratch == PKGALG, "Invalid Pkg algorithm");

        buf.read(&mut keynum)?;
        buf.read(&mut sig)?;

        let sig = ed25519_dalek::Signature::from_bytes(&sig)?;

        Ok(Signature {
            keynum: keynum,
            sig: sig,
        })
    }

    pub fn verify(&self, msg: &[u8], pkey: &PublicKey) -> bool {
        pkey.public.verify::<Sha512>(msg, &self.sig)
    }
}
