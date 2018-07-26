extern crate base64;
extern crate failure;
extern crate toml;
extern crate sha2;
#[macro_use]
extern crate serde_derive;

extern crate rand;
extern crate ed25519_dalek as ed25519;
#[macro_use] extern crate structopt;

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use failure::Error;
use structopt::StructOpt;

mod key_data;
mod config;

use key_data::KeyData;
use config::Config;

#[derive(StructOpt, Debug)]
enum Opt {
    #[structopt(name = "init", about = "(Re)initialize signify, generate a new keypair.")]
    Init,

    #[structopt(name = "print", about = "Print the current public key")]
    Print,

    #[structopt(name = "sign", about = "Sign a message")]
    Sign {
        #[structopt(help = "Path to the message to sign")]
        path: Option<String>,
    },

    #[structopt(name = "verify", about = "Verify a message")]
    Verify {
        #[structopt(help = "Path to the message to verify")]
        path: Option<String>,
    },
}

fn main() -> Result<(), Error> {
    let matches = Opt::from_args();

    use Opt::*;
    match matches {
        Init => init(),
        _ => Ok(())
    }
}

fn init() -> Result<(), Error> {
    let keys_file = keys_file();
    if std::fs::metadata(&keys_file).is_ok() {
        eprintln!("A signify_keys.toml already exists. If you want to reinitialize your state\n\
                   delete the file at `{}` first", keys_file);
        return Ok(())
    }
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut rng = rand::OsRng::new()?;
    let keypair = ed25519::Keypair::generate::<sha2::Sha512>(&mut rng);
    let key_data = KeyData::create(keypair, timestamp);
    let config = Config::create(&key_data)?;

    let mut file = std::fs::File::create(keys_file)?;
    config.write(&mut file)?;
    println!("{}", key_data.public());
    Ok(())
}

fn keys_file() -> String {
    std::env::var("SIGNIFY_KEYS").unwrap_or_else(|_| {
        format!("{}/.signify_keys.toml", std::env::var("HOME").unwrap())
    })
}
