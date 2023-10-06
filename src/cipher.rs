//! Implementation of stream cipher based on Balloon-hashing called `Stream`.
//! Additionally defines `CryptSettings` object that encapsulates all information
//! required to perform cryptographic operations.

use crate::hash::Balloon;
use crate::progress::Progress;

use sha3::{Digest, Sha3_512};

use std::io::{self, Read, Seek, Write};

use serde::{Deserialize, Serialize};

/// Struct to encapsulate all parameters required for Balloon-Hashing.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct CryptSettings {
    pub s_cost: usize,
    pub t_cost: usize,
    pub step_delta: usize,
}

#[allow(dead_code)]
impl CryptSettings {
    /// Less aggressiv settings used primarily for testing.
    pub fn default_for_testing() -> Self {
        Self {
            s_cost: 1000,
            t_cost: 2,
            step_delta: 3,
        }
    }
}

impl std::default::Default for CryptSettings {
    /// Default settings with `s_cost` ~ 30 MB
    fn default() -> Self {
        Self {
            s_cost: 468750,
            t_cost: 2,
            step_delta: 3,
        }
    }
}

/// Stream cipher like struct.
/// Includes cache of stream.
pub struct Stream {
    balloon: Balloon,
    mask: [u8; 64],
    mask_ptr: usize,
    salt_ptr: usize,
}

impl Stream {
    /// Create a new stream cipher from `CryptSettings`
    fn new(
        passwd: impl AsRef<[u8]>,
        salt: Vec<u8>,
        settings: CryptSettings,
        prog: Progress,
    ) -> Self {
        let s_cost = settings.s_cost;
        let t_cost = settings.t_cost;
        let step_delta = settings.step_delta;

        let mut balloon = Balloon::new(passwd, salt, s_cost, t_cost, step_delta, prog.clone());
        let mask = balloon.step(prog);
        Self {
            balloon,
            mask,
            mask_ptr: 0,
            salt_ptr: 0,
        }
    }

    /// Applies stream cipher to `data`, dynamically updating internal mask.
    /// Additionally performs "wrapped `XOR`" with result and salt, effectively
    /// encrypting the salt.
    fn apply_with_salt(&mut self, mut data: impl AsMut<[u8]>, salt: &mut [u8; 64], prog: Progress) {
        for byte in data.as_mut() {
            if self.mask_ptr >= 64 {
                self.mask = self.balloon.step(prog.clone());
                self.mask_ptr = 0;
            }
            *byte ^= self.mask[self.mask_ptr];
            salt[self.salt_ptr % 64] ^= *byte;
            self.mask_ptr += 1;
            self.salt_ptr += 1;
        }
    }

    /// Applies stream cipher to `data`, dynamically updating internal mask.
    /// Additionally reads in output to a provided hasher.
    fn apply_with_hash(&mut self, mut data: impl AsMut<[u8]>, hash: &mut Sha3_512, prog: Progress) {
        for byte in data.as_mut() {
            if self.mask_ptr >= 64 {
                self.mask = self.balloon.step(prog.clone());
                self.mask_ptr = 0;
            }
            *byte ^= self.mask[self.mask_ptr];
            hash.update([*byte]); // TODO: Hash more than a byte at a time
            self.mask_ptr += 1;
        }
    }

    /// Like apply but gets data from reader and puts it into writer.
    fn copy_and_apply_with_salt(
        &mut self,
        src: &mut impl Read,
        dest: &mut impl Write,
        salt: &mut [u8; 64],
        prog: Progress,
    ) -> io::Result<()> {
        const BUFFER_SIZE: usize = 8 * 1024; // Same as BufReader
        let mut buffer = [0_u8; BUFFER_SIZE];
        loop {
            let n = src.read(&mut buffer[..])?;
            if n == 0 {
                break;
            };
            self.apply_with_salt(&mut buffer[0..n], salt, prog.clone());
            dest.write_all(&buffer[0..n])?;
        }
        Ok(())
    }

    fn copy_and_apply_with_hash(
        &mut self,
        src: &mut impl Read,
        dest: &mut impl Write,
        hash: &mut Sha3_512,
        prog: Progress,
    ) -> io::Result<()> {
        const BUFFER_SIZE: usize = 8 * 1024; // Same as BufReader
        let mut buffer = [0_u8; BUFFER_SIZE];
        loop {
            let n = src.read(&mut buffer[..])?;
            if n == 0 {
                break;
            };
            self.apply_with_hash(&mut buffer[0..n], hash, prog.clone());
            dest.write_all(&buffer[0..n])?;
        }
        Ok(())
    }
}

/// Generate salt using entropy from OS.
fn gen_salt() -> [u8; 64] {
    use rand::prelude::*;
    use rand_chacha::ChaCha20Rng;

    // uses getrandom which gets entropy from OS
    let mut rng = ChaCha20Rng::from_entropy();
    let mut res = [0_u8; 64];
    rng.fill(&mut res[..]);
    res
}

fn derive_password(key: impl AsRef<[u8]>, salt: impl AsRef<[u8]>) -> argon2::Result<[u8; 64]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let mut output = [0u8; 64];
    let params = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST * 10,
        Params::DEFAULT_P_COST,
        None,
    )?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password_into(key.as_ref(), salt.as_ref(), &mut output)?;
    Ok(output)
}

/// Encrypts in a stream like fashion reading from `source` and writing to `dest`.
/// Returns `salt` needed for decryption. Resulting message contains *MAC*.
pub fn encrypt<R: Read + Seek, W: Write>(
    source: &mut R,
    dest: &mut W,
    key: impl AsRef<[u8]>,
    settings: CryptSettings,
    prog: Progress,
) -> io::Result<[u8; 64]> {
    // Derive key
    prog.set_state("Deriving Password".to_string());
    let mut salt = gen_salt();
    let key = if let Ok(inner) = derive_password(key, salt) {
        inner
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Unable to derive password",
        ));
    };

    // Calculate MAC
    prog.set_state("Calculating MAC".to_string());
    let mut mac_hash = Sha3_512::new();
    mac_hash.update(&key);
    io::copy(source, &mut mac_hash)?;
    source.rewind()?;
    let mac: [u8; 64] = mac_hash.finalize().into();
    let mut mac = io::Cursor::new(mac);

    // Initialize Stream
    let mut stream = Stream::new(&key, salt.to_vec(), settings, prog.clone());

    prog.set_state("Encrypting".to_string());

    // Encrypt and Write to output
    stream.copy_and_apply_with_salt(&mut mac, dest, &mut salt, prog.clone())?;
    stream.copy_and_apply_with_salt(source, dest, &mut salt, prog)?;

    Ok(salt)
}

pub fn decrypt_salt<R: Read>(salt: &mut [u8; 64], source: &mut R) -> io::Result<()> {
    let mut salt_ptr = 0;
    const BUFFER_SIZE: usize = 8 * 1024; // Same as BufReader
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        let n = source.read(&mut buffer[..])?;
        if n == 0 {
            break;
        };
        for item in buffer.iter().take(n) {
            salt[salt_ptr % 64] ^= item;
            salt_ptr += 1;
        }
    }
    Ok(())
}

/// Decrypts in a stream like fashion reading from `source` and writing to `dest`.
/// Inverse of `encrypt`. Salt that was encrypted by `encrypt` needs to be decrypted
/// separately since the reader a priori doesn't implement `std::io::Cursor`.
/// Returns true if expected MAC and MAC of output match.
pub fn decrypt<R: Read, W: Write>(
    source: &mut R,
    dest: &mut W,
    key: impl AsRef<[u8]>,
    decrypted_salt: &[u8; 64],
    settings: CryptSettings,
    prog: Progress,
) -> io::Result<bool> {
    prog.set_state("Deriving Password".to_string());
    let key = if let Ok(inner) = derive_password(key, decrypted_salt) {
        inner
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Unable to derive password",
        ));
    };

    let mut expected_mac = [0_u8; 64];

    let mut stream = Stream::new(&key, decrypted_salt.to_vec(), settings, prog.clone());

    prog.set_state("Decrypting".to_string());

    source.read_exact(&mut expected_mac)?;
    stream.apply_with_salt(&mut expected_mac, &mut [0_u8; 64], prog.clone());

    let mut mac_hash = Sha3_512::new();
    mac_hash.update(&key);
    stream.copy_and_apply_with_hash(source, dest, &mut mac_hash, prog)?;

    let mac: [u8; 64] = mac_hash.finalize().into();

    Ok(expected_mac == mac)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::iter;

    use super::*;
    use crate::cipher::CryptSettings;
    use crate::progress::Progress;

    #[test]
    fn apply_and_copy() {
        let mut data: Vec<u8> = (0..255).collect();
        let mut c = io::Cursor::new(data.clone());
        let mut data2 = Vec::<u8>::new();

        let salt: Vec<u8> = vec![1, 2, 3];
        let mut s1 = Stream::new(
            b"123",
            salt.clone(),
            CryptSettings::default_for_testing(),
            Progress::new(),
        );
        let mut s2 = Stream::new(
            b"123",
            salt.clone(),
            CryptSettings::default_for_testing(),
            Progress::new(),
        );

        let mut salt1 = [0u8; 64];
        let mut salt2 = [0u8; 64];

        s1.apply_with_salt(&mut data, &mut salt1, Progress::new());
        s2.copy_and_apply_with_salt(&mut c, &mut data2, &mut salt2, Progress::new())
            .unwrap();

        assert_eq!(data, data2);
        assert_eq!(salt1, salt2);
    }

    /// Current implementation of `Stream` has two apply definitions.
    /// This checks their equality.
    #[test]
    fn apply_implementations_equiv() {
        let passwd = "password";
        let salt = vec![1, 2, 3];
        let settings = CryptSettings::default_for_testing();
        let prog = Progress::new();
        let mut s1 = Stream::new(passwd, salt.clone(), settings, Progress::new());
        let mut s2 = Stream::new(passwd, salt, settings, prog.clone());

        let mut data: Vec<u8> = (0..10_u64.pow(6)).map(|b| b as u8).collect();
        let mut data2 = data.clone();

        s1.apply_with_hash(&mut data, &mut Sha3_512::new(), prog.clone());
        s2.apply_with_salt(&mut data2, &mut [0_u8; 64], prog);

        assert_eq!(data, data2)
    }

    #[test]
    fn encrypt_and_decrypt() {
        let key = "password";
        let settings = CryptSettings::default_for_testing();
        let prog = Progress::new();

        let data: Vec<u8> = (0..10_u64.pow(6)).map(|b| b as u8).collect();
        let mut source = Cursor::new(data.clone());

        let mut dest = Cursor::new(Vec::<u8>::new());
        let mut dest2 = Cursor::new(Vec::<u8>::new());

        let mut salt = encrypt(&mut source, &mut dest, key, settings, prog.clone()).unwrap();

        prog.set_state("Decrypting salt".to_string());

        dest.rewind().unwrap();
        decrypt_salt(&mut salt, &mut dest).unwrap();
        dest.rewind().unwrap();

        decrypt(&mut dest, &mut dest2, key, &salt, settings, prog).unwrap();

        assert_eq!(data, dest2.into_inner());
    }

    // Todo: Add a test that checks decryption with wrong key

    /// Tests if bytes after encryption are approximately equally distributed.
    #[test]
    fn cipher_text_random() {
        let mut cnt = [0usize; 256];

        let len = 10000000; // ~10MB

        let settings = CryptSettings::default_for_testing();
        let mut data = Cursor::new((0..len).map(|_| 255 / 2).collect::<Vec<u8>>());
        let mut out = Cursor::new(Vec::new());
        encrypt(&mut data, &mut out, "passwd", settings, Progress::new()).unwrap();

        for byte in out.into_inner() {
            cnt[byte as usize] += 1;
        }

        let mut max_dist = 0;
        for (prev, current) in iter::zip(cnt.iter(), cnt.iter().skip(1)) {
            let tmp = (*prev as usize).abs_diff(*current as usize);
            if tmp > max_dist {
                max_dist = tmp;
            }
        }
        assert!((max_dist as f64 / len as f64) < 0.0005); // fluctuations less than 0.05%
    }

    #[test]
    fn apply_with_hash_is_correct() {
        let mut hasher1 = Sha3_512::new();
        let mut data: Vec<u8> = (0..10_u64.pow(1)).map(|b| b as u8).collect();

        let mut s = Stream::new(
            "passwd",
            Vec::from([0_u8; 64]),
            CryptSettings::default_for_testing(),
            Progress::new(),
        );

        s.apply_with_hash(&mut data, &mut hasher1, Progress::new());

        let mut hasher2 = Sha3_512::new();
        hasher2.update(data);

        let hash1: [u8; 64] = hasher1.finalize().into();
        let hash2: [u8; 64] = hasher2.finalize().into();

        assert_eq!(hash1, hash2);
    }
}
