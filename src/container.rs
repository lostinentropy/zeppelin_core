//! This module provides an easy to use API to apply the cipher to a reader/writer.

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use zip::{result::ZipResult, write::FileOptions, ZipArchive, ZipWriter};
use zip::{CompressionMethod, DateTime};

use crate::cipher::{decrypt, decrypt_salt, encrypt, CryptSettings};
use crate::progress::Progress;

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ContainerMetadata {
    version: String,
    settings: CryptSettings,
}

/// Create a container reading data from `source` and writing to `dest`.
/// This is the recommended way to encrypt data with this crate.
pub fn create_container<R: Read + Seek, W: Write + Seek>(
    source: &mut R,
    dest: &mut W,
    key: impl AsRef<[u8]>,
    settings: CryptSettings,
    prog: Option<Progress>,
) -> ZipResult<()> {
    let prog = if let Some(inner) = prog {
        inner
    } else {
        Progress::new()
    };
    let metadata = ContainerMetadata {
        version: env!("CARGO_PKG_VERSION").to_string(),
        settings,
    };
    let len = source.seek(SeekFrom::End(0))?;
    source.rewind()?;

    prog.set_max_data(len as usize);

    let file_options = FileOptions::default()
        .last_modified_time(DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap())
        .compression_method(CompressionMethod::Stored);

    let mut zip = ZipWriter::new(dest);
    zip.set_comment("Created by zeppelin_core");

    zip.start_file(
        "metadata.json",
        file_options.compression_method(CompressionMethod::Deflated),
    )?;
    
    zip.write_all(serde_json::to_string(&metadata).unwrap().as_bytes())?;

    zip.start_file("data.dat", file_options)?;
    let salt = encrypt(source, &mut zip, key, settings, prog)?;

    zip.start_file("salt.dat", file_options)?;
    zip.write_all(&salt)?;

    zip.finish()?;
    Ok(())
}

/// Decrypt a container reading from `source` and writing to `dest`.
/// Returns `true` if container was decrypted successfully, e.g. the
/// same password was used for encryption and decryption. Returns
/// `ZipError` if container is invalid.
/// ### Note:
/// Even if the password does not match, data will be written to `dest`
/// to avoid caching.
pub fn read_container<R: Read + Seek, W: Write>(
    source: &mut R,
    dest: &mut W,
    key: impl AsRef<[u8]>,
    prog: Option<Progress>,
) -> ZipResult<bool> {
    let prog = if let Some(inner) = prog {
        inner
    } else {
        Progress::new()
    };

    let mut zip = ZipArchive::new(source)?;

    let mut metadata_file = zip.by_name("metadata.json")?;
    let metadata: serde_json::Result<ContainerMetadata> =
        serde_json::from_reader(&mut metadata_file);
    let metadata = if let Ok(inner) = metadata {
        inner
    } else {
        // This seems a little long
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid `metadata.json` found").into());
    };
    drop(metadata_file);

    let mut salt = [0_u8; 64];
    let mut salt_file = zip.by_name("salt.dat")?;
    salt_file.read_exact(&mut salt)?;
    drop(salt_file);

    let mut data_file = zip.by_name("data.dat")?;
    decrypt_salt(&mut salt, &mut data_file)?;
    drop(data_file);

    let mut data_file = zip.by_name("data.dat")?;
    prog.set_max_data(data_file.size() as usize);
    let success = decrypt(&mut data_file, dest, key, &salt, metadata.settings, prog)?;

    Ok(success)
}

/// Used only internally; Writes random bytes to writer
fn override_writer<W: Write>(dest: &mut W, len: u64) -> io::Result<()> {
    let mut rng = ChaCha20Rng::from_entropy();
    io::copy(&mut (&mut rng as &mut dyn RngCore).take(len), dest)?;
    Ok(())
}

/// Completely overrides file with random noise, then deletes it.
pub fn erase_file(file: PathBuf) -> std::io::Result<()> {
    {
        let len: u64 = fs::metadata(file.clone())?.len();
        let mut tmp = fs::OpenOptions::new().write(true).open(file.clone())?;
        override_writer(&mut tmp, len)?;
        tmp.flush()?; // Should force write to be committed to disk
        drop(tmp); // Just in case `}` doesn't close file
    }
    std::fs::remove_file(file)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;

    use crate::cipher;

    use super::*;

    #[test]
    fn metadata_serialize() {
        let data1 = ContainerMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            settings: cipher::CryptSettings::default_for_testing(),
        };
        let serial = serde_json::to_string(&data1).unwrap();

        let data2: ContainerMetadata = serde_json::from_str(&serial).unwrap();

        assert_eq!(data1, data2);
    }

    #[test]
    fn override_cursor() {
        let mut disk = io::Cursor::new(Vec::<u8>::from([0_u8; 64]));
        override_writer(&mut disk, 64).unwrap();
    }

    #[test]
    fn container_read_and_write() {
        let data: Vec<u8> = (0..10_u64.pow(1)).map(|b| b as u8).collect();
        let mut source = io::Cursor::new(data);

        let mut container = io::Cursor::new(Vec::<u8>::new());

        create_container(
            &mut source,
            &mut container,
            "passwd",
            cipher::CryptSettings::default_for_testing(),
            None,
        )
        .unwrap();
        container.rewind().unwrap();

        let mut res = io::Cursor::new(Vec::<u8>::new());

        let success = read_container(&mut container, &mut res, "passwd", None).unwrap();

        assert!(success);
        assert_eq!(source.into_inner(), res.into_inner());
    }

    #[test]
    fn container_wrong_passwd() {
        let data: Vec<u8> = (0..10_u64.pow(1)).map(|b| b as u8).collect();
        let mut source = io::Cursor::new(data);

        let mut container = io::Cursor::new(Vec::<u8>::new());

        create_container(
            &mut source,
            &mut container,
            "passwd",
            cipher::CryptSettings::default_for_testing(),
            None,
        )
        .unwrap();
        container.rewind().unwrap();

        let mut res = io::Cursor::new(Vec::<u8>::new());

        let success = read_container(&mut container, &mut res, "wrong passwd", None).unwrap();

        assert!(!success);
    }
}
