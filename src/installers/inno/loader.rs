use std::{
    cmp::Ordering,
    io::{Cursor, Read},
};

use byteorder::{LE, ReadBytesExt};
use zerocopy::{Immutable, KnownLayout, TryFromBytes, little_endian::U32};

use crate::installers::inno::{InnoError, read::crc32::Crc32Reader, version::InnoVersion};

pub const SETUP_LOADER_OFFSET: usize = 0x30;
pub const SETUP_LOADER_RESOURCE: u32 = 11111;

#[expect(dead_code)]
#[derive(TryFromBytes, KnownLayout, Immutable)]
#[repr(u32)]
enum Magic {
    Inno = u32::from_le_bytes(*b"Inno"),
}

#[derive(TryFromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct SetupLoaderOffset {
    magic: Magic,
    pub table_offset: U32,
    pub not_table_offset: U32,
}

const SIGNATURE_LEN: usize = 12;

pub struct SetupLoaderVersion {
    signature: [u8; SIGNATURE_LEN],
    version: InnoVersion,
}

impl PartialEq<(u8, u8, u8)> for SetupLoaderVersion {
    fn eq(&self, other: &(u8, u8, u8)) -> bool {
        self.version.eq(other)
    }
}

impl PartialOrd<(u8, u8, u8)> for SetupLoaderVersion {
    fn partial_cmp(&self, other: &(u8, u8, u8)) -> Option<Ordering> {
        self.version.partial_cmp(other)
    }
}

const KNOWN_SETUP_LOADER_VERSIONS: [SetupLoaderVersion; 7] = [
    SetupLoaderVersion {
        signature: *b"rDlPtS02\x87eVx",
        version: InnoVersion::new(1, 2, 10, 0),
    },
    SetupLoaderVersion {
        signature: *b"rDlPtS04\x87eVx",
        version: InnoVersion::new(4, 0, 0, 0),
    },
    SetupLoaderVersion {
        signature: *b"rDlPtS05\x87eVx",
        version: InnoVersion::new(4, 0, 3, 0),
    },
    SetupLoaderVersion {
        signature: *b"rDlPtS06\x87eVx",
        version: InnoVersion::new(4, 0, 10, 0),
    },
    SetupLoaderVersion {
        signature: *b"rDlPtS07\x87eVx",
        version: InnoVersion::new(4, 1, 6, 0),
    },
    SetupLoaderVersion {
        signature: *b"rDlPtS\xCD\xE6\xD7{\x0B*",
        version: InnoVersion::new(5, 1, 5, 0),
    },
    SetupLoaderVersion {
        signature: *b"nS5W7dT\x83\xAA\x1B\x0Fj",
        version: InnoVersion::new(5, 1, 5, 0),
    },
];

#[expect(dead_code)]
enum Checksum {
    Adler32(u32),
    CRC32(u32),
}

#[expect(dead_code)]
pub struct SetupLoader {
    version: SetupLoaderVersion,
    revision: u32,
    /// Minimum expected size of setup.exe
    minimum_setup_exe_size: u32,
    /// Offset of compressed setup.e32
    exe_offset: u32,
    /// Size of setup.e32 after compression
    exe_compressed_size: u32,
    /// Size of setup.e32 before compression
    exe_uncompressed_size: u32,
    /// Checksum of setup.e32 before compression
    exe_checksum: Checksum,
    message_offset: u32,
    /// Offset of embedded setup-0.bin data
    pub header_offset: u32,
    /// Offset of embedded setup-1.bin data
    data_offset: u32,
}

impl SetupLoader {
    pub fn new(setup_loader_data: &[u8]) -> Result<Self, InnoError> {
        let mut checksum = Crc32Reader::new(Cursor::new(setup_loader_data));
        let mut signature = [0; SIGNATURE_LEN];
        checksum.read_exact(&mut signature)?;

        let loader_version = KNOWN_SETUP_LOADER_VERSIONS
            .into_iter()
            .find(|setup_loader_version| setup_loader_version.signature == signature)
            .ok_or(InnoError::UnknownLoaderSignature(signature))?;

        let revision = if loader_version >= (5, 1, 5) {
            checksum.read_u32::<LE>()?
        } else {
            0
        };

        let minimum_setup_exe_size = checksum.read_u32::<LE>()?;

        let exe_offset = checksum.read_u32::<LE>()?;

        let exe_compressed_size = if loader_version >= (4, 1, 6) {
            0
        } else {
            checksum.read_u32::<LE>()?
        };

        let exe_uncompressed_size = checksum.read_u32::<LE>()?;

        let exe_checksum = if loader_version >= (4, 0, 3) {
            Checksum::CRC32(checksum.read_u32::<LE>()?)
        } else {
            Checksum::Adler32(checksum.read_u32::<LE>()?)
        };

        let message_offset = if loader_version >= (4, 0, 0) {
            0
        } else {
            checksum.get_mut().read_u32::<LE>()?
        };

        let header_offset = checksum.read_u32::<LE>()?;
        let data_offset = checksum.read_u32::<LE>()?;

        if loader_version >= (4, 0, 10) {
            let expected_checksum = checksum.get_mut().read_u32::<LE>()?;
            let actual_checksum = checksum.finalize();
            if actual_checksum != expected_checksum {
                return Err(InnoError::CrcChecksumMismatch {
                    actual: actual_checksum,
                    expected: expected_checksum,
                });
            }
        }

        Ok(Self {
            version: loader_version,
            revision,
            minimum_setup_exe_size,
            exe_offset,
            exe_compressed_size,
            exe_uncompressed_size,
            exe_checksum,
            message_offset,
            header_offset,
            data_offset,
        })
    }
}
