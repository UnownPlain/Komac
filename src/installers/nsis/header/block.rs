use crate::installers::nsis::NsisError;
use crate::installers::utils::transmute_from_reader;
use crate::types::architecture::Architecture;
use std::borrow::Cow;
use std::io::Cursor;
use std::ops::Index;
use std::slice::{Iter, IterMut};
use strum::EnumCount;
use zerocopy::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout};

#[derive(Clone, Debug, Default, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct BlockHeader {
    pub offset: U64,
    pub num: U32,
}

#[expect(dead_code)]
#[derive(Copy, Clone, EnumCount)]
pub enum BlockType {
    Pages,
    Sections,
    Entries,
    Strings,
    LangTables,
    CtlColors,
    BgFont,
    Data,
}

impl BlockType {
    pub fn get<'data>(self, data: &'data [u8], blocks: &BlockHeaders) -> &'data [u8] {
        let start = blocks[self].offset.get() as usize;
        let end = blocks
            .iter()
            .skip(self as usize + 1)
            .find(|b| b.offset > U64::ZERO)
            .map_or(start, |block| block.offset.get() as usize);
        &data[start..end]
    }
}

#[derive(Clone, Debug, Default, FromBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct BlockHeaders([BlockHeader; BlockType::COUNT]);

impl BlockHeaders {
    pub fn iter(&self) -> Iter<BlockHeader> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> IterMut<BlockHeader> {
        self.0.iter_mut()
    }

    /// If the NSIS installer is 64-bit, the offset value in the `BlockHeader` is a u64 rather than
    /// a u32. This aims to still use zerocopy as much as possible, although the data will need to
    /// be owned if the offsets are u32's.
    pub fn read_dynamic_from_prefix(
        data: &[u8],
        architecture: Architecture,
    ) -> Result<(Cow<Self>, &[u8]), NsisError> {
        if architecture.is_64_bit() {
            Self::ref_from_prefix(data)
                .map(|(headers, rest)| (Cow::Borrowed(headers), rest))
                .map_err(|error| NsisError::ZeroCopy(error.to_string()))
        } else {
            let mut reader = Cursor::new(data);
            let mut block_headers = Self::default();
            for header in block_headers.iter_mut() {
                *header = BlockHeader {
                    offset: U64::from(transmute_from_reader::<U32>(&mut reader)?),
                    num: transmute_from_reader(&mut reader)?,
                }
            }
            Ok((
                Cow::Owned(block_headers),
                &data[usize::try_from(reader.position()).unwrap_or_default()..],
            ))
        }
    }
}

impl Index<BlockType> for BlockHeaders {
    type Output = BlockHeader;

    fn index(&self, index: BlockType) -> &Self::Output {
        self.0.index(index as usize)
    }
}
