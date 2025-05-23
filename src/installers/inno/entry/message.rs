use std::io::{Read, Result};

use byteorder::{LE, ReadBytesExt};
use encoding_rs::Encoding;

use crate::installers::inno::{encoding::InnoValue, entry::language::Language};

#[expect(dead_code)]
#[derive(Debug, Default)]
pub struct Message {
    name: String,
    value: String,
    language_index: i32,
}

impl Message {
    pub fn from_reader<R: Read>(
        reader: &mut R,
        languages: &[Language],
        codepage: &'static Encoding,
    ) -> Result<Self> {
        let mut message = Self {
            name: InnoValue::new_string(reader, codepage)?.unwrap_or_default(),
            ..Self::default()
        };

        let value = InnoValue::new_encoded(reader)?.unwrap_or_default();

        message.language_index = reader.read_i32::<LE>()?;

        let mut codepage = codepage;
        if message.language_index >= 0 {
            if let Some(language) = usize::try_from(message.language_index)
                .ok()
                .and_then(|index| languages.get(index))
            {
                codepage = language.codepage;
            }
        }

        message.value = value.into_string(codepage);

        Ok(message)
    }
}
