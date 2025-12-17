use std::{io::Cursor, mem};

use camino::Utf8Path;
use color_eyre::eyre::Result;
use memmap2::Mmap;
use tracing::debug;
use winget_types::{
    installer::Installer,
    locale::{Copyright, PackageName, Publisher},
    utils::ValidFileExtensions,
};
use yara_x::mods::PE;

use crate::{
    analysis::{
        Installers,
        installers::{
            Exe, Font, Msi, Zip,
            msix_family::{Msix, bundle::MsixBundle},
        },
    },
    traits::FromVSVersionInfo,
};

pub struct Analyzer<'data> {
    pub file_name: String,
    pub copyright: Option<Copyright>,
    pub package_name: Option<PackageName>,
    pub publisher: Option<Publisher>,
    pub installers: Vec<Installer>,
    pub zip: Option<Zip<Cursor<&'data [u8]>>>,
}

impl<'data> Analyzer<'data> {
    pub fn new(data: &'data Mmap, file_name: &str) -> Result<Self> {
        let extension = Utf8Path::new(file_name)
            .extension()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .parse::<ValidFileExtensions>()?;

        let mut zip = None;
        let mut copyright = None;
        let mut package_name = None;
        let mut publisher = None;
        let installers = match extension {
            ValidFileExtensions::Msi => Msi::new(Cursor::new(data.as_ref()))?.installers(),
            ValidFileExtensions::Msix | ValidFileExtensions::Appx => {
                Msix::new(Cursor::new(data.as_ref()))?.installers()
            }
            ValidFileExtensions::MsixBundle | ValidFileExtensions::AppxBundle => {
                MsixBundle::new(Cursor::new(data.as_ref()))?.installers()
            }
            ValidFileExtensions::Zip => {
                let mut scoped_zip = Zip::new(Cursor::new(data.as_ref()))?;
                let installers = mem::take(&mut scoped_zip.installers);
                zip = Some(scoped_zip);
                installers
            }
            ValidFileExtensions::Exe => {
                let pe = yara_x::mods::invoke::<PE>(data.as_ref()).unwrap();
                debug!(?pe.version_info);
                copyright = Copyright::from_version_info(&pe.version_info);
                package_name = PackageName::from_version_info(&pe.version_info);
                publisher = Publisher::from_version_info(&pe.version_info);
                Exe::new(Cursor::new(data.as_ref()), &pe)?.installers()
            }
            ValidFileExtensions::Fnt
            | ValidFileExtensions::Otc
            | ValidFileExtensions::Otf
            | ValidFileExtensions::Ttc
            | ValidFileExtensions::Ttf => {
                Font::new(Cursor::new(data.as_ref()), file_name)?.installers()
            }
        };
        Ok(Self {
            installers,
            file_name: String::new(),
            copyright,
            package_name,
            publisher,
            zip,
        })
    }
}
