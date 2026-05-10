use std::{
    io::{Read, Seek},
    mem,
};

use camino::Utf8Path;
use color_eyre::eyre::{Result, bail};
use winget_types::{
    installer::Installer,
    locale::{Copyright, PackageName, Publisher},
};

use super::extensions::{APPX, APPX_BUNDLE, EXE, MSI, MSIX, MSIX_BUNDLE, ZIP};
use crate::analysis::{
    Installers,
    installers::{
        Exe, Msi, Zip,
        msix_family::{Msix, bundle::MsixBundle},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerAnalysisKind {
    Appx,
    Burn,
    GenericExe,
    Inno,
    Msi,
    Msix,
    Nullsoft,
    Squirrel,
    Velopack,
    AdvancedInstaller,
    Wix,
    Zip,
}

impl InstallerAnalysisKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Appx => "appx",
            Self::Burn => "burn",
            Self::GenericExe => "generic exe",
            Self::Inno => "inno",
            Self::Msi => "msi",
            Self::Msix => "msix",
            Self::Nullsoft => "nullsoft",
            Self::Squirrel => "squirrel",
            Self::Velopack => "velopack",
            Self::AdvancedInstaller => "advanced installer",
            Self::Wix => "wix",
            Self::Zip => "zip",
        }
    }
}

pub struct Analyzer<'reader, R: Read + Seek> {
    pub file_name: String,
    pub copyright: Option<Copyright>,
    pub installer_kind: Option<InstallerAnalysisKind>,
    pub nsis_infinite_loop: bool,
    pub package_name: Option<PackageName>,
    pub publisher: Option<Publisher>,
    pub installers: Vec<Installer>,
    pub zip: Option<Zip<&'reader mut R>>,
}

impl<'reader, R: Read + Seek> Analyzer<'reader, R> {
    pub fn new(reader: &'reader mut R, file_name: &str) -> Result<Self> {
        let extension = Utf8Path::new(file_name)
            .extension()
            .unwrap_or_default()
            .to_ascii_lowercase();

        match extension.as_str() {
            MSI => {
                let installers = Msi::new(reader)?.installers();
                let installer_kind = if installers.iter().any(|installer| {
                    installer.r#type == Some(winget_types::installer::InstallerType::Wix)
                }) {
                    InstallerAnalysisKind::Wix
                } else {
                    InstallerAnalysisKind::Msi
                };
                return Ok(Self {
                    installers,
                    installer_kind: Some(installer_kind),
                    ..Self::default()
                });
            }
            MSIX => {
                return Ok(Self {
                    installers: Msix::new(reader)?.installers(),
                    installer_kind: Some(InstallerAnalysisKind::Msix),
                    ..Self::default()
                });
            }
            APPX => {
                return Ok(Self {
                    installers: Msix::new(reader)?.installers(),
                    installer_kind: Some(InstallerAnalysisKind::Appx),
                    ..Self::default()
                });
            }
            MSIX_BUNDLE => {
                return Ok(Self {
                    installers: MsixBundle::new(reader)?.installers(),
                    installer_kind: Some(InstallerAnalysisKind::Msix),
                    ..Self::default()
                });
            }
            APPX_BUNDLE => {
                return Ok(Self {
                    installers: MsixBundle::new(reader)?.installers(),
                    installer_kind: Some(InstallerAnalysisKind::Appx),
                    ..Self::default()
                });
            }
            ZIP => {
                let mut scoped_zip = Zip::new(reader)?;
                let installers = mem::take(&mut scoped_zip.installers);
                return Ok(Self {
                    installers,
                    installer_kind: Some(InstallerAnalysisKind::Zip),
                    zip: Some(scoped_zip),
                    ..Self::default()
                });
            }
            EXE => {
                let mut exe = Exe::new(reader)?;
                return Ok(Self {
                    installers: exe.installers(),
                    installer_kind: Some(exe.analysis_kind()),
                    nsis_infinite_loop: exe.nsis_infinite_loop(),
                    copyright: exe
                        .legal_copyright
                        .take()
                        .and_then(|copyright| Copyright::new(copyright).ok()),
                    package_name: exe
                        .product_name
                        .take()
                        .and_then(|product_name| PackageName::new(product_name).ok()),
                    publisher: exe
                        .company_name
                        .take()
                        .and_then(|company_name| Publisher::new(company_name).ok()),
                    ..Self::default()
                });
            }
            _ => bail!(r#"Unsupported file extension: "{extension}""#),
        }
    }
}

impl<R: Read + Seek> Default for Analyzer<'_, R> {
    fn default() -> Self {
        Self {
            file_name: String::default(),
            copyright: None,
            installer_kind: None,
            nsis_infinite_loop: false,
            package_name: None,
            publisher: None,
            installers: Vec::default(),
            zip: None,
        }
    }
}
