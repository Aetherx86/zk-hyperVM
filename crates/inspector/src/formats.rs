//! Executable format parsers. Every offset and size comes from an untrusted file, so all reads go
//! through bounds-checked helpers and counts are capped before anything loops over them.

use crate::{Architecture, InspectError, Section, Symbol};

pub struct Segment {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub executable: bool,
}

/// A binary mapped into its virtual address space.
pub struct Image {
    pub format: &'static str,
    pub architecture: Architecture,
    pub entry: Option<u64>,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub notes: Vec<String>,
}

impl Image {
    /// The bytes available at an address, within an executable segment.
    pub fn code_at(&self, address: u64) -> Option<&[u8]> {
        for segment in &self.segments {
            if !segment.executable {
                continue;
            }
            let offset = address.checked_sub(segment.address)?;
            if let Some(slice) = usize::try_from(offset)
                .ok()
                .and_then(|o| segment.bytes.get(o..))
            {
                if !slice.is_empty() {
                    return Some(slice);
                }
            }
        }
        None
    }
}

const MAX_SECTIONS: usize = 4096;
const MAX_SEGMENTS: usize = 256;
const MAX_SYMBOLS: usize = 20_000;

fn u16le(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64le(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

fn c_string(b: &[u8], at: usize) -> String {
    let Some(tail) = b.get(at..) else {
        return String::new();
    };
    let end = tail
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(tail.len())
        .min(256);
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

/// Copies a file range, tolerating a range that runs past the end of a truncated file.
fn file_range(b: &[u8], offset: u64, size: u64) -> Vec<u8> {
    let Ok(start) = usize::try_from(offset) else {
        return Vec::new();
    };
    if start >= b.len() {
        return Vec::new();
    }
    let available = (b.len() - start) as u64;
    b[start..start + size.min(available) as usize].to_vec()
}

const TRUNCATED: InspectError = InspectError::Malformed("the file ends in the middle of a header");

pub fn parse_elf(b: &[u8]) -> Result<Image, InspectError> {
    if b.len() < 52 {
        return Err(TRUNCATED);
    }
    let is64 = match b[4] {
        1 => false,
        2 => true,
        _ => return Err(InspectError::Malformed("ELF class is invalid")),
    };
    if b[5] != 1 {
        return Err(InspectError::Unsupported("big-endian ELF files".into()));
    }
    let machine = u16le(b, 18).ok_or(TRUNCATED)?;
    let architecture = match machine {
        3 => Architecture::X86,
        62 => Architecture::X86_64,
        183 => Architecture::Aarch64,
        243 => Architecture::Riscv64,
        other => Architecture::Unknown(format!("ELF machine {other}")),
    };
    let read_word = |at: usize| -> Option<u64> {
        if is64 {
            u64le(b, at)
        } else {
            u32le(b, at).map(u64::from)
        }
    };
    let (entry, ph_off, sh_off) = if is64 {
        (read_word(24), read_word(32), read_word(40))
    } else {
        (read_word(24), read_word(28), read_word(32))
    };
    let header = if is64 { 54 } else { 42 };
    let ph_size = u16le(b, header).ok_or(TRUNCATED)? as usize;
    let ph_count = u16le(b, header + 2).ok_or(TRUNCATED)? as usize;
    let sh_size = u16le(b, header + 4).ok_or(TRUNCATED)? as usize;
    let sh_count = u16le(b, header + 6).ok_or(TRUNCATED)? as usize;
    let sh_names = u16le(b, header + 8).ok_or(TRUNCATED)? as usize;

    let mut segments = Vec::new();
    for i in 0..ph_count.min(MAX_SEGMENTS) {
        let Some(at) = ph_off
            .and_then(|o| usize::try_from(o).ok())
            .and_then(|o| o.checked_add(i.checked_mul(ph_size)?))
        else {
            break;
        };
        let (kind, flags, offset, vaddr, filesz) = if is64 {
            (
                u32le(b, at),
                u32le(b, at + 4),
                u64le(b, at + 8),
                u64le(b, at + 16),
                u64le(b, at + 32),
            )
        } else {
            (
                u32le(b, at),
                u32le(b, at + 24),
                u32le(b, at + 4).map(u64::from),
                u32le(b, at + 8).map(u64::from),
                u32le(b, at + 16).map(u64::from),
            )
        };
        let (Some(kind), Some(flags), Some(offset), Some(vaddr), Some(filesz)) =
            (kind, flags, offset, vaddr, filesz)
        else {
            break;
        };
        if kind == 1 {
            segments.push(Segment {
                address: vaddr,
                bytes: file_range(b, offset, filesz),
                executable: flags & 1 != 0,
            });
        }
    }

    // Section headers are optional, so a stripped file simply has fewer details.
    let section_header = |i: usize| -> Option<usize> {
        usize::try_from(sh_off?)
            .ok()?
            .checked_add(i.checked_mul(sh_size)?)
    };
    let name_table = section_header(sh_names).and_then(|at| {
        if is64 {
            u64le(b, at + 24)
        } else {
            u32le(b, at + 16).map(u64::from)
        }
    });
    let mut sections = Vec::new();
    let mut symbol_tables = Vec::new();
    for i in 0..sh_count.min(MAX_SECTIONS) {
        let Some(at) = section_header(i) else { break };
        let (name, kind, flags, addr, offset, size, link) = if is64 {
            (
                u32le(b, at),
                u32le(b, at + 4),
                u64le(b, at + 8),
                u64le(b, at + 16),
                u64le(b, at + 24),
                u64le(b, at + 32),
                u32le(b, at + 40),
            )
        } else {
            (
                u32le(b, at),
                u32le(b, at + 4),
                u32le(b, at + 8).map(u64::from),
                u32le(b, at + 12).map(u64::from),
                u32le(b, at + 16).map(u64::from),
                u32le(b, at + 20).map(u64::from),
                u32le(b, at + 24),
            )
        };
        let (Some(name), Some(kind), Some(flags), Some(addr), Some(offset), Some(size), Some(link)) =
            (name, kind, flags, addr, offset, size, link)
        else {
            break;
        };
        let display = name_table
            .and_then(|t| usize::try_from(t).ok())
            .and_then(|t| t.checked_add(name as usize))
            .map(|at| c_string(b, at))
            .unwrap_or_default();
        sections.push(Section {
            name: display,
            address: addr,
            size,
            file_offset: offset,
            executable: flags & 4 != 0,
        });
        // 2 is .symtab and 11 is .dynsym.
        if kind == 2 || kind == 11 {
            symbol_tables.push((offset, size, link));
        }
    }

    let mut symbols = Vec::new();
    for (offset, size, link) in symbol_tables {
        let strings = section_header(link as usize).and_then(|at| {
            if is64 {
                u64le(b, at + 24)
            } else {
                u32le(b, at + 16).map(u64::from)
            }
        });
        let entry_size = if is64 { 24 } else { 16 };
        let count = (size / entry_size as u64).min(MAX_SYMBOLS as u64) as usize;
        let Ok(base) = usize::try_from(offset) else {
            continue;
        };
        for i in 0..count {
            if symbols.len() >= MAX_SYMBOLS {
                break;
            }
            let Some(at) = i.checked_mul(entry_size).and_then(|d| base.checked_add(d)) else {
                break;
            };
            let (name, info, value, sym_size) = if is64 {
                (
                    u32le(b, at),
                    b.get(at + 4).copied(),
                    u64le(b, at + 8),
                    u64le(b, at + 16),
                )
            } else {
                (
                    u32le(b, at),
                    b.get(at + 12).copied(),
                    u32le(b, at + 4).map(u64::from),
                    u32le(b, at + 8).map(u64::from),
                )
            };
            let (Some(name), Some(info), Some(value), Some(sym_size)) =
                (name, info, value, sym_size)
            else {
                break;
            };
            // Only defined functions are useful as starting points for disassembly.
            if info & 0xF != 2 || value == 0 {
                continue;
            }
            let display = strings
                .and_then(|t| usize::try_from(t).ok())
                .and_then(|t| t.checked_add(name as usize))
                .map(|at| c_string(b, at))
                .unwrap_or_default();
            symbols.push(Symbol {
                name: display,
                address: value,
                size: sym_size,
            });
        }
    }

    Ok(Image {
        format: if is64 { "ELF64" } else { "ELF32" },
        architecture,
        entry: entry.filter(|e| *e != 0),
        segments,
        sections,
        symbols,
        notes: Vec::new(),
    })
}

pub fn parse_pe(b: &[u8]) -> Result<Image, InspectError> {
    let pe_at = u32le(b, 0x3C).ok_or(TRUNCATED)? as usize;
    if b.get(pe_at..pe_at.checked_add(4).ok_or(TRUNCATED)?) != Some(b"PE\0\0".as_slice()) {
        return Err(InspectError::Malformed("the PE signature is missing"));
    }
    let coff = pe_at + 4;
    let machine = u16le(b, coff).ok_or(TRUNCATED)?;
    let architecture = match machine {
        0x14C => Architecture::X86,
        0x8664 => Architecture::X86_64,
        0xAA64 => Architecture::Aarch64,
        other => Architecture::Unknown(format!("PE machine {other:#x}")),
    };
    let section_count = u16le(b, coff + 2).ok_or(TRUNCATED)? as usize;
    let optional_size = u16le(b, coff + 16).ok_or(TRUNCATED)? as usize;
    let optional = coff + 20;
    let magic = u16le(b, optional).ok_or(TRUNCATED)?;
    let entry_rva = u32le(b, optional + 16).ok_or(TRUNCATED)?;
    let image_base = match magic {
        0x10B => u64::from(u32le(b, optional + 28).ok_or(TRUNCATED)?),
        0x20B => u64le(b, optional + 24).ok_or(TRUNCATED)?,
        _ => {
            return Err(InspectError::Malformed(
                "the PE optional header magic is invalid",
            ))
        }
    };
    let table = optional.checked_add(optional_size).ok_or(TRUNCATED)?;
    let mut sections = Vec::new();
    let mut segments = Vec::new();
    for i in 0..section_count.min(MAX_SECTIONS) {
        let at = table + i * 40;
        let Some(raw_name) = b.get(at..at + 8) else {
            break;
        };
        let (Some(virtual_size), Some(rva), Some(raw_size), Some(raw_offset), Some(flags)) = (
            u32le(b, at + 8),
            u32le(b, at + 12),
            u32le(b, at + 16),
            u32le(b, at + 20),
            u32le(b, at + 36),
        ) else {
            break;
        };
        let end = raw_name.iter().position(|c| *c == 0).unwrap_or(8);
        let executable = flags & 0x2000_0000 != 0;
        let address = image_base.wrapping_add(u64::from(rva));
        sections.push(Section {
            name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
            address,
            size: u64::from(virtual_size),
            file_offset: u64::from(raw_offset),
            executable,
        });
        if segments.len() < MAX_SEGMENTS {
            segments.push(Segment {
                address,
                bytes: file_range(b, u64::from(raw_offset), u64::from(raw_size)),
                executable,
            });
        }
    }
    Ok(Image {
        format: if magic == 0x20B { "PE32+" } else { "PE32" },
        architecture,
        entry: (entry_rva != 0).then(|| image_base.wrapping_add(u64::from(entry_rva))),
        segments,
        sections,
        symbols: Vec::new(),
        notes: Vec::new(),
    })
}

pub fn parse_macho(b: &[u8]) -> Result<Image, InspectError> {
    let cpu = u32le(b, 4).ok_or(TRUNCATED)?;
    let architecture = match cpu {
        0x0100_0007 => Architecture::X86_64,
        0x0100_000C => Architecture::Aarch64,
        other => Architecture::Unknown(format!("Mach-O CPU {other:#x}")),
    };
    let commands = u32le(b, 16).ok_or(TRUNCATED)? as usize;
    let mut at = 32usize;
    let mut segments = Vec::new();
    let mut sections = Vec::new();
    let mut symbols = Vec::new();
    let mut entry_offset = None;
    let mut text_base = None;
    for _ in 0..commands.min(MAX_SECTIONS) {
        let (Some(kind), Some(size)) = (u32le(b, at), u32le(b, at + 4)) else {
            break;
        };
        let size = size as usize;
        if size < 8 {
            return Err(InspectError::Malformed(
                "a Mach-O load command has an invalid size",
            ));
        }
        match kind {
            0x19 => {
                // LC_SEGMENT_64
                let name = c_string(&b[..(at + 24).min(b.len())], at + 8);
                let (Some(vmaddr), Some(fileoff), Some(filesize), Some(initprot), Some(nsects)) = (
                    u64le(b, at + 24),
                    u64le(b, at + 40),
                    u64le(b, at + 48),
                    u32le(b, at + 60),
                    u32le(b, at + 64),
                ) else {
                    break;
                };
                if name == "__TEXT" {
                    text_base = Some(vmaddr);
                }
                if segments.len() < MAX_SEGMENTS {
                    segments.push(Segment {
                        address: vmaddr,
                        bytes: file_range(b, fileoff, filesize),
                        executable: initprot & 4 != 0,
                    });
                }
                for s in 0..(nsects as usize).min(MAX_SECTIONS) {
                    let entry = at + 72 + s * 80;
                    let (Some(addr), Some(sect_size), Some(offset), Some(flags)) = (
                        u64le(b, entry + 32),
                        u64le(b, entry + 40),
                        u32le(b, entry + 48),
                        u32le(b, entry + 64),
                    ) else {
                        break;
                    };
                    let sect_name = c_string(&b[..(entry + 16).min(b.len())], entry);
                    sections.push(Section {
                        name: format!("{name},{sect_name}"),
                        address: addr,
                        size: sect_size,
                        file_offset: u64::from(offset),
                        executable: flags & 0x8000_0400 != 0,
                    });
                }
            }
            0x8000_0028 => entry_offset = u64le(b, at + 8), // LC_MAIN
            0x02 => {
                // LC_SYMTAB
                let (Some(table), Some(count), Some(strings)) =
                    (u32le(b, at + 8), u32le(b, at + 12), u32le(b, at + 16))
                else {
                    break;
                };
                for i in 0..(count as usize).min(MAX_SYMBOLS) {
                    let entry = table as usize + i * 16;
                    let (Some(name), Some(kind), Some(value)) = (
                        u32le(b, entry),
                        b.get(entry + 4).copied(),
                        u64le(b, entry + 8),
                    ) else {
                        break;
                    };
                    // N_SECT with no debugging bits means a symbol defined in a section.
                    if kind & 0xE0 == 0 && kind & 0x0E == 0x0E && value != 0 {
                        symbols.push(Symbol {
                            name: c_string(b, strings as usize + name as usize),
                            address: value,
                            size: 0,
                        });
                    }
                }
            }
            _ => {}
        }
        at = at.checked_add(size).ok_or(TRUNCATED)?;
    }
    let entry = match (entry_offset, text_base) {
        (Some(offset), Some(base)) => Some(base.wrapping_add(offset)),
        _ => None,
    };
    Ok(Image {
        format: "Mach-O 64",
        architecture,
        entry,
        segments,
        sections,
        symbols,
        notes: Vec::new(),
    })
}

/// A universal binary holds one slice per architecture. This picks the 64-bit Arm slice if present,
/// or else the first 64-bit one.
pub fn parse_fat_macho(b: &[u8]) -> Result<Image, InspectError> {
    let be32 = |at: usize| -> Option<u32> {
        let s = b.get(at..at.checked_add(4)?)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    };
    let count = be32(4).ok_or(TRUNCATED)? as usize;
    if count == 0 || count > 32 {
        return Err(InspectError::Malformed(
            "a universal binary has an invalid slice count",
        ));
    }
    let mut chosen = None;
    for i in 0..count {
        let at = 8 + i * 20;
        let (Some(cpu), Some(offset), Some(size)) = (be32(at), be32(at + 8), be32(at + 12)) else {
            return Err(TRUNCATED);
        };
        let slice = (offset as usize, size as usize);
        if cpu == 0x0100_000C {
            chosen = Some(slice);
            break;
        }
        if cpu & 0x0100_0000 != 0 && chosen.is_none() {
            chosen = Some(slice);
        }
    }
    let (offset, size) = chosen.ok_or(InspectError::Unsupported(
        "universal binaries with no 64-bit slice".into(),
    ))?;
    let end = offset.checked_add(size).ok_or(TRUNCATED)?;
    let slice = b.get(offset..end).ok_or(TRUNCATED)?;
    if u32le(slice, 0) != Some(0xFEED_FACF) {
        return Err(InspectError::Malformed(
            "a universal binary slice is not a 64-bit Mach-O",
        ));
    }
    let mut image = parse_macho(slice)?;
    image.format = "Mach-O universal";
    Ok(image)
}
