//! ELF runtime metadata parsing.
//!
//! For IL2CPP Unity games that are built for linux or linux-based platforms,
//! you will find a shared object file named `libil2cpp.so`. This file contains
//! the libil2cpp library, code generated from C#, as well as certain metadata
//! information.
//!
//! To read metadata information from `libil2cpp.so`, see
//! [`RuntimeMetadata::read()`] and [`RuntimeMetadata::read_elf()`].

use super::*;
use crate::global_metadata::{GenericParameterIndex, GlobalMetadata, TypeDefinitionIndex};
use crate::runtime_metadata::errors::{Il2CppBinaryError, Result};
use bad64::{disasm, Imm, Instruction, Op, Operand, Reg};
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use object::read::elf::ElfFile64;
use object::{Endianness, File, Object, ObjectSection, ObjectSegment, ObjectSymbol, RelocationEncoding, RelocationTarget};
use std::collections::HashMap;
use std::io::Cursor;
use std::str;

fn analyze_reg_rel(elf: &File, elf_rel: &[u8], instructions: &[Instruction]) -> HashMap<Reg, u64> {
    let mut map = HashMap::new();
    for ins in instructions {
        match (ins.op(), ins.operands()) {
            (Op::ADRP, [Operand::Reg { reg, .. }, Operand::Label(Imm::Unsigned(imm))]) => {
                map.insert(*reg, *imm);
            }
            (
                Op::ADD,
                [Operand::Reg { reg: a, .. }, Operand::Reg { reg: b, .. }, Operand::Imm64 {
                    imm: Imm::Unsigned(imm),
                    ..
                }],
            ) => {
                if a != b {
                    continue;
                }
                map.entry(*a).and_modify(|v| *v += imm);
            }
            (
                Op::LDR,
                [Operand::Reg { reg: a, .. }, Operand::MemOffset {
                    reg: b,
                    offset: Imm::Signed(imm),
                    ..
                }],
            ) => {
                if a != b {
                    continue;
                }
                map.entry(*a).and_modify(|v| {
                    // TODO: propogate error
                    let offset = vaddr_conv(elf, (*v as i64 + imm) as u64).unwrap();
                    *v = (&elf_rel[offset as usize..offset as usize + 8])
                        .read_u64::<LittleEndian>()
                        .unwrap();
                });
            }
            _ => {}
        }
    }
    map
}

fn try_disassemble(code: &[u8], addr: u64) -> Result<Vec<Instruction>> {
    disasm(code, addr)
        .map(|res| res.map_err(Il2CppBinaryError::Disassemble))
        .collect()
}

fn nth_bl<'data>(elf: &File, data: &'data [u8],addr: u64, n: usize) -> Result<u64> {
    let offset = vaddr_conv(elf, addr)?;
    let mut count = 0;

    for i in 0.. {
        let offset = offset + i * 4;
        let code = &data[offset as usize..offset as usize + 4];
        let ins = &try_disassemble(code, addr + i * 4)?[0];
        if let (Op::BL, [Operand::Label(Imm::Unsigned(target))]) = (ins.op(), ins.operands()) {
            count += 1;
            if count == n {
                return Ok(*target);
            }
        }
    }

    unreachable!()
}

/// Finds and returns the address of the first `blr` instruction it comes across starting from `addr`.
fn find_blr<'data>(elf: &File, data: &'data [u8], addr: u64, limit: usize) -> Result<Option<(u64, Reg)>> {
    let offset = vaddr_conv(elf, addr)?;
    for i in 0..limit {
        let offset = offset + i as u64 * 4;
        let code = &data[offset as usize..offset as usize + 4];
        let ins = &try_disassemble(code, addr + i as u64 * 4)?[0];
        if let (Op::BLR, [Operand::Reg { reg, .. }]) = (ins.op(), ins.operands()) {
            return Ok(Some((offset, *reg)));
        }
    }
    Ok(None)
}

fn process_relocations<'data>(elf: &File, data: &'data [u8]) -> Result<Vec<u8>> {
    let mut elf_rel = data.to_vec();

    if let Some(relocations) = elf.dynamic_relocations() {
        for (addr, rel) in relocations {
            if rel.encoding() != RelocationEncoding::Generic || rel.target() != RelocationTarget::Absolute {
                // TODO: handle more relocation types
                continue;
            }

            let target = rel.addend() as u64;

            let mut cur = Cursor::new(&mut elf_rel);
            cur.set_position(vaddr_conv(elf, addr)?);
            cur.write_u64::<LittleEndian>(target)?;
        }
    }

    Ok(elf_rel)
}

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
fn find_registration<'data>(elf: &File, data: &'data [u8], elf_rel: &[u8]) -> Result<(u64, u64)> {
    let il2cpp_init = elf
        .dynamic_symbols()
        .find(|s| s.name() == Ok("il2cpp_init"))
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?
        .address();
    let runtime_init = nth_bl(elf, elf_rel, il2cpp_init, 2)?;
    let runtime_init_offset = vaddr_conv(elf, runtime_init)?;

    let (blr_offset, blr_reg) =
        find_blr(elf, elf_rel, runtime_init, 200)?.ok_or(Il2CppBinaryError::MissingBlr)?;

    let instructions = try_disassemble(
        &data[runtime_init_offset as usize..blr_offset as usize],
        runtime_init,
    )?;
    let regs = analyze_reg_rel(elf, &elf_rel, &instructions);

    let fn_addr = vaddr_conv(elf, regs[&blr_reg])?;
    let code = &data[fn_addr as usize..fn_addr as usize + 7 * 4];
    let instructions = try_disassemble(code, regs[&blr_reg])?;
    let regs = analyze_reg_rel(elf, &elf_rel, instructions.as_slice());

    Ok((regs[&Reg::X0], regs[&Reg::X1]))
}

impl<'data> RuntimeMetadata<'data> {
    /// Read runtime metadata information from an [`Elf`].
    pub fn read_elf_runtime(elf: &File<'data>, data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let elf_rel = process_relocations(elf, &data)?;

        let (cr_addr, mr_addr) = find_registration(elf, data, &elf_rel)?;
        let code_registration = Il2CppCodeRegistration::read(elf, &elf_rel, cr_addr)?;
        let metadata_registration = Il2CppMetadataRegistration::read(elf, &elf_rel, mr_addr, global_metadata)?;
        Ok(RuntimeMetadata {
            code_registration,
            metadata_registration,
        })
    }

    /// Read runtime metadata information from raw ELF data.
    pub fn read_elf(data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let object = File::parse(data)?;
        Self::read_elf_runtime(&object, data, global_metadata)
    }
}
