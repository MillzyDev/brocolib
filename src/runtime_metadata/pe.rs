//! PE/pe runtime metadata parsing.
//!
//! For IL2CPP Unity games that are built for windows platforms,
//! you will find a DLL file named `GameAssembly.dll`. This file contains
//! the libil2cpp library, code generated from C#, as well as certain metadata
//! information.
//!
//! To read metadata information from `GameAssembly.dll`, see
//! [`RuntimeMetadata::read()`] and [`RuntimeMetadata::read_pe()`].

use super::*;
use crate::global_metadata::{GenericParameterIndex, GlobalMetadata, TypeDefinitionIndex};
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use capstone::arch::x86::X86OperandType;
use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax, DetailsArchInsn};
use capstone::{arch, Capstone};
use object::{File, Object, ObjectSection, ObjectSegment, ObjectSymbol, RelocationEncoding, RelocationTarget};
use std::collections::HashMap;
use std::io::{self, Cursor, Seek, SeekFrom};
use std::str;
use thiserror::Error;
use crate::runtime_metadata::errors::{Il2CppBinaryError, Result};

fn nth_lea<'data>(pe: &File, data: &'data [u8], addr: u64, n: usize) -> Result<u64> {
    let offset = vaddr_conv(pe, addr)?;

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("failed to create Capstone object");

    let code = &data[offset as usize..];
    let insns = cs.disasm_all(code, addr).expect("Failed to disassemble");

    let mut count = 0;

    for i in insns.as_ref() {
        if cs.insn_name(i.id()).expect("Failed to get insn name") == "lea" {
            count += 1;
        }

        if count == n {
            println!("{}", i);

            let detail = cs.insn_detail(&i).expect("failed to get detail");
            let arch_detail = detail.arch_detail();
            let x86_detail = arch_detail.x86().expect("failed to get x86 arch detail");
            let ops = x86_detail.operands();

            for op in ops {
                match op.op_type {
                    X86OperandType::Mem(mem) => {
                        if cs.reg_name(mem.base()).expect("Failed to get reg name") != "rip" {
                            break;
                        }

                        return Ok(i.address() + (i.len() as u64) + ( mem.disp() as u64))
                    }
                    _ => { break; }
                }
            }
        }
    }

    unreachable!()
}

fn nth_call<'data>(pe: &File, data: &'data [u8], addr: u64, n: usize) -> Result<u64> {
    let offset = vaddr_conv(pe, addr)?;

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("failed to create Capstone object");

    let code = &data[offset as usize..];
    let insns = cs.disasm_count(&code, addr, 4096).expect("Failed to disassemble");

    let mut count = 0;

    for i in insns.iter() {
        if cs.insn_name(i.id()).expect("Failed to get insn name") == "call" {
            count += 1;
        }

        if count == n {
            println!("{}", i);

            let detail = cs.insn_detail(&i).expect("failed to get detail");
            let arch_detail = detail.arch_detail();
            let x86_detail = arch_detail.x86().expect("failed to get x86 arch detail");
            let ops = x86_detail.operands();

            for op in ops {
                match op.op_type {
                    X86OperandType::Imm(immediate) => {
                        return Ok(immediate as u64)
                    }
                    X86OperandType::Mem(mem) => {
                        if cs.reg_name(mem.base()).expect("Failed to get reg name") != "rip" {
                            break;
                        }

                        return Ok(i.address() + (i.len() as u64) + ( mem.disp() as u64))
                    }
                    _ => { break; }
                }
            }
        }
    }

    unreachable!()
}

fn nth_mov<'data>(pe: &File, data: &'data [u8], addr: u64, n: usize) -> Result<u64> {
    let offset = vaddr_conv(pe, addr)?;

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("failed to create Capstone object");

    let code = &data[offset as usize..];
    let insns = cs.disasm_all(&code, addr).expect("Failed to disassemble");

    let mut count = 0;

    for i in insns.iter() {
        if cs.insn_name(i.id()).expect("Failed to get insn name") == "mov" {
            count += 1;
        }

        if count == n {
            let detail = cs.insn_detail(&i).expect("failed to get detail");
            let arch_detail = detail.arch_detail();
            let x86_detail = arch_detail.x86().expect("failed to get x86 arch detail");
            let ops = x86_detail.operands();

            for op in ops {
                match op.op_type {
                    X86OperandType::Imm(immediate) => return Ok(immediate as u64),
                    X86OperandType::Mem(mem) => {
                        if cs.reg_name(mem.base()).expect("Failed to get reg name") != "rip" {
                            break;
                        }

                        return Ok(i.address() + (i.len() as u64) + (mem.disp() as u64))
                    }
                    _ => { break; }
                }
            }
        }
    }

    unreachable!()
}

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
fn find_registration<'data>(pe: &File, data: &'data [u8]) -> Result<(u64, u64)> {
    let il2cpp_init = pe
        .exports()?
        .iter().find(|s| str::from_utf8(s.name()) == Ok("il2cpp_init"))
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?
        .address();

    let runtime_init = nth_call(pe, &data, il2cpp_init, 2)?;
    let registration_function_ptr = nth_call(pe, &data, runtime_init, 15)?;

    let registration_function_ptr_offset = vaddr_conv(pe, registration_function_ptr)?;

    let mut buf: [u8; 8] = [0x0; 8];
    buf[0..].copy_from_slice(&data[registration_function_ptr_offset as usize..][..8]);
    let registration_function = u64::from_le_bytes(buf);

    let metadata_registration = nth_lea(pe, &data, registration_function, 2).expect("Failed to get metadata registration");
    let code_registration = nth_lea(pe, &data, registration_function, 3).expect("Failed to get code registration");

    Ok((code_registration, metadata_registration))
}

impl<'data> RuntimeMetadata<'data> {
    /// Read runtime metadata information from an [`pe`].
    pub fn read_pe_runtime(pe: &File<'data>, data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let (cr_addr, mr_addr) = find_registration(pe, &data)?;

        let code_registration = Il2CppCodeRegistration::read(pe, &data, cr_addr)?;
        let metadata_registration = Il2CppMetadataRegistration::read(pe, &data, mr_addr, global_metadata)?;

        Ok(RuntimeMetadata {
            code_registration,
            metadata_registration,
        })
    }

    /// Read runtime metadata information from raw pe data.
    pub fn read_pe(data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let object = File::parse(data)?;
        Self::read_pe_runtime(&object, data, global_metadata)
    }
}