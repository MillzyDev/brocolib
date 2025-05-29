//! ELF runtime metadata parsing.
//!
//! For IL2CPP Unity games that are built for linux or linux-based platforms,
//! you will find a shared object file named `libil2cpp.so`. This file contains
//! the libil2cpp library, code generated from C#, as well as certain metadata
//! information.
//!
//! To read metadata information from `libil2cpp.so`, see
//! [`RuntimeMetadata::read()`] and [`RuntimeMetadata::read_coff()`].

use std::any::Any;
use super::*;
use crate::global_metadata::{GenericParameterIndex, GlobalMetadata, TypeDefinitionIndex};
//use bad64::{disasm, DecodeError, Imm, Instruction, Op, Operand, Reg};

use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use object::read::coff::CoffFile;
use object::{Endianness, File, Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable, RelocationEncoding, RelocationTarget};
use std::collections::HashMap;
use std::io::{self, Cursor, Seek, SeekFrom};
use std::str;
use capstone::{arch, Capstone, InsnId};
use capstone::arch::{ArchOperand, BuildsCapstone, BuildsCapstoneSyntax, DetailsArchInsn};
use capstone::arch::x86::{X86OpMem, X86Operand, X86OperandType};
use iced_x86::{ConstantOffsets, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use object::read::elf::ElfFile;
use thiserror::Error;

pub type Coff<'data> = CoffFile<'data>;
pub type Elf<'data> = ElfFile<'data, Endianness>;

#[derive(Error, Debug, Clone, Copy)]
#[error("error disassembling code")]
pub struct DisassembleError;

#[derive(Error, Debug)]
pub enum Il2CppBinaryError {
    #[error("error disassembling code")]
    Disassemble(DisassembleError),

    #[error("failed to convert virtual address {0:#016x}")]
    VAddrConv(u64),

    #[error("could not find il2cpp_init symbol in coff")]
    MissingIl2CppInit,

    #[error("could not find indirect branch in Runtime::Init")]
    MissingBlr,

    #[error("could not find registration function")]
    MissingRegistration,

    #[error("invalid Il2CppType with type {0}")]
    InvalidType(u8),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    BinaryDeserialize(#[from] binread::Error),

    #[error(transparent)]
    Utf8(#[from] str::Utf8Error),

    #[error(transparent)]
    Elf(#[from] object::Error),
}

type Result<T> = std::result::Result<T, Il2CppBinaryError>;

pub fn strlen(data: &[u8], offset: usize) -> usize {
    let mut len = 0;
    while data[offset + len] != 0 {
        len += 1;
    }
    len
}

pub fn get_str(data: &[u8], offset: usize) -> Result<&str> {
    let len = strlen(data, offset);
    let str = str::from_utf8(&data[offset..offset + len])?;
    Ok(str)
}

pub fn addr_in_bss(coff: &File, vaddr: u64) -> bool {
    match coff.section_by_name(".bss") {
        Some(bss) => bss.address() <= vaddr && vaddr - bss.address() < bss.size(),
        None => false,
    }
}

/// Converts a virtual address in the elf to a file offset
pub fn vaddr_conv(coff: &File, vaddr: u64) -> Result<u64> {
    for segment in coff.segments() {
        if segment.address() <= vaddr {
            let offset = vaddr - segment.address();
            if offset < segment.size() {
                // println!("{:08x} -> {:08x}", vaddr, segment.file_range().0 + offset);
                return Ok(segment.file_range().0 + offset);
            }
        }
    }
    Err(Il2CppBinaryError::VAddrConv(vaddr))
}

fn try_disassemble(code: &[u8], addr: u64) -> Result<Vec<Instruction>> {
    let mut decoder = Decoder::with_ip(64, code, addr, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }
    Ok(instructions)
}

fn nth_lea<'data>(coff: &File, data: &'data [u8], addr: u64, n: usize) -> Result<u64> {
    let offset = vaddr_conv(coff, addr)?;

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

fn nth_call<'data>(coff: &File, data: &'data [u8], addr: u64, n: usize) -> Result<u64> {
    let offset = vaddr_conv(coff, addr)?;

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("failed to create Capstone object");

    let code = &data[offset as usize..];
    let insns = cs.disasm_count(&code, addr, 4096).expect("Failed to disassemble");

    //println!("Found {} instructions", insns.len());

    let mut count = 0;

    for i in insns.iter() {
        //println!("{}", i);

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

                        println!("Addr:    {:x}    Len: {}    Disp: {:x}", i.address(), i.len(), mem.disp());
                        println!("Calculated Target: {:x}", i.address() + (i.len() as u64) + ( mem.disp() as u64));

                        return Ok(i.address() + (i.len() as u64) + ( mem.disp() as u64))
                    }
                    _ => { break; }
                }
            }
        }
    }

    unreachable!()
}

fn nth_mov<'data>(coff: &File, data: &'data [u8], addr: u64, n: usize) -> Result<u64> {
    let offset = vaddr_conv(coff, addr)?;

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("failed to create Capstone object");

    let code = &data[offset as usize..];
    let insns = cs.disasm_all(&code, addr).expect("Failed to disassemble");

    println!("Found {} instructions", insns.len());

    let mut count = 0;

    for i in insns.iter() {

        if cs.insn_name(i.id()).expect("Failed to get insn name") == "mov" {
            count += 1;
            println!("{}", i);
            println!("Found {} of {}", count, n);
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

                        return Ok(i.address() + (i.len() as u64) + ( mem.disp() as u64))
                    }
                    _ => { break; }
                }
            }
        }
    }

    unreachable!()
}

fn process_relocations<'data>(coff: &File, data: &'data [u8]) -> Result<Vec<u8>> {
    let mut coff_rel = data.to_vec();

    if let Some(relocations) = coff.dynamic_relocations() {
        for (addr, rel) in relocations {
            if rel.encoding() != RelocationEncoding::Generic || rel.target() != RelocationTarget::Absolute {
                // TODO: handle more relocation types
                continue;
            }

            let target = rel.addend() as u64;

            let mut cur = Cursor::new(&mut coff_rel);
            cur.set_position(vaddr_conv(coff, addr)?);
            cur.write_u64::<LittleEndian>(target)?;
        }
    }

    Ok(coff_rel)
}

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
fn find_registration<'data>(coff: &File, data: &'data [u8]) -> Result<(u64, u64)> {
    let il2cpp_init = coff
        .exports()?
        .iter().find(|s| str::from_utf8(s.name()) == Ok("il2cpp_init"))
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?
        .address();

    let runtime_init = nth_call(coff, &data, il2cpp_init, 2)?;
    let registration_function_ptr = nth_call(coff, &data, runtime_init, 15)?;

    let registration_function_ptr_offset = vaddr_conv(coff, registration_function_ptr)?;

    let mut buf: [u8; 8] = [0x0; 8];
    buf[0..].copy_from_slice(&data[registration_function_ptr_offset as usize..][..8]);
    let registration_function = u64::from_le_bytes(buf);
    println!("Found registration function: {:x}", registration_function);

    let metadata_registration = nth_lea(coff, &data, registration_function, 2).expect("Failed to get metadata registration");
    //let metadata_registration = vaddr_conv(coff, metadata_registration)?;
    let code_registration = nth_lea(coff, &data, registration_function, 3).expect("Failed to get code registration");
    //let code_registration = vaddr_conv(coff, code_registration)?;

    Ok((code_registration, metadata_registration))
}

struct CoffReader<'coff, 'data> {
    elf: &'coff File<'data>,
    elf_rel: &'data [u8],
}

impl<'coff, 'data> CoffReader<'coff, 'data> {
    fn new(elf: &'coff File<'data>, elf_rel: &'data [u8]) -> Self {
        Self { elf, elf_rel }
    }

    fn make_cur(&self, vaddr: u64) -> Result<Cursor<&[u8]>> {
        let pos = vaddr_conv(self.elf, vaddr)?;
        let mut cur = Cursor::new(self.elf_rel);
        cur.set_position(pos);
        Ok(cur)
    }

    fn get_str(&self, vaddr: u64) -> Result<&'data str> {
        let ptr = vaddr_conv(self.elf, vaddr)?;
        get_str(self.elf_rel, ptr as usize)
    }
}

fn read_arr<T>(reader: &CoffReader, vaddr: u64, len: usize) -> Result<Vec<T>>
where
    T: BinRead,
{
    if len == 0 {
        return Ok(Vec::new())
    }
    let mut cur = reader.make_cur(vaddr)?;
    let mut vec = Vec::with_capacity(len);
    for _ in 0..len {
        let value = cur.read_le()?;
        vec.push(value);
    }
    Ok(vec)
}

fn read_len_arr<T>(reader: &CoffReader, cur: &mut Cursor<&[u8]>) -> Result<Vec<T>>
where
    T: BinRead,
{
    let count = cur.read_u32::<LittleEndian>()? as usize;
    if count == 0 {
        cur.seek(SeekFrom::Current(12))?;
        return Ok(Vec::new());
    }
    let _padding = cur.read_u32::<LittleEndian>()?;
    let addr = cur.read_u64::<LittleEndian>()?;
    read_arr(reader, addr, count)
}

fn read_len_arr_nullable<T>(reader: &CoffReader, cur: &mut Cursor<&[u8]>) -> Result<Vec<T>>
where
    T: BinRead + Default + Clone,
{
    let count = cur.read_u32::<LittleEndian>()? as usize;
    if count == 0 {
        cur.seek(SeekFrom::Current(12))?;
        return Ok(Vec::new());
    }
    let _padding = cur.read_u32::<LittleEndian>()?;
    let addr = cur.read_u64::<LittleEndian>()?;
    if addr_in_bss(reader.elf, addr) {
        Ok(vec![Default::default(); count])
    } else {
        read_arr(reader, addr, count)
    }
}

impl<'data> Il2CppCodeGenModule<'data> {
    fn read<'elf>(reader: &CoffReader<'elf, 'data>, vaddr: u64) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let name = reader.get_str(cur.read_u64::<LittleEndian>()?)?;

        let method_pointers = read_len_arr_nullable(reader, &mut cur)?;
        let adjustor_thunks = read_len_arr(reader, &mut cur)?;

        let addr = cur.read_u64::<LittleEndian>()?;
        let invoker_indices = read_arr(reader, addr, method_pointers.len())?;

        // reverse_pinvoke_wrapper_indices
        let _todo = cur.read_u128::<LittleEndian>()?;

        let rgctx_ranges = read_len_arr(reader, &mut cur)?;
        let rgctxs = read_len_arr(reader, &mut cur)?;
        Ok(Self {
            name,
            method_pointers,
            adjustor_thunks,
            invoker_indices,
            rgctx_ranges,
            rgctxs,
        })
    }
}

impl<'data> Il2CppCodeRegistration<'data> {
    fn read(coff: &File<'data>, data: &'data [u8], addr: u64) -> Result<Self> {
        let reader = CoffReader::new(coff, data);
        let mut cur = reader.make_cur(addr)?;

        let reverse_pinvoke_wrappers = read_len_arr(&reader, &mut cur)?;

        let generic_method_pointers = read_len_arr(&reader, &mut cur)?;
        let addr = cur.read_u64::<LittleEndian>()?;
        let generic_adjustor_thunks = read_arr(&reader, addr, generic_method_pointers.len())?;

        let invoker_pointers = read_len_arr(&reader, &mut cur)?;
        // unresolvedIndirectCallCount
        // unresolvedVirtualCallPointers
        let unresolved_virtual_call_pointers: Vec<u64> = read_len_arr(&reader, &mut cur)?;
        let _unresolved_instance_call_pointers = cur.read_u64::<LittleEndian>()?;
        let _unresolved_static_call_pointers = cur.read_u64::<LittleEndian>()?;

        // interopDataCount
        // interopData
        let _interop_data: Vec<u64> = read_len_arr(&reader, &mut cur)?;

        // windowsRuntimeFactoryCount
        // windowsRuntimeFactoryTable
        let _windows_runtime_factory_table: Vec<u64> = read_len_arr_nullable(&reader, &mut cur)?;

        let module_addrs = read_len_arr(&reader, &mut cur)?;
        let mut code_gen_modules = Vec::with_capacity(module_addrs.len());
        for addr in module_addrs {
            code_gen_modules.push(Il2CppCodeGenModule::read(&reader, addr)?);
        }

        Ok(Self {
            reverse_pinvoke_wrappers,
            generic_method_pointers,
            generic_adjustor_thunks,
            invoker_pointers,
            unresolved_indirect_call_pointers: unresolved_virtual_call_pointers,
            code_gen_modules,
        })
    }
}

impl Il2CppType {
    fn read(
        reader: &CoffReader,
        vaddr: u64,
        type_map: &HashMap<u64, usize>,
        generic_class_map: &HashMap<u64, usize>,
        array_types: &mut Vec<Il2CppArrayType>,
        array_type_map: &mut HashMap<u64, usize>,
    ) -> Result<Il2CppType> {
        let mut cur = reader.make_cur(vaddr)?;

        let raw_data = cur.read_u64::<LittleEndian>()?;
        let attrs = cur.read_u16::<LittleEndian>()?;
        let ty_id = cur.read_u8()?;
        let ty = Il2CppTypeEnum::from_ty(ty_id).ok_or(Il2CppBinaryError::InvalidType(ty_id))?;
        let bitfield = cur.read_u8()?;

        let data = match ty {
            Il2CppTypeEnum::Var | Il2CppTypeEnum::Mvar => TypeData::GenericParameterIndex(GenericParameterIndex::new(raw_data as u32)),
            Il2CppTypeEnum::Ptr | Il2CppTypeEnum::Szarray => TypeData::TypeIndex(type_map[&raw_data]),
            Il2CppTypeEnum::Array => TypeData::ArrayType({
                match array_type_map.get(&raw_data) {
                    Some(idx) => *idx,
                    None => {
                        let idx = array_types.len();
                        array_types.push(Il2CppArrayType::read(reader, raw_data, type_map)?);
                        array_type_map.insert(raw_data, idx);
                        idx
                    }
                }
            }),
            Il2CppTypeEnum::Genericinst => TypeData::GenericClassIndex(generic_class_map[&raw_data]),
            _ => TypeData::TypeDefinitionIndex(TypeDefinitionIndex::new(raw_data as u32)),
        };
        let byref = (bitfield >> 5) != 0;
        let pinned = (bitfield >> 6) != 0;
        let valuetype = (bitfield >> 7) != 0;

        Ok(Il2CppType {
            data,
            attrs,
            ty,
            byref,
            pinned,
            valuetype,
        })
    }
}

impl Il2CppGenericClass {
    fn read(
        reader: &CoffReader,
        vaddr: u64,
        generic_inst_map: &HashMap<u64, usize>,
        type_map: &HashMap<u64, usize>,
    ) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let type_ptr = cur.read_u64::<LittleEndian>()?;
        let type_index = type_map[&type_ptr];

        let context = Il2CppGenericContext::read(&mut cur, generic_inst_map)?;
        Ok(Self {
            type_index,
            context,
        })
    }
}

impl Il2CppGenericContext {
    fn read(cur: &mut Cursor<&[u8]>, generic_inst_map: &HashMap<u64, usize>) -> Result<Self> {
        Ok(Self {
            class_inst_idx: generic_inst_map
                .get(&cur.read_u64::<LittleEndian>()?)
                .copied(),
            method_inst_idx: generic_inst_map
                .get(&cur.read_u64::<LittleEndian>()?)
                .copied(),
        })
    }
}

impl Il2CppGenericInst {
    fn read(reader: &CoffReader, vaddr: u64, types_map: &HashMap<u64, usize>) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let type_ptrs = read_len_arr(reader, &mut cur)?;
        let mut types = Vec::with_capacity(type_ptrs.len());
        for addr in type_ptrs {
            types.push(types_map[&addr]);
        }
        Ok(Self { types })
    }
}

impl Il2CppArrayType {
    fn read(reader: &CoffReader, vaddr: u64, types_map: &HashMap<u64, usize>) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let elem_ty_ptr = cur.read_u64::<LittleEndian>()?;
        let elem_ty = types_map[&elem_ty_ptr];

        let rank = cur.read_u8()?;
        let num_sizes = cur.read_u8()?;
        let num_lobounds = cur.read_u8()?;

        let _padding = cur.read_u32::<LittleEndian>()?;
        let _padding = cur.read_u8()?;

        let sizes_ptr = cur.read_u64::<LittleEndian>()?;
        let sizes = read_arr(reader, sizes_ptr, num_sizes as usize)?;

        let lobounds_ptr = cur.read_u64::<LittleEndian>()?;
        let lower_bounds = read_arr(reader, lobounds_ptr, num_lobounds as usize)?;

        Ok(Self { elem_ty, rank, sizes, lower_bounds })
    }
}

impl Il2CppMetadataRegistration {
    fn read(coff: &File, data: &[u8], addr: u64, metadata: &GlobalMetadata) -> Result<Self> {
        let reader = CoffReader::new(coff, data);
        let mut cur = reader.make_cur(addr)?;

        let generic_class_addrs = read_len_arr(&reader, &mut cur)?;
        let generic_inst_addrs = read_len_arr(&reader, &mut cur)?;
        let generic_method_table = read_len_arr(&reader, &mut cur)?;
        let type_addrs = read_len_arr(&reader, &mut cur)?;
        let method_specs = read_len_arr(&reader, &mut cur)?;
        let field_offset_ptrs = read_len_arr(&reader, &mut cur)?;
        let type_definition_sizes_ptrs = read_len_arr(&reader, &mut cur)?;

        let mut generic_inst_map = HashMap::new();
        for (i, &addr) in generic_inst_addrs.iter().enumerate() {
            generic_inst_map.insert(addr, i);
        }

        let mut type_map = HashMap::new();
        for (i, &addr) in type_addrs.iter().enumerate() {
            type_map.insert(addr, i);
        }

        let mut generic_classes = Vec::with_capacity(type_addrs.len());
        let mut generic_class_map = HashMap::new();
        for (i, addr) in generic_class_addrs.into_iter().enumerate() {
            generic_classes.push(Il2CppGenericClass::read(&reader, addr, &generic_inst_map, &type_map)?);
            generic_class_map.insert(addr, i);
        }

        let mut types = Vec::with_capacity(type_addrs.len());
        let mut array_types = Vec::new();
        let mut array_type_map = HashMap::new();
        for addr in type_addrs {
            types.push(Il2CppType::read(&reader, addr, &type_map, &generic_class_map, &mut array_types, &mut array_type_map)?);
        }

        let mut generic_insts = Vec::with_capacity(generic_inst_addrs.len());
        for addr in generic_inst_addrs {
            generic_insts.push(Il2CppGenericInst::read(&reader, addr, &type_map)?);
        }

        let mut type_definition_sizes = Vec::with_capacity(type_definition_sizes_ptrs.len());
        for addr in type_definition_sizes_ptrs {
            let mut cur = reader.make_cur(addr)?;
            type_definition_sizes.push(cur.read_le()?);
        }

        let mut field_offsets = Vec::with_capacity(field_offset_ptrs.len());
        for (i, addr) in field_offset_ptrs.into_iter().enumerate() {
            if addr == 0 {
                field_offsets.push(Vec::new());
                continue;
            }
            let mut cur = reader.make_cur(addr)?;

            let type_def_idx = TypeDefinitionIndex::new(i as u32);
            let arr_len = metadata.type_definitions[type_def_idx].field_count as usize;
            let mut arr = Vec::with_capacity(arr_len);
            for _ in 0..arr_len {
                arr.push(cur.read_u32::<LittleEndian>()?);
            }
            field_offsets.push(arr);
        }

        Ok(Il2CppMetadataRegistration {
            generic_classes,
            generic_insts,
            generic_method_table,
            types,
            array_types,
            method_specs,
            field_offsets: Some(field_offsets),
            type_definition_sizes: Some(type_definition_sizes),
        })
    }
}

impl<'data> RuntimeMetadata<'data> {
    /// Read runtime metadata information from an [`Elf`].
    pub fn read(coff: &File<'data>, data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let (cr_addr, mr_addr) = find_registration(coff, &data)?;

        println!("CR: {:x} MR: {:x}", cr_addr, mr_addr);

        let code_registration = Il2CppCodeRegistration::read(coff, &data, cr_addr)?;
        let metadata_registration = Il2CppMetadataRegistration::read(coff, &data, mr_addr, global_metadata)?;

        Ok(RuntimeMetadata {
            code_registration,
            metadata_registration,
        })
    }

    /// Read runtime metadata information from raw ELF data.
    pub fn read_coff(coff_data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let object = File::parse(coff_data)?;
        Self::read(&object, coff_data, global_metadata)
    }
}