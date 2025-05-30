pub mod source;
pub mod elf;
pub mod pe;
pub mod errors;

use std::collections::HashMap;
use std::io::{Cursor, Seek, SeekFrom};
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt};
use object::{File, Object, ObjectSection, ObjectSegment};
use crate::global_metadata::{Token, TypeDefinitionIndex, GenericParameterIndex, MethodIndex, GlobalMetadata};
use crate::Metadata;
use crate::runtime_metadata::errors::Il2CppBinaryError;

/// Defined at `il2cpp-class-internals:570`
#[derive(BinRead, Debug)]
pub struct Il2CppTokenAdjustorThunkPair {
    pub token: Token,
    #[br(align_before = 8)]
    pub adjustor_thunk: u64,
}

/// Defined at `il2cpp-class-internals:550`
#[derive(BinRead, Debug)]
pub struct Il2CppRange {
    pub start: u32,
    pub length: u32,
}

/// Defined at `il2cpp-class-internals:556`
#[derive(BinRead, Debug)]
pub struct Il2CppTokenRangePair {
    pub token: Token,
    pub range: Il2CppRange,
}

/// Defined at `il2cpp-metadata.h:69`
#[derive(BinRead, Debug)]
#[br(repr = u64)]
pub enum Il2CppRGCTXDataType {
    Invalid,
    Type,
    Class,
    Method,
    Array,
    Constrained,
}

/// A runtime generic context.
/// 
/// Defined at `il2cpp-metadata.h:92`
#[derive(BinRead, Debug)]
pub struct Il2CppRGCTXDefinition {
    pub ty: Il2CppRGCTXDataType,
    // TODO
    pub data: u64,
}

/// Defined at `il2cpp-runtime-metadata.h:11`
#[derive(Debug)]
pub struct Il2CppArrayType {
    pub elem_ty: usize,
    pub rank: u8,
    pub sizes: Vec<u32>,
    pub lower_bounds: Vec<u32>,
}

/// Defined at `il2cpp-class-internals:582`
#[derive(Debug)]
pub struct Il2CppCodeGenModule<'data> {
    /// Module names have `.dll` at the end
    pub name: &'data str,
    pub method_pointers: Vec<u64>,
    pub adjustor_thunks: Vec<Il2CppTokenAdjustorThunkPair>,
    pub invoker_indices: Vec<u32>,

    // TODO:
    // reverse_pinvoke_wrapper_indices: Vec<TokenIndexMethodTuple>,

    pub rgctx_ranges: Vec<Il2CppTokenRangePair>,
    pub rgctxs: Vec<Il2CppRGCTXDefinition>,

    // TODO:
    // debugger_metadata: Il2CppDebuggerMetadataRegistration,
    // module_initializer: Il2CppMethodPointer,
    // static_constructor_type_indices: Vec<TypeDefinitionIndex>,
    // /// Per-assembly mode only
    // metadata_registration: Option<Il2CppMetadataRegistration>,
    // /// Per-assembly mode only
    // code_registration: Option<Il2CppCodeRegistration>,
}

/// Defined at `il2cpp-class-internals:603`
#[derive(Debug)]
pub struct Il2CppCodeRegistration<'data> {
    pub reverse_pinvoke_wrappers: Vec<u64>,
    pub generic_method_pointers: Vec<u64>,
    pub generic_adjustor_thunks: Vec<u64>,
    pub invoker_pointers: Vec<u64>,
    pub unresolved_indirect_call_pointers: Vec<u64>,

    // TODO
    // pub interop_data: Vec<InteropData>,
    // pub windows_runtime_factory_table: Vec<WindowsRuntimeFactoryTableEntry>,
    pub code_gen_modules: Vec<Il2CppCodeGenModule<'data>>,
}

/// Corresponds to element type signatures.
/// See ECMA-335, II.23.1.16
/// 
/// Defined at `il2cpp-blob.h:6`
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Il2CppTypeEnum {
    /// End of list
    End,
    /// System.Void (void)
    Void,
    /// System.Boolean (bool)
    Boolean,
    /// System.Char (char)
    Char,
    /// System.SByte (sbyte)
    I1,
    /// System.Byte (byte)
    U1,
    /// System.Int16 (short)
    I2,
    /// System.UInt16 (ushort)
    U2,
    /// System.Int32 (int)
    I4,
    /// System.UInt32 (uint)
    U4,
    /// System.Int64 (long)
    I8,
    /// System.UInt64 (ulong)
    U8,
    /// System.Single (float)
    R4,
    /// System.Double (double)
    R8,
    /// System.String (string)
    String,
    Ptr,
    Byref,
    Valuetype,
    Class,
    /// Class generic parameter
    Var,
    Array,
    Genericinst,
    /// System.TypedReference
    Typedbyref,
    /// System.IntPtr
    I,
    /// System.UIntPtr
    U,
    Fnptr,
    /// System.Object (object)
    Object,
    /// Single-dimensioned zero-based array type
    Szarray,
    /// Method generic parameter
    Mvar,
    /// Required modifier
    CmodReqd,
    /// Optional modifier
    CmodOpt,
    Internal,
    Modifier,
    /// Sentinel for vararg method signature
    Sentinel,
    /// Denotes a local variable points to a pinned object
    Pinned,
    /// Used in custom attributes to specify an enum
    Enum
}

impl Il2CppTypeEnum {
    fn from_ty(ty: u8) -> Option<Self> {
        Some(match ty {
            0x00 => Il2CppTypeEnum::End,
            0x01 => Il2CppTypeEnum::Void,
            0x02 => Il2CppTypeEnum::Boolean,
            0x03 => Il2CppTypeEnum::Char,
            0x04 => Il2CppTypeEnum::I1,
            0x05 => Il2CppTypeEnum::U1,
            0x06 => Il2CppTypeEnum::I2,
            0x07 => Il2CppTypeEnum::U2,
            0x08 => Il2CppTypeEnum::I4,
            0x09 => Il2CppTypeEnum::U4,
            0x0a => Il2CppTypeEnum::I8,
            0x0b => Il2CppTypeEnum::U8,
            0x0c => Il2CppTypeEnum::R4,
            0x0d => Il2CppTypeEnum::R8,
            0x0e => Il2CppTypeEnum::String,
            0x0f => Il2CppTypeEnum::Ptr,
            0x10 => Il2CppTypeEnum::Byref,
            0x11 => Il2CppTypeEnum::Valuetype,
            0x12 => Il2CppTypeEnum::Class,
            0x13 => Il2CppTypeEnum::Var,
            0x14 => Il2CppTypeEnum::Array,
            0x15 => Il2CppTypeEnum::Genericinst,
            0x16 => Il2CppTypeEnum::Typedbyref,
            0x18 => Il2CppTypeEnum::I,
            0x19 => Il2CppTypeEnum::U,
            0x1b => Il2CppTypeEnum::Fnptr,
            0x1c => Il2CppTypeEnum::Object,
            0x1d => Il2CppTypeEnum::Szarray,
            0x1e => Il2CppTypeEnum::Mvar,
            0x1f => Il2CppTypeEnum::CmodReqd,
            0x20 => Il2CppTypeEnum::CmodOpt,
            0x21 => Il2CppTypeEnum::Internal,
            0x40 => Il2CppTypeEnum::Modifier,
            0x41 => Il2CppTypeEnum::Sentinel,
            0x45 => Il2CppTypeEnum::Pinned,
            0x55 => Il2CppTypeEnum::Enum,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TypeData {
    TypeDefinitionIndex(TypeDefinitionIndex),
    /// For [`Il2CppTypeEnum::Ptr`] and [`Il2CppTypeEnum::Szarray`]
    TypeIndex(usize),
    /// For [`Il2CppTypeEnum::Var`] and [`Il2CppTypeEnum::Mvar`]
    GenericParameterIndex(GenericParameterIndex),
    /// For [`Il2CppTypeEnum::Genericinst`]
    GenericClassIndex(usize),
    /// For [`Il2CppTypeEnum::Array`]
    ArrayType(usize),
}

/// Defined at `il2cpp-runtime-metadata.h:48`
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Il2CppType {
    pub data: TypeData,
    /// Param attributes or field flags. See `il2cpp-tabledef.h`
    pub attrs: u16,
    pub ty: Il2CppTypeEnum,
    pub byref: bool,
    /// valid when included in a local var signature
    pub pinned: bool,
    pub valuetype: bool,
}

impl Il2CppType {
    pub fn full_name(&self, metadata: &Metadata) -> String {
        let mr = &metadata.runtime_metadata.metadata_registration;
        let types = &mr.types;
        let type_defs = &metadata.global_metadata.type_definitions;

        String::from(match self.ty {
            Il2CppTypeEnum::Void => "System.Void",
            Il2CppTypeEnum::Boolean => "System.Boolean",
            Il2CppTypeEnum::Char => "System.Char",
            Il2CppTypeEnum::I1 => "System.SByte",
            Il2CppTypeEnum::U1 => "System.Byte",
            Il2CppTypeEnum::I2 => "System.Int16",
            Il2CppTypeEnum::U2 => "System.UInt16",
            Il2CppTypeEnum::I4 => "System.Int32",
            Il2CppTypeEnum::U4 => "System.UInt32",
            Il2CppTypeEnum::U8 => "System.Int64",
            Il2CppTypeEnum::I8 => "System.UInt64",
            Il2CppTypeEnum::R4 => "System.Float",
            Il2CppTypeEnum::R8 => "System.Double",
            Il2CppTypeEnum::String => "System.String",
            Il2CppTypeEnum::Typedbyref => "System.TypedReference",
            Il2CppTypeEnum::I => "System.IntPtr",
            Il2CppTypeEnum::U => "System.UIntPtr",
            Il2CppTypeEnum::Object => "System.Object",
            Il2CppTypeEnum::Sentinel => "<<SENTINEL>>",
            _ => return match (self.ty, self.data) {
                (Il2CppTypeEnum::Var | Il2CppTypeEnum::Mvar, TypeData::GenericParameterIndex(idx)) => metadata.global_metadata.generic_parameters[idx].name(metadata).to_string(),
                (Il2CppTypeEnum::Ptr, TypeData::TypeIndex(ty_idx)) => format!("{}*", types[ty_idx].full_name(metadata)),
                (Il2CppTypeEnum::Szarray, TypeData::TypeIndex(ty_idx)) => format!("{}[]", types[ty_idx].full_name(metadata)),
                (Il2CppTypeEnum::Array, TypeData::ArrayType(arr_ty_idx)) => {
                    let arr_type = &mr.array_types[arr_ty_idx];
                    let mut str = types[arr_type.elem_ty].full_name(metadata);
                    str.push('[');
                    for _ in 0..arr_type.rank - 1 {
                        str.push(',');
                    }
                    str.push(']');
                    str
                },
                (Il2CppTypeEnum::Class | Il2CppTypeEnum::Valuetype, TypeData::TypeDefinitionIndex(ty_idx)) => type_defs[ty_idx].full_name(metadata, false),
                (Il2CppTypeEnum::Genericinst, TypeData::GenericClassIndex(gc)) => {
                    let gc = &mr.generic_classes[gc];
                    let inst = &mr.generic_insts[gc.context.class_inst_idx.unwrap()];
                    let generic_args = inst.types.iter().map(|ty| types[*ty].full_name(metadata)).collect::<Vec<_>>().join(", ");
                    format!("{}<{}>", types[gc.type_index].full_name(metadata), generic_args)
                }
                _ => format!("({:?}?)", self.ty)
            }
        })
    }
}

/// A generic class instantiation.
///
/// Defined at `il2cpp-runtime-metadata.h:40`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Il2CppGenericClass {
    /// The generic type definition.
    ///
    /// Indices into the [`Il2CppMetadataRegistration::types`] field.
    pub type_index: usize,

    /// A context that contains the type instantiation doesn't contain any method instantiation.
    pub context: Il2CppGenericContext,
}

/// Defined at `il2cpp-runtime-metadata.h:27`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Il2CppGenericContext {
    /// Indices into the [`Il2CppMetadataRegistration::generic_insts`] field
    pub class_inst_idx: Option<usize>,

    /// Indices into the [`Il2CppMetadataRegistration::generic_insts`] field
    pub method_inst_idx: Option<usize>,
}

/// A generic method instantiation.
/// 
/// It is not possible for both `class_inst_index` and `method_inst_index` to
/// be invalid since if both the class and method are not generic, you cannot
/// make a generic instance.
/// 
/// Defined at `il2cpp-metadata.h:67`
#[derive(BinRead, Debug)]
pub struct Il2CppMethodSpec {
    /// The method definition.
    pub method_definition_index: MethodIndex,

    /// The class generic argument list (if class is generic).
    ///
    /// Indices into the [`Il2CppMetadataRegistration::generic_insts`] field
    pub class_inst_index: u32,

    /// The method generic argument list (if method is generic).
    ///
    /// Indices into the [`Il2CppMetadataRegistration::generic_insts`] field
    pub method_inst_index: u32,
}

/// A list of types used for a generic instantiation.
/// 
/// Defined at `il2cpp-runtime-metadata.h:21`
#[derive(Debug)]
pub struct Il2CppGenericInst {
    /// Indices into the [`Il2CppMetadataRegistration::types`] field
    pub types: Vec<usize>,
}

#[derive(BinRead, Debug)]
pub struct GenericMethodIndices {
    /// Index for the [`Il2CppCodeRegistration::generic_method_pointers`] field
    pub method_index: u32,

    /// Index for the [`Il2CppCodeRegistration::invoker_pointers`] field
    pub invoker_index: u32,

    /// Index for the [`Il2CppCodeRegistration::generic_adjustor_thunks`] field (optional)
    pub adjustor_thunk_index: u32,
}

/// Defined at `il2cpp-metadata.h:105`
#[derive(BinRead, Debug)]
pub struct Il2CppGenericMethodFunctionsDefinitions {
    /// Index for [`Il2CppMetadataRegistration::method_specs`]
    pub generic_method_index: u32,
    pub indices: GenericMethodIndices,
}

/// Compiler calculated values
/// 
/// Defined at `il2cpp-class-internals:475`
#[derive(BinRead, Debug)]
pub struct Il2CppTypeDefinitionSizes {
    pub instance_size: u32,
    pub native_size: i32,
    pub static_fields_size: u32,
    pub thread_static_fields_size: u32,
}

/// Defined at `il2cpp-class-internals.h:622`
#[derive(Debug)]
pub struct Il2CppMetadataRegistration {
    pub generic_classes: Vec<Il2CppGenericClass>,
    pub generic_insts: Vec<Il2CppGenericInst>,
    pub generic_method_table: Vec<Il2CppGenericMethodFunctionsDefinitions>,
    pub types: Vec<Il2CppType>,
    /// This is not a real field in the metadata. It is here to provide the
    /// ability to access array types by index instead of by pointer.
    pub array_types: Vec<Il2CppArrayType>,
    pub method_specs: Vec<Il2CppMethodSpec>,
    /// Compiler calculated field offset values. Only exists when read from an
    /// ELF. Since this is platform dependent, it cannot be read from C++
    /// sources.
    pub field_offsets: Option<Vec<Vec<u32>>>,
    /// Compiler calculated size values. Only exists when read from an ELF.
    /// Since this is platform dependent, it cannot be read from C++ sources.
    pub type_definition_sizes: Option<Vec<Il2CppTypeDefinitionSizes>>,
    // TODO:
    // pub metadata_usages: ??
}

#[derive(Debug)]
pub struct RuntimeMetadata<'data> {
    pub code_registration: Il2CppCodeRegistration<'data>,
    pub metadata_registration: Il2CppMetadataRegistration,
}

pub fn strlen(data: &[u8], offset: usize) -> usize {
    let mut len = 0;
    while data[offset + len] != 0 {
        len += 1;
    }
    len
}

pub fn get_str(data: &[u8], offset: usize) -> errors::Result<&str> {
    let len = strlen(data, offset);
    let str = str::from_utf8(&data[offset..offset + len])?;
    Ok(str)
}

pub fn addr_in_bss(object_file: &File, vaddr: u64) -> bool {
    match object_file.section_by_name(".bss") {
        Some(bss) => bss.address() <= vaddr && vaddr - bss.address() < bss.size(),
        None => false,
    }
}

/// Converts a virtual address in the pe to a file offset
pub fn vaddr_conv(object_file: &File, vaddr: u64) -> errors::Result<u64> {
    for segment in object_file.segments() {
        if segment.address() <= vaddr {
            let offset = vaddr - segment.address();
            if offset < segment.size() {
                return Ok(segment.file_range().0 + offset);
            }
        }
    }
    Err(Il2CppBinaryError::VAddrConv(vaddr))
}

struct ObjectReader<'object, 'data> {
    object: &'object File<'data>,
    object_rel: &'data [u8],
}

impl<'object, 'data> ObjectReader<'object, 'data> {
    fn new(object: &'object File<'data>, object_rel: &'data [u8]) -> Self {
        Self { object, object_rel }
    }

    fn make_cur(&self, vaddr: u64) -> errors::Result<Cursor<&[u8]>> {
        let pos = vaddr_conv(self.object, vaddr)?;
        let mut cur = Cursor::new(self.object_rel);
        cur.set_position(pos);
        Ok(cur)
    }

    fn get_str(&self, vaddr: u64) -> errors::Result<&'data str> {
        let ptr = vaddr_conv(self.object, vaddr)?;
        get_str(self.object_rel, ptr as usize)
    }
}

fn read_arr<T>(reader: &ObjectReader, vaddr: u64, len: usize) -> errors::Result<Vec<T>>
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

fn read_len_arr<T>(reader: &ObjectReader, cur: &mut Cursor<&[u8]>) -> errors::Result<Vec<T>>
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

fn read_len_arr_nullable<T>(reader: &ObjectReader, cur: &mut Cursor<&[u8]>) -> errors::Result<Vec<T>>
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
    if addr_in_bss(reader.object, addr) {
        Ok(vec![Default::default(); count])
    } else {
        read_arr(reader, addr, count)
    }
}

impl<'data> Il2CppCodeGenModule<'data> {
    fn read<'elf>(reader: &ObjectReader, vaddr: u64) -> errors::Result<Self> {
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
    fn read(object: &File<'data>, object_rel: &[u8], addr: u64) -> errors::Result<Self> {
        let reader = ObjectReader::new(object, object_rel);
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
        let _windows_runtime_factory_table: Vec<u64> = read_len_arr(&reader, &mut cur)?;

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
        reader: &ObjectReader,
        vaddr: u64,
        type_map: &HashMap<u64, usize>,
        generic_class_map: &HashMap<u64, usize>,
        array_types: &mut Vec<Il2CppArrayType>,
        array_type_map: &mut HashMap<u64, usize>,
    ) -> errors::Result<Il2CppType> {
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
        reader: &ObjectReader,
        vaddr: u64,
        generic_inst_map: &HashMap<u64, usize>,
        type_map: &HashMap<u64, usize>,
    ) -> errors::Result<Self> {
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
    fn read(cur: &mut Cursor<&[u8]>, generic_inst_map: &HashMap<u64, usize>) -> errors::Result<Self> {
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
    fn read(reader: &ObjectReader, vaddr: u64, types_map: &HashMap<u64, usize>) -> errors::Result<Self> {
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
    fn read(reader: &ObjectReader, vaddr: u64, types_map: &HashMap<u64, usize>) -> errors::Result<Self> {
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
    fn read(elf: &File, elf_rel: &[u8], addr: u64, metadata: &GlobalMetadata) -> errors::Result<Self> {
        let reader = ObjectReader::new(elf, elf_rel);
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