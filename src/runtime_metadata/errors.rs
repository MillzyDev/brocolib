use std::io;
use thiserror::Error;

#[cfg(feature = "elf")]
use bad64::DecodeError;

pub type Result<T> = std::result::Result<T, Il2CppBinaryError>;

#[derive(Error, Debug, Clone, Copy)]
#[error("error disassembling code")]
pub struct DisassembleError;

#[derive(Error, Debug)]
pub enum Il2CppBinaryError {
    #[cfg(feature = "elf")]
    #[error("error disassembling code")]
    Disassemble(DecodeError),

    #[error("failed to convert virtual address {0:#016x}")]
    VAddrConv(u64),

    #[error("could not find il2cpp_init symbol in elf")]
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
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Elf(#[from] object::Error),
}