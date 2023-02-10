pub(crate) mod engine;
mod exports;
pub(crate) mod extern_ref;
pub(crate) mod externals;
mod imports;
mod instance;
pub(crate) mod module;
mod native;
mod ptr;
mod tunables;
mod value;

pub use crate::sys::exports::{ExportError, Exportable, Exports, ExportsIterator};
pub use crate::sys::externals::{
    Extern, FromToNativeWasmType, Function, Global, HostFunction, Memory, MemoryView, Table,
    WasmTypeList,
};
pub use crate::sys::imports::Imports;
pub use crate::sys::instance::{Instance, InstantiationError};
pub use crate::sys::native::TypedFunction;

pub use crate::sys::ptr::{Memory32, Memory64, MemorySize, WasmPtr, WasmPtr64};
pub use crate::sys::tunables::BaseTunables;
pub use crate::sys::value::Value;
pub use target_lexicon::{Architecture, CallingConvention, OperatingSystem, Triple, HOST};
#[cfg(feature = "compiler")]
pub use wasmer_compiler::{
    wasmparser, CompilerConfig, FunctionMiddleware, MiddlewareReaderState, ModuleMiddleware,
};
pub use wasmer_compiler::{Features, FrameInfo, LinkError, RuntimeError, Tunables};
pub use wasmer_derive::ValueType;
pub use wasmer_types::is_wasm;
// TODO: OnCalledAction is needed for asyncify. It will be refactored with https://github.com/wasmerio/wasmer/issues/3451
pub use wasmer_types::{
    CpuFeature, ExportType, ExternType, FunctionType, GlobalType, ImportType, MemoryType,
    Mutability, OnCalledAction, TableType, Target, Type,
};

pub use wasmer_types::{
    Bytes, CompileError, DeserializeError, ExportIndex, GlobalInit, LocalFunctionIndex,
    MiddlewareError, Pages, ParseCpuFeatureError, SerializeError, ValueType, WasmError, WasmResult,
    WASM_MAX_PAGES, WASM_MIN_PAGES, WASM_PAGE_SIZE,
};

// TODO: should those be moved into wasmer::vm as well?
pub use wasmer_vm::{raise_user_trap, MemoryError};
pub mod vm {
    //! The `vm` module re-exports wasmer-vm types.

    pub use wasmer_vm::{
        MemoryError, MemoryStyle, TableStyle, VMExtern, VMMemory, VMMemoryDefinition,
        VMOwnedMemory, VMSharedMemory, VMTable, VMTableDefinition,
    };
}

#[cfg(feature = "wat")]
pub use wat::parse_bytes as wat2wasm;

#[cfg(feature = "singlepass")]
pub use wasmer_compiler_singlepass::Singlepass;

#[cfg(feature = "cranelift")]
pub use wasmer_compiler_cranelift::{Cranelift, CraneliftOptLevel};

#[cfg(feature = "llvm")]
pub use wasmer_compiler_llvm::{LLVMOptLevel, LLVM};

#[cfg(feature = "compiler")]
pub use wasmer_compiler::{Artifact, EngineBuilder};

/// Version number of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// This type is deprecated, it has been replaced by TypedFunction.
#[deprecated(
    since = "3.0.0",
    note = "NativeFunc has been replaced by TypedFunction"
)]
pub type NativeFunc<Args = (), Rets = ()> = TypedFunction<Args, Rets>;
