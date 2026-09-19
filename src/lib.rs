#![allow(dead_code)]
#![allow(unused_imports)]

//! Static library entry point linked into LWx.
//!
//! Exposes `lwx_dump_offsets`, which runs the full cs2-dumper analysis against
//! the game process and writes the flat offsets cache consumed by the cheat:
//!
//! ```json
//! { "<category>": { "<name>": "0xHEX" } }
//! ```
//!
//! Categories match what the cheat's old regex `.hpp` parser produced:
//! module namespaces slugified (`client.dll` -> `client_dll`), schema class
//! names slugified (`C_BaseEntity`), and button state RVAs under `"buttons"`.
//! Enum members are intentionally excluded - the `.hpp` output declares them
//! as real `enum class` declarations, which the old parser never captured.

use std::collections::BTreeMap;
use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};

use anyhow::{Result, bail};

use log::{error, info, LevelFilter, Log, Metadata, Record};

use memflow::prelude::v1::*;

use windows::core::PCSTR;
use windows::Win32::Storage::FileSystem::{MoveFileExA, MOVEFILE_REPLACE_EXISTING};

mod analysis;
mod memory;
mod output;
mod source2;

use analysis::AnalysisResult;

/// Arguments for [`lwx_dump_offsets`]. All strings are NUL-terminated UTF-8.
#[repr(C)]
pub struct LwxDumpArgs {
    /// Name of the game process to dump (e.g. "cs2.exe").
    pub process_name: *const c_char,
    /// Destination path of the flat offsets cache.
    pub out_path: *const c_char,
    /// Path of the log file written by this dump (e.g. "<out_path>.log").
    pub log_path: *const c_char,
}

fn cstr_to_string(ptr: *const c_char) -> Result<String> {
    if ptr.is_null() {
        bail!("null string argument");
    }

    // SAFETY: strings are NUL-terminated per the C ABI contract.
    Ok(unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned())
}

fn write_err(err_buf: *mut c_char, err_len: usize, msg: &str) {
    if err_buf.is_null() || err_len == 0 {
        return;
    }

    let n = msg.len().min(err_len - 1);

    unsafe {
        std::ptr::copy_nonoverlapping(msg.as_ptr(), err_buf.cast(), n);
        *err_buf.add(n) = 0;
    }
}

/// File logger that reopens the file for every line, so the handle is never
/// held open - the log stays previewable by editors for the whole lifetime of
/// the cheat, not just between dumps. (simplelog's `WriteLogger` keeps the
/// `File` alive until process exit, which locked the log even after the dump
/// finished.)
struct AppendFileLogger {
    path: String,
    lock: std::sync::Mutex<()>,
}

impl AppendFileLogger {
    fn new(path: String) -> Self {
        Self {
            path,
            lock: std::sync::Mutex::new(()),
        }
    }
}

impl Log for AppendFileLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        use std::io::Write;

        // Same "HH:MM:SS [LEVEL] message" shape as simplelog's default (UTC).
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!(
            "{:02}:{:02}:{:02} [{:>5}] {}",
            (secs / 3600) % 24,
            (secs / 60) % 60,
            secs % 60,
            record.level(),
            record.args()
        );

        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(file, "{line}");
        }
    }

    fn flush(&self) {}
}

/// Runs the full cs2-dumper analysis against `process_name` and writes the flat
/// offsets cache to `out_path`.
///
/// Returns 0 on success, nonzero on failure, and fills `err_buf` with a
/// description of the failure. Panics never escape this function.
#[unsafe(no_mangle)]
pub extern "C" fn lwx_dump_offsets(
    args: *const LwxDumpArgs,
    err_buf: *mut c_char,
    err_len: usize,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| dump_offsets(args))) {
        Ok(Ok(())) => 0,
        Ok(Err(err)) => {
            error!("{err:#}");

            write_err(err_buf, err_len, &format!("{err:#}"));

            1
        }
        Err(_) => {
            write_err(err_buf, err_len, "offset dump panicked");

            1
        }
    }
}

fn dump_offsets(args: *const LwxDumpArgs) -> Result<()> {
    if args.is_null() {
        bail!("null argument struct");
    }

    let args = unsafe { &*args };

    let process_name = cstr_to_string(args.process_name)?;
    let out_path = cstr_to_string(args.out_path)?;
    let log_path = cstr_to_string(args.log_path)?;

    // Truncate once per dump, then append per line (see AppendFileLogger).
    std::fs::write(&log_path, "")?;

    // The log crate wants a 'static logger; leak one and let it live until
    // process exit. A later dump in the same process just appends to the
    // same file.
    let logger: &'static AppendFileLogger =
        Box::leak(Box::new(AppendFileLogger::new(log_path.clone())));
    let _ = log::set_logger(logger);
    log::set_max_level(LevelFilter::Info);

    // Do not enable SeDebugPrivilege on the caller's token - the caller can
    // already open the game process without it.
    let os_args = OsArgs {
        target: None,
        extra_args: Args::new().insert("elevate_token", "off"),
    };

    // Retry once with default arguments in case the process cannot be opened
    // without the debug privilege.
    let mut os = match memflow_native::create_os(&os_args, LibArc::default()) {
        Ok(os) => os,
        Err(err) => {
            error!("attach failed without privilege elevation: {err:#}");

            memflow_native::create_os(&OsArgs::default(), LibArc::default())?
        }
    };

    let mut process = os.process_by_name(&process_name)?;

    let result = analysis::analyze_all(&mut process)?;

    // A missing offsets or schemas section breaks the cheat's offset registry;
    // refuse to write a degraded cache over the last good one.
    if result.offsets.is_empty() || result.schemas.is_empty() {
        bail!(
            "incomplete dump: {} offset modules, {} schema modules",
            result.offsets.len(),
            result.schemas.len()
        );
    }

    let flat = flatten(&result);

    let json = serde_json::to_string_pretty(&flat)?;

    write_cache(&out_path, &json)
}

/// Converts the analysis result into the flat cache format (see module docs).
fn flatten(result: &AnalysisResult) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut flat = BTreeMap::<String, BTreeMap<String, String>>::new();

    for (module, offsets) in &result.offsets {
        let category = slugify(module);

        for (name, rva) in offsets {
            flat.entry(category.clone())
                .or_default()
                .insert(name.clone(), format!("0x{rva:X}"));
        }
    }

    for (module, interfaces) in &result.interfaces {
        let category = slugify(module);

        for (name, instance_rva) in interfaces {
            flat.entry(category.clone())
                .or_default()
                .insert(name.clone(), format!("0x{instance_rva:X}"));
        }
    }

    {
        let category = "buttons".to_string();

        for (name, state_rva) in &result.buttons {
            flat.entry(category.clone())
                .or_default()
                .insert(name.clone(), format!("0x{state_rva:X}"));
        }
    }

    // `schemas` is a BTreeMap keyed by module name, so modules iterate
    // alphabetically ("client.dll" before "server.dll"). Many classes exist
    // in both modules with different layouts (e.g. CCSPlayerController) -
    // keep the FIRST module's field so the client layout wins and server
    // values never overwrite the offsets the cheat reads.
    for (_, (classes, _enums)) in &result.schemas {
        for class in classes {
            let category = slugify(&class.name);

            for field in &class.fields {
                flat.entry(category.clone())
                    .or_default()
                    .entry(field.name.clone())
                    .or_insert_with(|| format!("0x{:X}", field.offset as u32));
            }
        }
    }

    flat
}

/// Mirrors `output::mod::slugify` so category names match the cheat's cache.
#[inline]
fn slugify(input: &str) -> String {
    input.replace(|c: char| !c.is_alphanumeric(), "_")
}

/// Writes via a temp file + MoveFileEx so a failed dump never leaves a
/// truncated cache in place of the last good one.
fn write_cache(out_path: &str, json: &str) -> Result<()> {
    let tmp_path = format!("{out_path}.tmp");

    std::fs::write(&tmp_path, json)?;

    let from = std::ffi::CString::new(tmp_path)?;
    let to = std::ffi::CString::new(out_path)?;

    unsafe {
        MoveFileExA(
            PCSTR(from.as_ptr().cast()),
            PCSTR(to.as_ptr().cast()),
            MOVEFILE_REPLACE_EXISTING,
        )
    }
    .map_err(|err| anyhow::anyhow!("failed to replace cache file: {err}"))?;

    Ok(())
}
