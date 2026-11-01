//! The loaded plug-in modules (what glibc's iconv/gconv_dl.c keeps): one object per module path, shared by the conversion
//! descriptors that use it, with a count of its users. A module nobody uses stays loaded until three other modules have been
//! released after it, so a program that opens and closes the same conversion again and again loads the shared object once.
use crate::gconv_abi::{self as abi, LoadedObject};
use crate::gconv_sys;
use crate::heapvec::HeapVec;
use core::ffi::{CStr, c_char};
use rusty_libc_core::ffi::cstr_bytes;
use rusty_libc_core::lock::Locked;

/// How many releases of other modules an unused module survives (glibc's `TRIES_BEFORE_UNLOAD`).
const TRIES_BEFORE_UNLOAD: i32 = 2;

/// Why a module could not be had: the errno `iconv_open` reports.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LoadError {
    /// The file does not load or has no `gconv` function (`EINVAL`).
    NoModule,
    /// Out of memory (`ENOMEM`).
    NoMemory,
}

/// Every module object made so far (addresses of objects that are never freed, so the table can hold them as plain data).
static LOADED: Locked<HeapVec<usize>> = Locked::new(HeapVec::new());

/// The name of a loaded object.
fn name_of<'a>(obj: *const LoadedObject) -> &'a [u8] {
    // SAFETY: the name points into the object's own allocation, which is never freed; it was NUL-terminated by `new_object`.
    let name = unsafe { (*obj).name };
    // SAFETY: as above.
    unsafe { cstr_bytes(name) }
}

/// Load the shared object of `obj` and find its functions (`__gconv_find_shlib`). Leaves `obj` unloaded on failure.
fn load_object(obj: &mut LoadedObject) -> Result<(), LoadError> {
    // SAFETY: the name is the NUL-terminated copy `new_object` made.
    let name = unsafe { CStr::from_ptr(obj.name) };
    // SAFETY: loading a module runs its constructors, which is what a conversion through `GCONV_PATH` asks for.
    let handle = unsafe { gconv_sys::load(name) };
    if handle.is_null() {
        return Err(LoadError::NoModule);
    }
    // SAFETY: `handle` is the live handle just returned.
    let fct = unsafe { gconv_sys::symbol(handle, c"gconv") };
    if fct == 0 {
        // SAFETY: nothing of the module ran; the handle is given up.
        unsafe { gconv_sys::unload(handle) };
        return Err(LoadError::NoModule);
    }
    // SAFETY: `handle` is live.
    let init = unsafe { gconv_sys::symbol(handle, c"gconv_init") };
    // SAFETY: `handle` is live.
    let end = unsafe { gconv_sys::symbol(handle, c"gconv_end") };
    obj.handle = handle;
    obj.fct = abi::mangle(fct);
    obj.init_fct = abi::mangle(init);
    obj.end_fct = abi::mangle(end);
    obj.counter = 1;
    Ok(())
}

/// A new, unloaded object for the module at `path`.
fn new_object(path: &[u8]) -> Option<*mut LoadedObject> {
    let size = size_of::<LoadedObject>() + path.len() + 1;
    // SAFETY: calloc may be called with any sizes; the result is checked below.
    let obj = unsafe { rusty_libc_malloc::calloc(1, size) }.cast::<LoadedObject>();
    if obj.is_null() {
        return None;
    }
    let name_at = obj.wrapping_add(1).cast::<u8>();
    // SAFETY: the name goes into the bytes after the object, inside the allocation (`size` covers it with its NUL, which
    // the zeroed allocation provides).
    unsafe { core::ptr::copy_nonoverlapping(path.as_ptr(), name_at, path.len()) };
    // SAFETY: `obj` is the allocation just made, not shared yet.
    unsafe { (*obj).name = name_at.cast::<c_char>() };
    Some(obj)
}

/// The loaded object of the module at `path`, loading it if need be; the caller is one more user of it.
pub(crate) fn acquire(path: &[u8]) -> Result<*mut LoadedObject, LoadError> {
    LOADED.with(|list| {
        if let Some(&addr) = list.iter().find(|&&a| name_of(a as *const LoadedObject) == path) {
            let obj = addr as *mut LoadedObject;
            // SAFETY: objects in the table are valid and only changed with the table locked.
            let o = unsafe { &mut *obj };
            if o.handle.is_null() {
                // unloaded after its last user left: load it again
                load_object(o)?;
            } else {
                o.counter = (o.counter + 1).max(1);
            }
            return Ok(obj);
        }
        let obj = new_object(path).ok_or(LoadError::NoMemory)?;
        // SAFETY: `obj` is the allocation just made, not shared yet.
        let o = unsafe { &mut *obj };
        if let Err(e) = load_object(o) {
            // SAFETY: not shared and not in the table.
            unsafe { rusty_libc_malloc::free(obj.cast()) };
            return Err(e);
        }
        if !list.push(obj as usize) {
            // SAFETY: the module just loaded is given up again; the object is not in the table.
            unsafe { gconv_sys::unload(o.handle) };
            // SAFETY: not shared and not in the table.
            unsafe { rusty_libc_malloc::free(obj.cast()) };
            return Err(LoadError::NoMemory);
        }
        Ok(obj)
    })
}

/// One user less of `released`; the modules nobody uses that have waited long enough are unloaded.
pub(crate) fn release(released: *mut LoadedObject) {
    LOADED.with(|list| {
        for &addr in list.iter() {
            let obj = addr as *mut LoadedObject;
            // SAFETY: objects in the table are valid and only changed with the table locked.
            let o = unsafe { &mut *obj };
            if obj == released {
                o.counter -= 1;
            } else if o.counter <= 0 && o.counter >= -TRIES_BEFORE_UNLOAD {
                o.counter -= 1;
                if o.counter < -TRIES_BEFORE_UNLOAD && !o.handle.is_null() {
                    // SAFETY: nothing runs code of an unused module: its last step was released.
                    unsafe { gconv_sys::unload(o.handle) };
                    o.handle = core::ptr::null_mut();
                }
            }
        }
    });
}
