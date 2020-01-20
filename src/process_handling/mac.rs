use crate::errors::*;
use nix::libc::*;
use std::ffi::{CString};
use std::{mem::MaybeUninit, ptr};
use log::trace;


pub fn execute(program: CString, argv: &[CString], envar: &[CString]) -> Result<(), RunError> {
    let disable_aslr = CString::new("DYLD_NO_PIE=1\0").unwrap();
    let mut attr: MaybeUninit<posix_spawnattr_t> = MaybeUninit::uninit();
    let mut res = unsafe { posix_spawnattr_init(attr.as_mut_ptr()) };
    if res != 0 {
        trace!("Can't initialise posix_spawnattr_t");
    }
    let mut attr = unsafe { attr.assume_init() };
    let flags = (POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETEXEC | 0x0100) as i16;

    res = unsafe { posix_spawnattr_setflags(&mut attr, flags) };
    if res != 0 {
        trace!("Failed to set spawn flags");
    }

    let mut args: Vec<*mut c_char> = argv.iter().map(|s| s.clone().into_raw()).collect();

    args.push(ptr::null_mut());

    let mut envs: Vec<*mut c_char> = envar.iter().map(|s| s.clone().into_raw()).collect();
    envs.push(disable_aslr.into_raw());
    envs.push(ptr::null_mut());

    unsafe { 
        posix_spawnp(
            ptr::null_mut(),
            program.into_raw(),
            ptr::null_mut(),
            &attr,
            args.as_ptr(),
            envs.as_ptr(),
        );
    }

    Err(RunError::Internal)
}
