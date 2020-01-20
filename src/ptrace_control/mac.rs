#![allow(unused)]
use nix::errno::Errno;
use nix::libc::{c_long, c_uint};
use nix::sys::ptrace::*;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use nix::{Error, Result};
use std::ptr;
use std::mem;
use std::mem::MaybeUninit;
use std::convert::TryInto;
use mach::kern_return::{KERN_SUCCESS};
use mach::mach_types::thread_act_array_t;
use mach::message::mach_msg_type_number_t;
use mach::thread_status::{x86_THREAD_STATE64};
use mach::structs::x86_thread_state64_t;

pub fn trace_children(pid: Pid) -> Result<()> {
    //TODO need to check support.
    todo!()
}

pub fn detach_child(pid: Pid) -> Result<()> {
    detach(pid, None)
}

pub fn continue_exec(pid: Pid, sig: Option<Signal>) -> Result<()> {
    cont(pid, sig)
}

#[allow(deprecated)]
pub fn single_step(pid: Pid) -> Result<()> {
    step(pid, None)
}

pub fn read_address(pid: Pid, address: u64) -> Result<c_long> {
    read(pid, address as AddressType).map(|res| res as c_long)
}

pub fn write_to_address(pid: Pid, address: u64, data: i64) -> Result<()> {
    let data: [u8; 8] = data.to_ne_bytes();
    let data_lo = i32::from_ne_bytes(data[0..4].try_into().unwrap());
    let data_hi = i32::from_ne_bytes(data[4..8].try_into().unwrap());
    write(pid, address as AddressType, data_lo)?;
    let address = address + mem::size_of::<i32>() as u64;
    write(pid, address as AddressType, data_hi)
}

#[allow(deprecated)]
pub fn current_instruction_pointer(pid: Pid) -> Result<c_long> {

    unsafe {
        Errno::clear();
    }
    let mut port: MaybeUninit<c_uint> = MaybeUninit::uninit();
    unsafe {
        if mach::traps::task_for_pid(
            mach::traps::mach_task_self(),
            pid.into(),
            port.as_mut_ptr()
        ) == KERN_SUCCESS {
            let port = port.assume_init();
            let mut thread_list: thread_act_array_t = ptr::null_mut();
            let mut thread_count: mach_msg_type_number_t = 0;

            if mach::task::task_threads(
                port,
                &mut thread_list,
                &mut thread_count
            ) == KERN_SUCCESS {
                let mut old_state = x86_thread_state64_t::new();
                let mut state_count = x86_thread_state64_t::count();
                if mach::thread_act::thread_get_state (
                    *thread_list.offset(0),
                    x86_THREAD_STATE64,
                    &mut old_state as *mut _ as *mut u32,
                    &mut state_count
                ) == KERN_SUCCESS {
                    Ok(old_state.__rip.try_into().unwrap())
                } else {
                    Err(Error::from_errno(Errno::UnknownErrno))
                }
            } else {
                Err(Error::from_errno(Errno::UnknownErrno))
            }
        } else {
            Err(Error::from_errno(Errno::UnknownErrno))
        }
    }
}

#[allow(deprecated)]
pub fn set_instruction_pointer(pid: Pid, pc: u64) -> Result<c_long> {
    // unsafe {
    //     ptrace(
    //         Request::PTRACE_POKEUSER,
    //         pid,
    //         RIP as *mut c_void,
    //         pc as *mut c_void,
    //     )
    // }
    todo!()
}

pub fn request_trace() -> Result<()> {
    traceme()
}

pub fn get_event_data(pid: Pid) -> Result<c_long> {
    // getevent(pid);
    todo!()
}
