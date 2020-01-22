#![allow(unused)]
#![allow(non_camel_case_types)]

use nix::errno::Errno;
use nix::libc::{c_long, c_uint, c_int};
use nix::sys::ptrace::*;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use nix::{Error, Result};
use std::ptr;
use std::mem;
use std::slice;
use std::mem::MaybeUninit;
use std::{fmt::Display, convert::TryInto};
use crate::mach::*;

pub fn trace_children(pid: Pid) -> Result<()> {
    //TODO need to check support.
    // todo!()
    Ok(())
    // attach(pid)
}

pub fn detach_child(pid: Pid) -> Result<()> {
    detach(pid, None)
}

pub fn continue_exec(pid: Pid, sig: Option<Signal>) -> Result<()> {
    cont(pid, sig)
}

#[allow(deprecated)]
pub fn single_step(pid: Pid) -> Result<()> {
    // let rip = current_instruction_pointer(pid)?;
    // loop {
        unsafe {
            Errno::clear();
        }
        println!("Single step");
        let res = Errno::result(unsafe { libc::ptrace(
            libc::PT_STEP,
            libc::pid_t::from(pid),
            1 as *mut i8,
            0
        ) })?;
        // let res = Errno::result(unsafe { libc::ptrace(
        //     libc::PT_STEP,
        //     libc::pid_t::from(pid),
        //     1 as *mut i8,
        //     0
        // ) })?;
        // let res = step(pid, None)?;
    // }
    // Ok((res))
    Ok(())
}


pub fn read_address(pid: Pid, address: u64) -> Result<c_long> {
    mach_read(pid, address)
}

pub fn write_to_address(pid: Pid, address: u64, data: i64) -> Result<()> {
    mach_write(pid, address, data)
}

pub fn current_instruction_pointer(pid: Pid) -> Result<c_long> {
    println!("CURRENT IP");
    unsafe {
        Errno::clear();
    }
    println!("current PID is {:?}", pid);
    let test_thread = test_thread_for_pid(pid)?;
    let thread_state = get_thread_state(test_thread)?;
    Ok(thread_state.__rip.try_into().unwrap())
}

#[allow(deprecated)]
pub fn set_instruction_pointer(pid: Pid, pc: u64) -> Result<c_long> {
    println!("Setting PC to {}", pc);
    let task = get_task_port(pid)?;
    let test_thread = test_thread_for_pid(pid)?;
    // unsafe { mach::thread_act::thread_suspend(test_thread); }
    unsafe { mach::task::task_suspend(task); }
    println!("Test thread = {}", test_thread);
    let mut old_state = get_thread_state(test_thread)?;
    let old_pc = old_state.__rip;
    old_state.__rip = pc;
    println!("setting");
    set_thread_state(test_thread, old_state)?;
    println!("set");
    let changed = get_thread_state(test_thread)?;
    assert_eq!(changed.__rip, pc);
    // let res: KernelRet = unsafe { mach::thread_act::thread_resume(test_thread).into() };
    let res: KernelRet = unsafe { mach::task::task_resume(task).into() };
    println!("RESUMED => RES = {:?}", res);
    Ok(pc as i64)
}

pub fn request_trace() -> Result<()> {
    traceme()
    // Ok(())
}

pub fn get_event_data(pid: Pid) -> Result<c_long> {
    // getevent(pid);
    todo!()
}
