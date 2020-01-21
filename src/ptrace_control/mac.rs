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
use mach::kern_return::{kern_return_t, KERN_SUCCESS};
use mach::mach_types::{thread_act_array_t, vm_task_entry_t, thread_act_t, task_port_t};
use mach::message::mach_msg_type_number_t;
use mach::thread_status::{x86_THREAD_STATE64, thread_state_flavor_t, thread_state_t};
use mach::structs::x86_thread_state64_t;
use mach::vm_types::{mach_vm_address_t, mach_vm_size_t, vm_offset_t, natural_t, integer_t};
use mach::vm::{mach_vm_read, mach_vm_write, mach_vm_protect, mach_vm_region};
use mach::vm_prot::{VM_PROT_COPY, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, VM_PROT_ALL,vm_prot_t};
use mach::vm_page_size::{vm_page_size, mach_vm_trunc_page};
use mach::vm_region::{VM_REGION_BASIC_INFO_64, vm_region_basic_info_64, vm_region_basic_info_64_t};

type thread_flavor_t = natural_t;

type thread_info_t = *mut integer_t;

type time_value_t = time_value;

type policy_t = c_int;

type thread_basic_info_data_t = thread_basic_info;
type thread_basic_info_t = *mut thread_basic_info;

type thread_identifier_info_data_t = thread_identifier_info;
type thread_identifier_info_t = *mut thread_identifier_info;

type thread_extended_info_data_t = thread_extended_info;
type thread_extended_info_t = *mut thread_extended_info;

/// No policy
const POLICY_NULL: policy_t = 0;
/// Timesharing policy
const POLICY_TIMESHARE: policy_t = 1;
/// Fixed round robin policy
const POLICY_RR: policy_t = 2;
/// Fixed FIFO policy
const POLICY_FIFO: policy_t = 4;
#[derive(Debug)]
#[repr(C)]
struct time_value {
    seconds: integer_t,
    microseconds: integer_t,
}
#[derive(Debug)]
#[repr(C)]
struct thread_basic_info {
    user_time: time_value_t,
    system_time: time_value_t,
    cpu_usage: integer_t,
    policy: policy_t,
    run_state: integer_t,
    flags: integer_t,
    suspend_count: integer_t,
    sleep_time: integer_t,
}
#[derive(Debug)]
#[repr(C)]
struct thread_identifier_info {
    thread_id: u64,
    thread_handle: u64,
    dispatch_qaddr: u64,
}

const MAX_THREAD_NAME_SIZE: usize = 64;
#[repr(C)]
struct thread_extended_info {
    pth_user_time: u64,
    pth_system_time: u64,
    pth_cpu_usage: i32,
    pth_policy: i32,
    pth_run_state: i32,
    pth_flags: i32,
    pth_sleep_time: i32,
    pth_curpri: i32,
    pth_priority: i32,
    pth_maxpriority: i32,
    pth_name: [u8; MAX_THREAD_NAME_SIZE],
}

const THREAD_BASIC_INFO: thread_flavor_t = 3;
const THREAD_IDENTIFIER_INFO: thread_flavor_t = 4;
const THREAD_EXTENDED_INFO: thread_flavor_t = 5;

const THREAD_BASIC_INFO_COUNT: mach_msg_type_number_t = (mem::size_of::<thread_basic_info_data_t>() / mem::size_of::<natural_t>()) as mach_msg_type_number_t;
const THREAD_IDENTIFIER_INFO_COUNT: mach_msg_type_number_t = (mem::size_of::<thread_identifier_info_data_t>() / mem::size_of::<natural_t>()) as mach_msg_type_number_t;
const THREAD_EXTENDED_INFO_COUNT: mach_msg_type_number_t = (mem::size_of::<thread_extended_info_data_t>() / mem::size_of::<natural_t>()) as mach_msg_type_number_t;

extern "C" {
    pub fn thread_set_state(
        target_thread: thread_act_t,
        flavor: thread_state_flavor_t,
        new_state: thread_state_t,
        new_state_count: mach_msg_type_number_t,
    ) -> kern_return_t;

    pub fn thread_info(
        target_thread: thread_act_t,
        flavor: thread_flavor_t,
        thread_info: thread_info_t,
        thread_info_count: *mut mach_msg_type_number_t,
    ) -> kern_return_t;
}

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
    let task_port = get_task_port(pid)?;
    println!("Task port = {}, Reading address = {}", task_port, address);
    unsafe {
        let mut data_addr: MaybeUninit<vm_offset_t> = MaybeUninit::uninit();
        let mut bytes_read: mach_msg_type_number_t = mem::size_of::<c_long>().try_into().unwrap();
        let bytes_req = bytes_read as u64;
        let res: KernelRet = KernelRet::from(mach_vm_read(
            task_port,
            address,
            bytes_req,
            data_addr.as_mut_ptr(),
            &mut bytes_read
        ) as u32);
        if res == KernelRet::Success {
            let data_addr = data_addr.assume_init();
            let data_ptr = data_addr as *const u8;
            assert_eq!(bytes_read as u64, bytes_req);
            let data = std::slice::from_raw_parts(data_ptr, bytes_read as usize);
            let value = c_long::from_ne_bytes(data.try_into().unwrap());
            println!("Read => {}", value);
            Ok(value)
        } else {
            Err(Error::from_errno(res.into()))
        }
    }
}

impl From<c_uint> for KernelRet {
    fn from(kern_ret: c_uint) -> Self {
        use KernelRet::*;
        match kern_ret {
            0 => Success,
            1 => InvalidAddress,
            2 => ProtectionFailure,
            4 => InvalidArgument,
            5 => Failure,
            6 => ResourceShortage,
            8 => NoAccess,
            9 => MemoryFailure,
            10 => MemoryError,
            14 => Aborted,
            15 => InvalidName,
            16 => InvalidTask,
            17 => InvalidRight,
            18 => InvalidValue,
            20 => InvalidCapability,
            32 => ExceptionProtected,
            37 => Terminated,
            46 => NotSupported,
            49 => OperationTimedOut,
            e => Other(e)
        }
    }
}

impl From<i32> for KernelRet {
    fn from(kern_ret: i32) -> Self {
        Self::from(kern_ret as c_uint)
    }
}
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelRet {
    Success,
    InvalidAddress,
    ProtectionFailure,
    InvalidArgument,
    Failure,
    ResourceShortage,
    NoAccess,
    MemoryFailure,
    MemoryError,
    Aborted,
    InvalidName,
    InvalidTask,
    InvalidRight,
    InvalidValue,
    InvalidCapability,
    ExceptionProtected,
    Terminated,
    NotSupported,
    OperationTimedOut,
    Other(c_uint)
}

impl Into<Errno> for KernelRet {
    fn into(self) -> Errno {
        // TODO: write a real impl
        Errno::UnknownErrno
    }
}

fn get_task_port(pid: Pid) -> Result<vm_task_entry_t> {
    let mut port: MaybeUninit<vm_task_entry_t> = MaybeUninit::uninit();
    unsafe {
        let res = mach::traps::task_for_pid(
            mach::traps::mach_task_self(),
            pid.into(),
            port.as_mut_ptr()
        );
        if res == KERN_SUCCESS {
            let port = port.assume_init();
            Ok(port)
        } else {
            println!("KERN RET FAIL : {}", res);
            Err(Error::from_errno(Errno::UnknownErrno))
        }
    }
}

fn check_prots(task: vm_task_entry_t, address: u64) -> Result<(u64, i32)> {
    let mut address = address;
    let mut region_info = vm_region_basic_info_64::default();
    let mut size = mem::size_of_val(&region_info).try_into().unwrap();
    let mut sz = 8;
    let mut name = 1;
    println!("REGION");
    let res: KernelRet = unsafe { mach_vm_region(
        task,
        &mut address,
        &mut sz,
        VM_REGION_BASIC_INFO_64,
        &mut region_info as *mut _ as *mut i32,
        &mut size,
        &mut name
    ).into()};
    let prot = region_info.protection;
    let max_prot = region_info.max_protection;
    println!("Protection = {}", prot);
    println!("Max protection = {}", max_prot);
    println!("Region started at addr : {}", address);
    Ok((address, prot))
}

fn set_prot_flag(task: vm_task_entry_t, address: u64, prots: i32) -> Result<()> {
    // let (addr, prot) = check_prots(task, address)?;
    // if prot & prots == prots {
    //     println!("Protections already correctly set!");
    //     return Ok(());
    // }
    unsafe { 
        let res: KernelRet = mach_vm_protect(
            task,
            address,
            8 as u64,
            0,
            prots
        ).into();
        match res {
            KernelRet::Success => {
                Ok(())
            },
            _ => {
                eprintln!("Kernel returned {:?}", res);
                // let (addr, prot) = check_prots(task, addr)?;
                Err(Error::from_errno(res.into()))
            }
        }
    }
}

pub fn write_to_address(pid: Pid, address: u64, data: i64) -> Result<()> {
    println!("write_to_address: {:?} {:?} {:?}", pid, address, data);
    let task_port = get_task_port(pid)?;
    println!("Task port = {}, Write address = {}", task_port, address);
    unsafe {
        let bytes_to_write: u32 = mem::size_of::<i64>().try_into().unwrap();
        loop {
            let (_, prot) = check_prots(task_port, address)?;
            println!("current protection : {}", prot);
            if prot == VM_PROT_ALL {
                break;
            } 
            println!("setting prots");
            set_prot_flag(task_port, address, VM_PROT_COPY)?;
            set_prot_flag(task_port, address, VM_PROT_ALL)?;
        }
        let bytes = &data as *const _ as *const u8 as usize;
        // let byte_addr = bytes.as_ptr() as usize;

        let res: KernelRet = KernelRet::from(mach_vm_write(
            task_port,
            address,
            bytes,
            bytes_to_write,
        ) as u32);
        if res == KernelRet::Success {
            Ok(())
        } else {
            eprintln!("KERN ERROR : {:?}", res);
            Err(Error::from_errno(res.into()))
        }
    }
}

fn threads_for_task<'a>(task: vm_task_entry_t) -> Result<&'a [thread_act_t]> {
    let mut thread_list: thread_act_array_t = ptr::null_mut();
    let mut thread_count: mach_msg_type_number_t = 0;
    unsafe {
        let res: KernelRet = mach::task::task_threads(
            task,
            &mut thread_list,
            &mut thread_count
        ).into();
        if res == KernelRet::Success {
            assert!(thread_count >= 1);
            println!("Thread count = {}", thread_count);
            let threads = slice::from_raw_parts(thread_list, thread_count as usize);
            println!("Threads = {:?}", threads);
            println!("Current thread = {}", unsafe { mach::mach_init::mach_thread_self() });
            Ok(threads)
        } else {
            Err(Error::from_errno(res.into()))
        }
    }
}

fn get_thread_info(thread: thread_act_t) -> Result<thread_identifier_info> {
    let mut info: MaybeUninit<thread_identifier_info> = MaybeUninit::uninit();
    let mut count = THREAD_IDENTIFIER_INFO_COUNT; 
    unsafe {
        let res: KernelRet = thread_info(
            thread,
            THREAD_IDENTIFIER_INFO,
            &mut info as *mut _ as thread_info_t,
            &mut count
        ).into();
        match res {
            KernelRet::Success => {
                assert_eq!(count, 6);
                let info = info.assume_init();
                println!("Thread info for {} => {:?}", thread, info);
                Ok(info)
            }
            code => Err(Error::from_errno(code.into()))
        }
    }
}

fn test_thread_for_pid(pid: Pid) -> Result<thread_act_t> {
    let task = get_task_port(pid)?;
    let threads = threads_for_task(task)?;
    let highest = threads.iter().map(|&t| (t, get_thread_info(t).unwrap().thread_id)).max_by_key(|&(t, tid)| tid).unwrap();
    Ok(highest.0)
}

fn get_thread_state(thread: thread_act_t) -> Result<x86_thread_state64_t> {
    let mut old_state = x86_thread_state64_t::new();
    let mut state_count = x86_thread_state64_t::count();
    let expected = state_count;
    unsafe {
        let res: KernelRet = mach::thread_act::thread_get_state(
            thread,
            x86_THREAD_STATE64,
            &mut old_state as *mut _ as *mut u32,
            &mut state_count
        ).into();
        match res {
            KernelRet::Success => {
                assert_eq!(expected, state_count);
                Ok(old_state)
            },
            _ => Err(Error::from_errno(res.into()))
        }
    }
}

fn set_thread_state(thread: thread_act_t, new_state: x86_thread_state64_t) -> Result<()> {
    let mut state_count = x86_thread_state64_t::count();
    let mut new_state = new_state;
    unsafe {
        let res: KernelRet = thread_set_state(
            thread,
            x86_THREAD_STATE64,
            &mut new_state as *mut _ as *mut u32,
            state_count
        ).into();
        match res {
            KernelRet::Success => Ok(()),
            _ => Err(Error::from_errno(res.into()))
        }
    }
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
