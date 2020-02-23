#![allow(unused)]
#![allow(non_camel_case_types)]

use mem::MaybeUninit;
use std::mem;
use std::ptr;
use std::slice;
use {
    convert::{TryFrom, TryInto},
    std::convert,
};

use libc::{boolean_t, c_int, c_long, c_uint};
use mach::exception_types::{
    exception_behavior_array_t, exception_behavior_t, exception_mask_array_t, exception_mask_t,
    exception_port_array_t, exception_type_t, mach_exception_data_t, EXCEPTION_DEFAULT,
    EXC_MASK_ALL, EXC_SOFTWARE, EXC_SOFT_SIGNAL, MACH_EXCEPTION_CODES,
};
use mach::kern_return::{kern_return_t, KERN_SUCCESS};
use mach::mach_port::{mach_port_allocate, mach_port_deallocate, mach_port_insert_right};
use mach::mach_types::task_t;
use mach::mach_types::{task_port_t, thread_act_array_t, thread_act_t, vm_task_entry_t};
use mach::message::{
    mach_msg, mach_msg_return_t, MACH_RCV_INVALID_TYPE, MACH_RCV_MSG, MACH_RCV_TIMED_OUT,
};
use mach::message::{mach_msg_header_t, mach_msg_type_number_t, MACH_MSG_TYPE_MAKE_SEND};
use mach::port::{mach_port_name_t, mach_port_t, MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE};
use mach::structs::x86_thread_state64_t;
use mach::thread_status::{
    thread_state_flavor_t, thread_state_t, x86_EXCEPTION_STATE64, x86_THREAD_STATE64,
    THREAD_STATE_NONE,
};
use mach::traps::mach_task_self;
use mach::vm::{mach_vm_protect, mach_vm_read, mach_vm_region, mach_vm_write};
use mach::vm_page_size::{mach_vm_trunc_page, vm_page_size};
use mach::vm_prot::{
    vm_prot_t, VM_PROT_ALL, VM_PROT_COPY, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use mach::vm_region::{
    vm_region_basic_info_64, vm_region_basic_info_64_t, VM_REGION_BASIC_INFO_64,
};
use mach::vm_types::{integer_t, mach_vm_address_t, mach_vm_size_t, natural_t, vm_offset_t};
use nix::errno::Errno;
use nix::sys::ptrace::{AddressType, Request, RequestType};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use nix::{Error, Result};

type ipc_port_t = *mut u8;

type thread_state_flavor_array_t = *mut thread_state_flavor_t;

extern "C" {
    fn task_get_exception_ports(
        task: task_t,
        exception_mask: exception_mask_t,
        masks: exception_mask_array_t,
        count_cnt: *mut mach_msg_type_number_t,
        ports: exception_port_array_t,
        behaviors: exception_behavior_array_t,
        flavors: thread_state_flavor_array_t,
    ) -> kern_return_t;

    fn task_set_exception_ports(
        task: task_t,
        exception_mask: exception_mask_t,
        new_port: mach_port_t,
        new_behavior: exception_behavior_t,
        new_flavor: thread_state_flavor_t,
    ) -> kern_return_t;

    fn mach_exc_server(
        in_head_ptr: *mut mach_msg_header_t,
        out_head_ptr: *mut mach_msg_header_t,
    ) -> boolean_t;

}

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
pub(crate) struct thread_identifier_info {
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

const THREAD_BASIC_INFO_COUNT: mach_msg_type_number_t = (mem::size_of::<thread_basic_info_data_t>()
    / mem::size_of::<natural_t>())
    as mach_msg_type_number_t;
const THREAD_IDENTIFIER_INFO_COUNT: mach_msg_type_number_t =
    (mem::size_of::<thread_identifier_info_data_t>() / mem::size_of::<natural_t>())
        as mach_msg_type_number_t;
const THREAD_EXTENDED_INFO_COUNT: mach_msg_type_number_t =
    (mem::size_of::<thread_extended_info_data_t>() / mem::size_of::<natural_t>())
        as mach_msg_type_number_t;

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

#[no_mangle]
pub unsafe extern "C" fn catch_mach_exception_raise(
    exc_port: mach_port_t,
    thread: mach_port_t,
    task: mach_port_t,
    exception_type: exception_type_t,
    code: mach_exception_data_t,
    num_codes: mach_msg_type_number_t,
) -> kern_return_t {
    println!("caught an exception!");
    if exception_type == EXC_SOFTWARE as i32
        && num_codes > 0
        && *code.offset(0) == EXC_SOFT_SIGNAL as i64
    {
        for i in 0..num_codes.try_into().unwrap() {
            let sig: i32 = (*code.offset(i)).try_into().unwrap();
            let signal = Signal::try_from(sig).unwrap_or(Signal::SIGALRM);
            println!("Signal was {}", signal.as_str());
        }
        return KERN_SUCCESS;
    }
    return 5;
}

#[no_mangle]
pub extern "C" fn catch_mach_exception_raise_state(
    exc_port: mach_port_t,
    exception: exception_type_t,
    code: mach_exception_data_t,
    code_cnt: mach_msg_type_number_t,
    flavor: *mut c_int,
    old_state: thread_state_t,
    old_state_cnt: mach_msg_type_number_t,
    new_state: thread_state_t,
    new_state_cnt: *mut mach_msg_type_number_t,
) -> kern_return_t {
    return MACH_RCV_INVALID_TYPE;
}

#[no_mangle]
pub extern "C" fn catch_mach_exception_raise_state_identity(
    exc_port: mach_port_t,
    thread: mach_port_t,
    task: mach_port_t,
    exception: exception_type_t,
    code: mach_exception_data_t,
    code_cnt: mach_msg_type_number_t,
    flavor: *mut c_int,
    old_state: thread_state_t,
    old_state_cnt: mach_msg_type_number_t,
    new_state: thread_state_t,
    new_state_cnt: *mut mach_msg_type_number_t,
) -> kern_return_t {
    return MACH_RCV_INVALID_TYPE;
}

pub(crate) fn get_task_port(pid: Pid) -> Result<mach_port_name_t> {
    let mut port: MaybeUninit<mach_port_name_t> = MaybeUninit::uninit();
    unsafe {
        let res =
            mach::traps::task_for_pid(mach::traps::mach_task_self(), pid.into(), port.as_mut_ptr());
        if res == KERN_SUCCESS {
            let port = port.assume_init();
            Ok(port)
        } else {
            println!("KERN RET FAIL : {}", res);
            Err(Error::from_errno(Errno::UnknownErrno))
        }
    }
}

pub(crate) fn check_prots(task: vm_task_entry_t, address: u64) -> Result<(u64, i32)> {
    let mut address = address;
    let mut region_info = vm_region_basic_info_64::default();
    let mut size = mem::size_of_val(&region_info).try_into().unwrap();
    let mut sz = 8;
    let mut name = 1;
    println!("REGION");
    let res: KernelRet = unsafe {
        mach_vm_region(
            task,
            &mut address,
            &mut sz,
            VM_REGION_BASIC_INFO_64,
            &mut region_info as *mut _ as *mut i32,
            &mut size,
            &mut name,
        )
        .into()
    };
    let prot = region_info.protection;
    let max_prot = region_info.max_protection;
    println!("Protection = {}", prot);
    println!("Max protection = {}", max_prot);
    println!("Region started at addr : {}", address);
    Ok((address, prot))
}

pub(crate) fn set_prot_flag(task: vm_task_entry_t, address: u64, prots: i32) -> Result<()> {
    // let (addr, prot) = check_prots(task, address)?;
    // if prot & prots == prots {
    //     println!("Protections already correctly set!");
    //     return Ok(());
    // }
    unsafe {
        let res: KernelRet = mach_vm_protect(task, address, 8 as u64, 0, prots).into();
        match res {
            KernelRet::Success => Ok(()),
            _ => {
                eprintln!("Kernel returned {:?}", res);
                // let (addr, prot) = check_prots(task, addr)?;
                Err(Error::from_errno(res.into()))
            }
        }
    }
}

pub(crate) fn mach_read(pid: Pid, address: u64) -> Result<c_long> {
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
            &mut bytes_read,
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

pub(crate) fn mach_write(pid: Pid, address: u64, data: i64) -> Result<()> {
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

        let res: KernelRet =
            KernelRet::from(mach_vm_write(task_port, address, bytes, bytes_to_write) as u32);
        if res == KernelRet::Success {
            Ok(())
        } else {
            eprintln!("KERN ERROR : {:?}", res);
            Err(Error::from_errno(res.into()))
        }
    }
}

pub(crate) fn threads_for_task<'a>(task: vm_task_entry_t) -> Result<&'a [thread_act_t]> {
    let mut thread_list: thread_act_array_t = ptr::null_mut();
    let mut thread_count: mach_msg_type_number_t = 0;
    unsafe {
        let res: KernelRet =
            mach::task::task_threads(task, &mut thread_list, &mut thread_count).into();
        if res == KernelRet::Success {
            assert!(thread_count >= 1);
            println!("Thread count = {}", thread_count);
            let threads = slice::from_raw_parts(thread_list, thread_count as usize);
            println!("Threads = {:?}", threads);
            println!("Current thread = {}", unsafe {
                mach::mach_init::mach_thread_self()
            });
            Ok(threads)
        } else {
            Err(Error::from_errno(res.into()))
        }
    }
}

pub(crate) fn get_thread_info(thread: thread_act_t) -> Result<thread_identifier_info> {
    let mut info: MaybeUninit<thread_identifier_info> = MaybeUninit::uninit();
    let mut count = THREAD_IDENTIFIER_INFO_COUNT;
    unsafe {
        let res: KernelRet = thread_info(
            thread,
            THREAD_IDENTIFIER_INFO,
            &mut info as *mut _ as thread_info_t,
            &mut count,
        )
        .into();
        match res {
            KernelRet::Success => {
                assert_eq!(count, 6);
                let info = info.assume_init();
                println!("Thread info for {} => {:?}", thread, info);
                Ok(info)
            }
            code => Err(Error::from_errno(code.into())),
        }
    }
}

pub(crate) fn test_thread_for_pid(pid: Pid) -> Result<thread_act_t> {
    let task = get_task_port(pid)?;
    let threads = threads_for_task(task)?;
    let highest = threads
        .iter()
        .map(|&t| (t, get_thread_info(t).unwrap().thread_id))
        .max_by_key(|&(t, tid)| tid)
        .unwrap();
    Ok(highest.0)
}

pub(crate) fn get_thread_state(thread: thread_act_t) -> Result<x86_thread_state64_t> {
    let mut old_state = x86_thread_state64_t::new();
    let mut state_count = x86_thread_state64_t::count();
    let expected = state_count;
    unsafe {
        let res: KernelRet = mach::thread_act::thread_get_state(
            thread,
            x86_THREAD_STATE64,
            &mut old_state as *mut _ as *mut u32,
            &mut state_count,
        )
        .into();
        match res {
            KernelRet::Success => {
                assert_eq!(expected, state_count);
                Ok(old_state)
            }
            _ => Err(Error::from_errno(res.into())),
        }
    }
}

pub(crate) fn set_thread_state(
    thread: thread_act_t,
    new_state: x86_thread_state64_t,
) -> Result<()> {
    let mut state_count = x86_thread_state64_t::count();
    let mut new_state = new_state;
    unsafe {
        let res: KernelRet = thread_set_state(
            thread,
            x86_THREAD_STATE64,
            &mut new_state as *mut _ as *mut u32,
            state_count,
        )
        .into();
        match res {
            KernelRet::Success => Ok(()),
            _ => Err(Error::from_errno(res.into())),
        }
    }
}

unsafe fn ptrace_other(
    request: Request,
    pid: Pid,
    addr: AddressType,
    data: c_int,
) -> Result<c_int> {
    Errno::result(libc::ptrace(
        request as RequestType,
        libc::pid_t::from(pid),
        addr,
        data,
    ))
    .map(|_| 0)
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
            e => Other(e),
        }
    }
}

impl From<i32> for KernelRet {
    fn from(kern_ret: i32) -> Self {
        Self::from(kern_ret as c_uint)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelRet {
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
    Other(c_uint),
}

impl Into<Errno> for KernelRet {
    fn into(self) -> Errno {
        // TODO: write a real impl
        Errno::UnknownErrno
    }
}

impl Into<Result<()>> for KernelRet {
    fn into(self) -> Result<()> {
        match self {
            KernelRet::Success => Ok(()),
            _ => Err(Error::from_errno(self.into())),
        }
    }
}

const EXC_TYPES_COUNT: usize = 14;

pub(crate) struct MachControl {
    pid: Pid,
    exc_port: mach_port_t,
    rcv_header: Vec<u8>,
    rpl_header: Vec<u8>,
    task: mach_port_name_t,
}

fn attach_exc(pid: Pid) -> Result<()> {
    unsafe { ptrace_other(Request::PT_ATTACHEXC, pid, ptr::null_mut(), 0).map(|_| ()) }
}

impl MachControl {
    const BUF_MAX: usize = 256;
    pub extern "C" fn asdf() -> c_long {
        0
    }
}

pub(crate) struct ThreadId(u64);
pub(crate) struct ThreadHandle(u64);

pub(crate) struct TaskPort(mach_port_t);

pub(crate) struct MachThread {
    id: ThreadId,
    handle: ThreadHandle,
    task: TaskPort,
}

impl MachThread {
    pub(crate) fn new(task: mach_port_t, thread: thread_act_t) -> Result<Self> {
        let identifers = get_thread_info(thread)?;
        let id = ThreadId(identifers.thread_id);
        let handle = ThreadHandle(identifers.thread_handle);
        let task = TaskPort(task);
        Ok(Self { id, handle, task })
    }
}

#[repr(C)]
pub(crate) struct MachMsgRaw {
    header: mach_msg_header_t,
    body: [u8; Self::BUF_MAX],
}

impl MachMsgRaw {
    pub(crate) const BUF_MAX: usize = 256;
    fn new() -> Self {
        Self {
            header: mach_msg_header_t::default(),
            body: [0; Self::BUF_MAX],
        }
    }

    fn as_mut_ptr(&mut self) -> *mut mach_msg_header_t {
        &mut self.header
    }
}

impl Default for MachMsgRaw {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct MachMessage {
    task: task_t,
    thread: MachThread,
    raw_msg: MachMsgRaw,
    msg_len: usize,
}

struct MachExceptionInfo {
    saved_masks: [exception_mask_t; EXC_TYPES_COUNT],
    saved_ports: [mach_port_t; EXC_TYPES_COUNT],
    saved_behaviors: [exception_behavior_t; EXC_TYPES_COUNT],
    saved_flavors: [thread_state_flavor_t; EXC_TYPES_COUNT],
    saved_exc_types_count: mach_msg_type_number_t,
}

impl MachExceptionInfo {
    fn from_task(task: task_t) -> Self {
        let mut saved_masks = [0; EXC_TYPES_COUNT];
        let mut saved_ports = [0; EXC_TYPES_COUNT];
        let mut saved_behaviors = [0; EXC_TYPES_COUNT];
        let mut saved_flavors = [0; EXC_TYPES_COUNT];
        let mut saved_exc_types_count = 0;

        unsafe {
            task_get_exception_ports(
                task,
                EXC_MASK_ALL,
                &mut saved_masks[0],
                &mut saved_exc_types_count,
                &mut saved_ports[0],
                &mut saved_behaviors[0],
                &mut saved_flavors[0],
            );
        }
        Self {
            saved_masks,
            saved_ports,
            saved_behaviors,
            saved_exc_types_count,
            saved_flavors,
        }
    }

    fn len(&self) -> usize {
        self.saved_exc_types_count.try_into().unwrap()
    }

    fn masks(&mut self) -> &mut [exception_mask_t] {
        let len = self.len();
        &mut self.saved_masks[..len]
    }
    fn ports(&mut self) -> &mut [mach_port_t] {
        let len = self.len();
        &mut self.saved_ports[..len]
    }
    fn behaviors(&mut self) -> &mut [exception_behavior_t] {
        let len = self.len();
        &mut self.saved_behaviors[..len]
    }
    fn flavors(&mut self) -> &mut [thread_state_flavor_t] {
        let len = self.len();
        &mut self.saved_flavors[..len]
    }

    unsafe fn masks_ptr_mut(&mut self) -> *mut exception_mask_t {
        &mut self.saved_masks[0]
    }

    unsafe fn ports_ptr_mut(&mut self) -> *mut mach_port_t {
        &mut self.saved_ports[0]
    }

    unsafe fn behaviors_ptr_mut(&mut self) -> *mut exception_behavior_t {
        &mut self.saved_behaviors[0]
    }

    unsafe fn flavors_ptr_mut(&mut self) -> *mut thread_state_flavor_t {
        &mut self.saved_flavors[0]
    }
}

pub(crate) struct MachTask {
    pid: Pid,
    exc_port: mach_port_t,
    task: task_t,
    old_exc_info: MachExceptionInfo,
}

impl MachTask {
    pub fn new(pid: Pid) -> MachTask {
        attach_exc(pid).unwrap();
        let task = get_task_port(pid.into()).unwrap();
        let old_exc_info = MachExceptionInfo::from_task(task);
        let mut exc_port = 0;

        unsafe {
            let mut ret =
                mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut exc_port);
            println!("allocated : {}", ret);

            ret = mach_port_insert_right(
                mach_task_self(),
                exc_port,
                exc_port,
                MACH_MSG_TYPE_MAKE_SEND,
            );

            println!("inserted : {}", ret);

            ret = task_set_exception_ports(
                task,
                EXC_MASK_ALL,
                exc_port,
                (EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES) as i32,
                THREAD_STATE_NONE,
            );
            println!("set exc ports : {}", ret);
            Self {
                pid,
                old_exc_info,
                exc_port,
                task,
            }
        }
    }

    fn task_port(&self) -> mach_port_t {
        self.task
    }

    fn suspend(&mut self) -> Result<()> {
        let kr: KernelRet = unsafe { mach::task::task_suspend(self.task) }.into();
        kr.into()
    }

    fn resume(&mut self) -> Result<()> {
        let kr: KernelRet = unsafe { mach::task::task_resume(self.task) }.into();
        kr.into()
    }
}

impl Drop for MachTask {
    fn drop(&mut self) {
        for i in 0..self.old_exc_info.len() {
            unsafe {
                task_set_exception_ports(
                    self.task,
                    self.old_exc_info.masks()[i],
                    self.old_exc_info.ports()[i],
                    self.old_exc_info.behaviors()[i],
                    self.old_exc_info.flavors()[i],
                );
            }
        }
        unsafe {
            mach_port_deallocate(mach_task_self(), self.exc_port);
        }
        nix::sys::ptrace::kill(self.pid);
    }
}

pub(crate) struct MachProcess {
    child_pid: Pid,
    task: MachTask,
    exc_msgs: Vec<MachMessage>,
    rcv_buf: MachMsgRaw,
    rpl_buf: MachMsgRaw,
}

impl MachProcess {
    pub(crate) fn new(pid: Pid) -> Self {
        let child_pid = pid;
        let task = MachTask::new(pid);
        let exc_msgs = Vec::new();

        Self {
            child_pid,
            task,
            exc_msgs,
            rcv_buf: MachMsgRaw::new(),
            rpl_buf: MachMsgRaw::new(),
        }
    }

    pub(crate) fn mach_msg_receive(&mut self) -> Option<Signal> {
        let asdf = mem::size_of::<mach_msg_header_t>();
        println!("size of msg header = {}", asdf);
        unsafe {
            let mut ret = mach_msg(
                self.rcv_buf.as_mut_ptr(),
                MACH_RCV_MSG,
                0,
                MachMsgRaw::BUF_MAX.try_into().unwrap(),
                self.task.exc_port,
                1,
                MACH_PORT_NULL,
            );
            println!("mach msg : {}", ret);
            println!("suspended task : {}", ret);
            if ret == KERN_SUCCESS {
                ret = mach::task::task_suspend(self.task.task_port());
                let msg_ok = mach_exc_server(self.rcv_buf.as_mut_ptr(), self.rpl_buf.as_mut_ptr());
                if msg_ok == 0 {
                    ret = mach::task::task_resume(self.task.task_port());
                    panic!()
                } else {
                    ret = mach::task::task_resume(self.task.task_port());
                    println!("RESUME : {}", ret);
                    Some(Signal::SIGCHLD)
                }
            } else {
                None
            }
        }
    }
}
