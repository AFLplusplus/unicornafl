use std::{
    io::{PipeReader, PipeWriter},
    os::fd::{AsFd, AsRawFd},
};

use libafl_bolts::os::{ChildHandle, ForkResult};
use libafl_targets::ForkserverParent;
use log::{error, trace};
use nix::{
    sys::signal::{SigHandler, Signal},
    unistd::Pid,
};

use crate::{executor::UnicornAflExecutor, uc_afl_ret};

fn write_to_fd(fd: impl AsFd, message: &[u8]) -> Result<(), uc_afl_ret> {
    let bytes_written =
        nix::unistd::write(fd, message).map_err(|_| uc_afl_ret::UC_AFL_RET_ERROR)?;
    if bytes_written != message.len() {
        return Err(uc_afl_ret::UC_AFL_RET_ERROR);
    }
    Ok(())
}
pub(crate) fn write_u32_to_fd(fd: impl AsFd, message: u32) -> Result<(), uc_afl_ret> {
    write_to_fd(fd, &message.to_ne_bytes())
}
pub(crate) fn write_u64_to_fd(fd: impl AsFd, message: u64) -> Result<(), uc_afl_ret> {
    write_to_fd(fd, &message.to_ne_bytes())
}

fn read_from_fd(fd: impl AsFd, message: &mut [u8]) -> Result<(), uc_afl_ret> {
    let bytes_read = nix::unistd::read(fd.as_fd().as_raw_fd(), message)
        .map_err(|_| uc_afl_ret::UC_AFL_RET_ERROR)?;
    if bytes_read != message.len() {
        return Err(uc_afl_ret::UC_AFL_RET_ERROR);
    }
    Ok(())
}
pub(crate) fn read_u32_from_fd(fd: impl AsFd) -> Result<u32, uc_afl_ret> {
    let mut buf = [0u8; 4];
    read_from_fd(fd, &mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}
pub(crate) fn read_u64_from_fd(fd: impl AsFd) -> Result<u64, uc_afl_ret> {
    let mut buf = [0u8; 8];
    read_from_fd(fd, &mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}

/// Messages from unicornafl child to parent
pub(crate) mod afl_child_ret {
    pub(crate) type ChildRet = u32;
    /// Current execution done without any interestring findings.
    /// Wait for parent to fire next execution
    pub(crate) const NEXT: ChildRet = 0;
    /// Current execution done with a crash found
    pub(crate) const FOUND_CRASH: ChildRet = 1;
    /// Edge generation event. This is always followed by generated edge PC.
    ///
    /// This will never be sent when child finished its execution.
    pub(crate) const TSL_REQUEST: ChildRet = 2;
    /// The child process has exited.
    ///
    /// This will never be sent from child to parent. Instead, this is a phantom
    /// state used for forkserver parent state management.
    pub(crate) const EXITED: ChildRet = 3;
    /// The child process found a crash, and is the last execution of one persistent loop.
    ///
    /// This is used for indicating the parent that it should not expect the child is in
    /// persistent loop any more.
    pub(crate) const FOUND_CRASH_AND_EXITED: ChildRet = 4;
}

type AflChildRet = afl_child_ret::ChildRet;

/// Forkserver parent for UnicornAFL
pub struct UnicornAflForkserverParent<'a, D, OT, H>
where
    D: 'a,
{
    /// Executor.
    ///
    /// You could drop the parent and take ownership back when parent
    /// returns from [`start_forkserver`][libafl_targets::start_forkserver], which
    /// indicates that it is the child process, and parent is useless anymore (the
    /// owned resources have been transferred to the executor itself).
    pub(crate) executor: UnicornAflExecutor<'a, D, OT, H>,
    child_pipe_r: Option<PipeReader>,
    child_pipe_w: Option<PipeWriter>,
    parent_pipe_r: Option<PipeReader>,
    parent_pipe_w: Option<PipeWriter>,
    last_child_pid: Option<i32>,
    last_child_ret: AflChildRet,
    old_sigchld_handler: Option<SigHandler>,
    wifsignaled: i32,
}

impl<'a, D, OT, H> UnicornAflForkserverParent<'a, D, OT, H>
where
    D: 'a,
{
    /// Create a new forkserver parent
    pub fn new(executor: UnicornAflExecutor<'a, D, OT, H>) -> Self {
        Self {
            executor,
            child_pipe_r: None,
            child_pipe_w: None,
            parent_pipe_r: None,
            parent_pipe_w: None,
            last_child_pid: None,
            last_child_ret: afl_child_ret::EXITED,
            old_sigchld_handler: None,
            wifsignaled: get_valid_wifsignaled(),
        }
    }
}

impl<'a, D, OT, H> ForkserverParent for UnicornAflForkserverParent<'a, D, OT, H>
where
    D: 'a,
{
    fn pre_fuzzing(&mut self) -> Result<(), libafl::Error> {
        let old_sigchld_handler =
            (unsafe { nix::sys::signal::signal(Signal::SIGCHLD, SigHandler::SigDfl) })
                .inspect_err(|_| {
                    error!("Fail to swap signal handler for SIGCHLD.");
                })?;
        self.old_sigchld_handler = Some(old_sigchld_handler);
        Ok(())
    }

    fn handle_child_requests(&mut self) -> Result<i32, libafl::Error> {
        let child_pipe_r = self.child_pipe_r.as_ref().unwrap().as_fd();
        self.last_child_ret = loop {
            let Ok(child_msg) = read_u32_from_fd(child_pipe_r) else {
                break afl_child_ret::EXITED;
            };

            trace!("Get a child_msg={child_msg}");

            if child_msg == afl_child_ret::NEXT
                || child_msg == afl_child_ret::FOUND_CRASH
                || child_msg == afl_child_ret::EXITED
                || child_msg == afl_child_ret::FOUND_CRASH_AND_EXITED
            {
                break child_msg;
            } else if child_msg == afl_child_ret::TSL_REQUEST {
                let Ok(pc) = read_u64_from_fd(child_pipe_r) else {
                    error!("Fail to read child tsl request.");
                    break afl_child_ret::EXITED;
                };

                if self.executor.uc.ctl_request_cache(pc, None).is_ok() {
                    trace!("TB is cached at 0x{pc:x}");
                } else {
                    error!("Failed to cache the TB at 0x{pc:x}");
                }
            } else {
                error!("Unexpected response by child! {child_msg}. Please report this as bug for unicornafl.
    Expected one of {{AFL_CHILD_NEXT: {}, AFL_CHILD_FOUND_CRASH: {}, AFL_CHILD_TSL_REQUEST: {}, AFL_CHILD_EXITED: {}, AFL_CHILD_FOUND_CRASH_AND_EXITED: {}}}.", afl_child_ret::NEXT, afl_child_ret::FOUND_CRASH, afl_child_ret::TSL_REQUEST, afl_child_ret::EXITED, afl_child_ret::FOUND_CRASH_AND_EXITED);
            }
        };

        match self.last_child_ret {
            afl_child_ret::NEXT => {
                // Child asks for next in persistent mode
                // This status tells AFL we are not crashed.
                Ok(0)
            }
            afl_child_ret::FOUND_CRASH => {
                // WIFSIGNALED(wifsignaled) == 1 -> tells AFL the child crashed
                // (even though it's still alive for persistent mode)
                Ok(self.wifsignaled)
            }
            afl_child_ret::FOUND_CRASH_AND_EXITED => {
                if unsafe {
                    nix::libc::waitpid(
                        *self.last_child_pid.as_ref().unwrap(),
                        std::ptr::null_mut(),
                        0,
                    )
                } < 0
                {
                    // Zombie Child could not be collected. Scary!
                    error!("[!] The child's exit code could not be determined.");
                    return Err(libafl::Error::illegal_state("waitpid"));
                }
                // WIFSIGNALED(wifsignaled) == 1 -> tells AFL the child crashed
                // (even though it's still alive for persistent mode)
                Ok(self.wifsignaled)
            }
            afl_child_ret::EXITED => {
                // Tell parent(unicornafl) to fork a new child.
                self.last_child_ret = afl_child_ret::EXITED;
                // If child exited, get and relay exit status to parent through waitpid
                let mut status = 0i32;
                if unsafe {
                    nix::libc::waitpid(*self.last_child_pid.as_ref().unwrap(), &mut status, 0)
                } < 0
                {
                    // Zombie Child could not be collected. Scary!
                    error!("[!] The child's exit code could not be determined.");
                    return Err(libafl::Error::illegal_state("waitpid"));
                }

                Ok(status)
            }
            _ => unreachable!(),
        }
    }

    fn spawn_child(&mut self, was_killed: bool) -> Result<ForkResult, libafl::Error> {
        // If we stopped the child in persistent mode, but there was a race
        // condition and afl-fuzz already issued SIGKILL, write off the old
        // process.
        if self.last_child_ret != afl_child_ret::EXITED && was_killed {
            error!("Child was killed by AFL in the meantime.");

            self.last_child_ret = afl_child_ret::EXITED;
            if let Some(child_pid) = self.last_child_pid.take() {
                nix::sys::wait::waitpid(Pid::from_raw(child_pid), None).inspect_err(|_| {
                    error!("Error waiting for child");
                })?;
            }
        }

        trace!("Spawn a child, last: {:?}", &self.last_child_ret);
        if self.last_child_ret == afl_child_ret::EXITED {
            // Child dead. Establish new a channel with child to grab
            // translation commands. We'll read from child_pipe_r,
            // child will write to child_pipe_w.
            let (child_pipe_r, child_pipe_w) = std::io::pipe().inspect_err(|_| {
                error!("[!] Error creating pipe to child");
            })?;
            // The re-assignment will close the previously-unclosed pipe ends
            self.child_pipe_r = Some(child_pipe_r);
            self.child_pipe_w = Some(child_pipe_w);
            let (parent_pipe_r, parent_pipe_w) = std::io::pipe().inspect_err(|_| {
                error!("[!] Error creating pipe to parent");
            })?;
            self.parent_pipe_r = Some(parent_pipe_r);
            self.parent_pipe_w = Some(parent_pipe_w);

            trace!("Going to fork a new child!");
            // Create a clone of our process.
            let fork_result = (unsafe { libafl_bolts::os::fork() }).inspect_err(|_| {
                error!("[!] Could not fork");
            })?;

            // In child process: close fds, resume execution.
            match &fork_result {
                ForkResult::Child => {
                    // New Child
                    (unsafe {
                        nix::sys::signal::signal(
                            Signal::SIGCHLD,
                            self.old_sigchld_handler.take().unwrap(),
                        )
                    })
                    .inspect_err(|_| {
                        error!("Fail to restore signal handler for SIGCHLD.");
                    })?;
                    self.child_pipe_r = None;
                    self.parent_pipe_w = None;
                    // Forward owned fd to executor to make it alive
                    self.executor.uc.get_data_mut().child_pipe_w = self.child_pipe_w.take();
                    self.executor.uc.get_data_mut().parent_pipe_r = self.parent_pipe_r.take();
                }
                ForkResult::Parent(child_pid) => {
                    // parent for new child

                    // If we don't close this in parent, we don't get notified
                    // on afl_child_pipe once child is gone
                    self.child_pipe_w = None;
                    self.parent_pipe_r = None;
                    self.last_child_pid = Some(child_pid.pid);
                }
            }
            Ok(fork_result)
        } else {
            // parent, in persistent mode
            let child_pid = ChildHandle {
                pid: *self.last_child_pid.as_ref().unwrap(),
            };

            // Special handling for persistent mode: if the child is alive
            // but currently stopped, simply restart it with a write to
            // afl_parent_pipe. In case we fuzz using shared map, use this
            // method to forward the size of the current testcase to the
            // child without cost.
            if write_u32_to_fd(self.parent_pipe_w.as_ref().unwrap().as_fd(), 0).is_err() {
                self.last_child_ret = afl_child_ret::EXITED;
                return self.spawn_child(was_killed);
            }

            Ok(ForkResult::Parent(child_pid))
        }
    }
}

/// Try to get a valid status which could make `WIFSIGNALED` return `true`.
fn get_valid_wifsignaled() -> i32 {
    let mut status = 0;

    while !nix::libc::WIFSIGNALED(status) {
        status += 1;
    }

    status
}
