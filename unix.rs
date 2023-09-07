use crate::{print_general, read_password_general};
use libc::{c_int, tcgetattr, tcsetattr, termios, ECHO, ECHONL, TCSANOW};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader},
    mem::MaybeUninit,
    os::unix::io::AsRawFd,
};
use zeroize::Zeroizing;

#[inline]
fn cvt(ret: c_int) -> io::Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn change_mode(mut mode: termios) -> termios {
    // Hide the password. This is what makes this function useful.
    mode.c_lflag &= !ECHO;

    // But don't hide the NL character when the user hits ENTER.
    mode.c_lflag |= ECHONL;

    mode
}

fn get_mode(fd: c_int) -> io::Result<termios> {
    let mut term = MaybeUninit::<termios>::uninit();
    cvt(unsafe { tcgetattr(fd, term.as_mut_ptr()) })?;
    Ok(unsafe { term.assume_init() })
}

fn set_mode(fd: c_int, mode: &termios) -> io::Result<()> {
    cvt(unsafe { tcsetattr(fd, TCSANOW, termios.as_ptr()) })
}

/// Displays a message on the TTY
pub fn print_tty(prompt: &str) -> io::Result<()> {
    let mut stream = OpenOptions::new().write(true).open("/dev/tty")?;
    print_general(&mut stream, prompt)
}

/// Reads a password from the TTY
pub fn read_password() -> io::Result<Zeroizing<String>> {
    let stream = File::open("/dev/tty")?;
    let fd = stream.as_raw_fd();
    let mut reader = BufReader::new(stream);

    let old_mode = get_mode(fd)?;

    let new_mode = change_mode(old_mode);
    set_mode(fd, &new_mode)?;

    let password = read_password_general(&mut reader)?;

    let _ = set_mode(fd, &old_mode);

    Ok(password)
}
