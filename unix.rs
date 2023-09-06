use libc::{c_int, tcsetattr, termios, ECHO, ECHONL, TCSANOW};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    mem::MaybeUninit,
    os::unix::io::AsRawFd,
};
use zeroize::Zeroizing;

/// Displays a message on the TTY
pub fn print_tty(prompt: &str) -> io::Result<()> {
    let mut stream = OpenOptions::new().write(true).open("/dev/tty")?;
    stream
        .write_all(prompt.as_bytes())
        .and_then(|_| stream.flush())
}

struct HiddenInput {
    fd: i32,
    term_orig: termios,
}

impl HiddenInput {
    fn new(fd: i32) -> io::Result<HiddenInput> {
        // Make two copies of the terminal settings. The first one will be modified
        // and the second one will act as a backup for when we want to set the
        // terminal back to its original state.
        let mut term = safe_tcgetattr(fd)?;
        let term_orig = safe_tcgetattr(fd)?;

        // Hide the password. This is what makes this function useful.
        term.c_lflag &= !ECHO;

        // But don't hide the NL character when the user hits ENTER.
        term.c_lflag |= ECHONL;

        // Save the settings for now.
        io_result(unsafe { tcsetattr(fd, TCSANOW, &term) })?;

        Ok(HiddenInput { fd, term_orig })
    }
}

impl Drop for HiddenInput {
    fn drop(&mut self) {
        // Set the the mode back to normal
        unsafe {
            tcsetattr(self.fd, TCSANOW, &self.term_orig);
        }
    }
}

/// Turns a C function return into an IO Result
fn io_result(ret: c_int) -> io::Result<()> {
    match ret {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

fn safe_tcgetattr(fd: c_int) -> io::Result<termios> {
    let mut term = MaybeUninit::<termios>::uninit();
    io_result(unsafe { libc::tcgetattr(fd, term.as_mut_ptr()) })?;
    Ok(unsafe { term.assume_init() })
}

/// Reads a password from the TTY
pub fn read_password() -> io::Result<Zeroizing<String>> {
    let tty = File::open("/dev/tty")?;
    let fd = tty.as_raw_fd();
    let mut reader = BufReader::new(tty);

    read_password_from_fd_with_hidden_input(&mut reader, fd)
}

/// Reads a password from a given file descriptor
fn read_password_from_fd_with_hidden_input(
    reader: &mut impl BufRead,
    fd: i32,
) -> io::Result<Zeroizing<String>> {
    let mut password = Zeroizing::<String>::default();

    let hidden_input = HiddenInput::new(fd)?;

    reader.read_line(&mut password)?;

    let _ = hidden_input;

    super::fix_line_issues(password)
}
