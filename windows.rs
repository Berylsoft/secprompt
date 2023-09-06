use std::io::{self, BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, SetConsoleMode, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
};
use zeroize::Zeroizing;

/// Displays a message on the TTY
pub fn print_tty(prompt: impl ToString) -> io::Result<()> {
    let handle = unsafe {
        CreateFileA(
            b"CONOUT$\x00".as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    let mut stream = unsafe { std::fs::File::from_raw_handle(handle as *mut _) };

    stream
        .write_all(prompt.to_string().as_str().as_bytes())
        .and_then(|_| stream.flush())
}

struct HiddenInput {
    mode: u32,
    handle: HANDLE,
}

impl HiddenInput {
    fn new(handle: HANDLE) -> io::Result<HiddenInput> {
        let mut mode = 0;

        // Get the old mode so we can reset back to it when we are done
        if unsafe { GetConsoleMode(handle, &mut mode as *mut _) } == 0 {
            return Err(io::Error::last_os_error());
        }

        // We want to be able to read line by line, and we still want backspace to work
        let new_mode_flags = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
        if unsafe { SetConsoleMode(handle, new_mode_flags) } == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(HiddenInput { mode, handle })
    }
}

impl Drop for HiddenInput {
    fn drop(&mut self) {
        // Set the the mode back to normal
        unsafe {
            SetConsoleMode(self.handle, self.mode);
        }
    }
}

/// Reads a password from the TTY
pub fn read_password() -> io::Result<Zeroizing<String>> {
    let handle = unsafe {
        CreateFileA(
            b"CONIN$\x00".as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    let mut stream = BufReader::new(unsafe { std::fs::File::from_raw_handle(handle as *mut _) });
    read_password_from_handle_with_hidden_input(&mut stream, handle)
}

/// Reads a password from a given file handle
fn read_password_from_handle_with_hidden_input(
    reader: &mut impl BufRead,
    handle: HANDLE,
) -> io::Result<Zeroizing<String>> {
    let mut password = Zeroizing::<String>::default();

    let hidden_input = HiddenInput::new(handle)?;

    let reader_return = reader.read_line(&mut password);

    // Newline for windows which otherwise prints on the same line.
    println!();

    if reader_return.is_err() {
        return Err(reader_return.unwrap_err());
    }

    std::mem::drop(hidden_input);

    super::fix_line_issues(password)
}
