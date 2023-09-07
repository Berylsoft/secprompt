use crate::{print_general, read_password_general};
use std::{
    fs::File,
    io::{self, BufReader},
    os::windows::io::FromRawHandle,
};
use windows_sys::{
    core::s,
    Win32::{
        Foundation::{BOOL, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, TRUE},
        Storage::FileSystem::{CreateFileA, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
        System::Console::{
            GetConsoleMode, SetConsoleMode, CONSOLE_MODE, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
        },
    },
};
use zeroize::Zeroizing;

fn open_file(filename: *const u8) -> io::Result<(File, HANDLE)> {
    let handle = unsafe {
        CreateFileA(
            filename,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if handle != INVALID_HANDLE_VALUE {
        Ok((unsafe { File::from_raw_handle(handle as *mut _) }, handle))
    } else {
        Err(io::Error::last_os_error())
    }
}

// We want to be able to read line by line, and we still want backspace to work
const NEW_MODE: CONSOLE_MODE = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;

fn get_mode(handle: HANDLE) -> io::Result<CONSOLE_MODE> {
    let mut mode: CONSOLE_MODE = 0;
    let status: BOOL = unsafe { GetConsoleMode(handle, &mut mode as *mut _) };
    if status == TRUE {
        Ok(mode)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_mode(handle: HANDLE, mode: CONSOLE_MODE) -> io::Result<()> {
    let status: BOOL = unsafe { SetConsoleMode(handle, mode) };
    if status == TRUE {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Displays a message on the TTY
pub fn print_tty(prompt: &str) -> io::Result<()> {
    let (mut stream, _) = open_file(s!("CONOUT$"))?;
    print_general(&mut stream, prompt)
}

/// Reads a password from the TTY
pub fn read_password() -> io::Result<Zeroizing<String>> {
    let (stream, handle) = open_file(s!("CONIN$"))?;
    let mut reader = BufReader::new(stream);

    let old_mode = get_mode(handle)?;

    set_mode(handle, NEW_MODE)?;

    let read_result = read_password_general(&mut reader);

    // Newline for windows which otherwise prints on the same line.
    println!();

    let password = read_result?;

    let _ = set_mode(handle, old_mode);

    Ok(password)
}
