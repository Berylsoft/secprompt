#[cfg_attr(target_family = "unix", path = "unix.rs")]
#[cfg_attr(target_family = "windows", path = "windows.rs")]
#[cfg_attr(target_family = "wasm", path = "fallback.rs")]
mod platform;
pub use platform::*;

use std::io::{self, BufRead, Write};
pub use zeroize;
use zeroize::Zeroizing;

/// Normalizes the return of `read_line()` in the context of a CLI application
pub fn fix_line_issues(mut line: Zeroizing<String>) -> io::Result<Zeroizing<String>> {
    if !line.ends_with('\n') {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }

    // Remove the \n from the line.
    line.pop();

    // Remove the \r from the line if present
    if line.ends_with('\r') {
        line.pop();
    }

    // Ctrl-U should remove the line in terminals
    if line.contains('\x15') {
        line = match line.rfind('\x15') {
            Some(last_ctrl_u_index) => line[last_ctrl_u_index + 1..].to_owned().into(),
            None => line,
        };
    }

    Ok(line)
}

/// Prints a message to a writer
pub fn print_general(stream: &mut impl Write, prompt: &str) -> io::Result<()> {
    stream.write_all(prompt.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// Reads a password from anything that implements BufRead
pub fn read_password_general(reader: &mut impl BufRead) -> io::Result<Zeroizing<String>> {
    let mut password = Zeroizing::<String>::default();
    reader.read_line(&mut password)?;
    fix_line_issues(password)
}

/// Prompts on a writer and then reads a password from anything that implements BufRead
pub fn prompt_password_general(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    prompt: &str,
) -> io::Result<Zeroizing<String>> {
    print_general(writer, prompt)?;
    read_password_general(reader)
}

/// Prompts on the TTY and then reads a password from TTY
pub fn prompt_password(prompt: &str) -> io::Result<Zeroizing<String>> {
    print_tty(prompt)?;
    read_password()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    fn mock_input_crlf() -> Cursor<&'static [u8]> {
        Cursor::new(&b"A mocked response.\r\nAnother mocked response.\r\n"[..])
    }

    fn mock_input_lf() -> Cursor<&'static [u8]> {
        Cursor::new(&b"A mocked response.\nAnother mocked response.\n"[..])
    }

    #[test]
    fn can_read_from_redirected_input_many_times() {
        let mut reader_crlf = mock_input_crlf();

        let response = super::read_password_general(&mut reader_crlf).unwrap();
        assert_eq!(response.as_str(), "A mocked response.");
        let response = super::read_password_general(&mut reader_crlf).unwrap();
        assert_eq!(response.as_str(), "Another mocked response.");

        let mut reader_lf = mock_input_lf();
        let response = super::read_password_general(&mut reader_lf).unwrap();
        assert_eq!(response.as_str(), "A mocked response.");
        let response = super::read_password_general(&mut reader_lf).unwrap();
        assert_eq!(response.as_str(), "Another mocked response.");
    }
}
