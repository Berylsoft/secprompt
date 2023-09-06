use std::io::{self, BufRead, Write};

/// Displays a message on the STDOUT
pub fn print_tty(prompt: impl ToString) -> io::Result<()> {
    let mut stdout = io::stdout();
    write!(stdout, "{}", prompt.to_string().as_str())?;
    stdout.flush()?;
    Ok(())
}

/// Reads a password from the TTY
pub fn read_password() -> io::Result<String> {
    let tty = std::fs::File::open("/dev/tty")?;
    let mut reader = io::BufReader::new(tty);

    read_password_from_fd_with_hidden_input(&mut reader)
}

/// Reads a password from a given file descriptor
fn read_password_from_fd_with_hidden_input(
    reader: &mut impl BufRead,
) -> io::Result<String> {
    let mut password = super::SafeString::new();

    reader.read_line(&mut password)?;
    super::fix_line_issues(password.into_inner())
}