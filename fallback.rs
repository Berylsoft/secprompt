use crate::{print_general, read_password_general};
use std::{
    fs::File,
    io::{self, BufReader},
};
use zeroize::Zeroizing;

pub fn print_tty(prompt: &str) -> io::Result<()> {
    let mut stream = io::stdout();
    print_general(&mut stream, prompt)
}

pub fn read_password() -> io::Result<Zeroizing<String>> {
    let stream = File::open("/dev/tty")?;
    let mut reader = BufReader::new(stream);
    read_password_general(&mut reader)
}
