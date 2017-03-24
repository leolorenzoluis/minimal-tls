mod structures;

use std::io::Read;
use std::io::Write;

use structures::ContentType;

pub struct TLS_config<'a> {
	reader : &'a Read,
	writer : &'a Write,
}

fn TLS_init<'a, R : Read, W : Write>(read : &'a R, write : &'a W) -> TLS_config<'a> {
	TLS_config{reader : read, writer : write}
}

// Ideas for functions...
// TLS_start -> handshake and connection setup
// TLS_send -> sends plaintext
// TLS_recieve -> recieves plaintext
// TLS_end -> closes the connection

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
