mod structures;

use std::io::Read;
use std::io::Write;

use structures::{Handshake, ContentType, TLSPlaintext, TLSState, TLSError};

pub struct TLS_config<'a> {
	reader : &'a Read,
	writer : &'a Write,
	state : TLSState,

	// Cache any remaining bytes in a TLS record
	recordcache: Vec<u8>
}

fn TLS_init<'a, R : Read, W : Write>(read : &'a R, write : &'a W) -> TLS_config<'a> {
	TLS_config{reader : read, writer : write, state : TLSState::Start, recordcache : Vec::new() }
}

impl<'a> TLS_config<'a> {

	fn get_next_message(&self) -> Result<TLSPlaintext, TLSError> {

		// First check if we have any cached data from the last record
		if self.recordcache.len() > 0 {
			// Try to parse from existing cached message
		} else {
			// Grab another TLS record object

			// Parse the first TLSPlaintext

			// Cache the rest
		}

		// TODO: Remove
		Err(TLSError::InvalidMessage)
	}

	fn read_handshake(&self) -> Result<TLSPlaintext, TLSError> {
		let plaintext : TLSPlaintext = try!(self.get_next_message());

		// TODO: Actually parse the handshake object here, don't just return a TLSPlaintext

		match plaintext.ctype {
			ContentType::Handshake => Ok(plaintext),
			_ => Err(TLSError::InvalidMessage)
		}
	}

	fn transition(&self) -> Result<&TLS_config, TLSError> {
		match self.state {
			TLSState::Start => {
				// Try to recieve the ClientHello
				let plaintext : TLSPlaintext = try!(self.read_handshake());
				Err(TLSError::InvalidState)
			},
			TLSState::RecievedClientHello => {
				Err(TLSError::InvalidState)
			},
			_ => {
				Err(TLSError::InvalidState)
			}
		}
	}

	fn TLS_start(&self) -> Result<u8, TLSError>{

		// Ensure we are in the "start" state
		if self.state != TLSState::Start {
			return Err(TLSError::InvalidState)
		}

		/*
			We want to transition through the TLS state machine until we
			encounter an error, or complete the handshake
		*/
		loop {
			match self.transition() {
				Err(e) => return Err(e),
				_ => {
					if self.state == TLSState::Connected {
						break
					}
				}
			}
		};

		// If all goes well, we should be in the "connected" state
		if self.state != TLSState::Connected {
			return Err(TLSError::InvalidState)
		}

		Ok(0)
	}
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
