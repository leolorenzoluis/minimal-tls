mod structures;
mod serialization;
mod extensions;

use std::io::Read;
use std::io::Write;
use serialization::TLSToBytes;
use structures::{Random, ClientHello, CipherSuite, Extension, ContentType, HandshakeMessage, ServerHello, TLSPlaintext, TLSState, TLSError};

// Misc. functions
pub fn bytes_to_u16(bytes : &[u8]) -> u16 {
	((bytes[0] as u16) << 8) | (bytes[1] as u16)
}

// Each connection needs to have its own TLS_config object
pub struct TLS_config<'a> {
	reader : &'a mut Read,
	writer : &'a mut Write,

	state : TLSState,

	// Boolean if we have sent a HelloRetryRequest
	sent_hello_retry : bool,

	// Cache any remaining bytes in a TLS record
    ctypecache : ContentType,
	recordcache: Vec<u8>
}

pub fn tls_init<'a, R : Read, W : Write>(read : &'a mut R, write : &'a mut W) -> TLS_config<'a> {
	TLS_config{reader : read, writer : write, state : TLSState::Start,
				sent_hello_retry : false,
				ctypecache : ContentType::InvalidReserved, recordcache : Vec::new() }
}

#[allow(unused_variables)]
#[allow(dead_code)]
impl<'a> TLS_config<'a> {
    /*
        Read implements reading directly from the TLSPlaintext streams.
        It will handle retrieving a new TLSPlaintext in the case of fragmentation
    */
    fn read(&mut self, dest: &mut [u8]) -> Result<usize, TLSError> {
        if dest.len() > self.recordcache.len() {
            // Grab another fragment
            let tlsplaintext : TLSPlaintext = try!(self.get_next_tlsplaintext());
            self.ctypecache = tlsplaintext.ctype;
            self.recordcache.extend(tlsplaintext.fragment);
        }

        let len = dest.len();
        dest.clone_from_slice(self.recordcache.drain(0..len).collect::<Vec<u8>>().as_slice());

        return Ok(len)
    }

    fn read_u8(&mut self) -> Result<u8, TLSError> {
        if self.recordcache.len() < 1 {
            // Grab another fragment
            let tlsplaintext : TLSPlaintext = try!(self.get_next_tlsplaintext());
            self.ctypecache = tlsplaintext.ctype;
            self.recordcache.extend(tlsplaintext.fragment);
        }

        Ok(self.recordcache.remove(0))
    }

    fn read_u16(&mut self) -> Result<u16, TLSError> {
        if self.recordcache.len() < 2 {
            // Grab another fragment
            let tlsplaintext : TLSPlaintext = try!(self.get_next_tlsplaintext());
            self.ctypecache = tlsplaintext.ctype;
            self.recordcache.extend(tlsplaintext.fragment);
        }

        let first = self.recordcache.remove(0);
        let second = self.recordcache.remove(1);
        Ok(((first as u16) << 8) | (second as u16))
    }

    fn drain_recordcache(&mut self) {
        self.recordcache.clear()
    }

    fn fill_recordcache(&mut self) -> Result<(), TLSError> {
        // Grab another fragment
        let tlsplaintext : TLSPlaintext = try!(self.get_next_tlsplaintext());
        self.ctypecache = tlsplaintext.ctype;
        self.recordcache.extend(tlsplaintext.fragment);
        Ok(())
    }

    fn create_tlsplaintext(&mut self, contenttype: ContentType, data: &Vec<u8>) -> Result<TLSPlaintext, TLSError> {
    	Err(TLSError::InvalidMessage)
    }

    fn send_tlsplaintext(&mut self, tlsplaintext : TLSPlaintext) -> Result<(), TLSError> {
    	let data : Vec<u8> = tlsplaintext.to_bytes();
    	self.writer.write_all(data.as_slice()).or(Err(TLSError::ReadError))
    }

	fn get_next_tlsplaintext(&mut self) -> Result<TLSPlaintext, TLSError> {
		// Try to read TLSPlaintext header
		let mut buffer : [u8; 5] = [0; 5];
		try!(self.reader.read_exact(&mut buffer).or(Err(TLSError::ReadError)));

		// Match content type (is there a better way to do this in Rust stable?)
		let contenttype : ContentType = match buffer[0] {
			0  => ContentType::InvalidReserved,
			20 => ContentType::ChangeCipherSpecReserved,
			21 => ContentType::Alert,
			22 => ContentType::Handshake,
			23 => ContentType::ApplicationData,
			_  => return Err(TLSError::InvalidHandshakeError)
		};

		// Match legacy protocol version
		let legacy_version = bytes_to_u16(&buffer[1..3]);
		if legacy_version != 0x0301 {
			return Err(TLSError::InvalidHandshakeError)
		}

		// Make sure length is less than 2^14-1
		let length = bytes_to_u16(&buffer[3..5]);
		if length >= 16384 {
			return Err(TLSError::InvalidHandshakeError)
		}

		// Read the remaining data from the buffer
		let mut data = Vec::with_capacity(length as usize);
		try!(self.reader.read_exact(data.as_mut_slice()).or(Err(TLSError::ReadError)));

        /*
            FIXME: Check if we have received a TLS Alert message here. That should always
            warrant returning an error to the caller
        */

		Ok(TLSPlaintext{ctype: contenttype, legacy_record_version: legacy_version, length: length, fragment: data})
	}

	fn process_ciphersuites(&mut self, data : &[u8]) -> Result<Vec<CipherSuite>, TLSError> {
        let mut ret : Vec<CipherSuite> = Vec::new();
        let mut iter = data.iter();

        loop {
            let first = iter.next();
            if first.is_none() {
                break
            }
            let first = first.unwrap();
            let second = iter.next().unwrap();
            ret.push(match ((*first as u16) << 8) | (*second as u16) {
                0x1301 => CipherSuite::TLS_AES_128_GCM_SHA256,
                0x1302 => CipherSuite::TLS_AES_256_GCM_SHA384,
                0x1303 => CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                0x1304 => CipherSuite::TLS_AES_128_CCM_SHA256,
                0x1305 => CipherSuite::TLS_AES_128_CCM_8_SHA256,
                _ => return Err(TLSError::InvalidHandshakeError)
            });
        }
	    Ok(ret)
    }

	fn process_extensions(&mut self, data : &[u8]) -> Result<Vec<Extension>, TLSError> {

        let mut ret : Vec<Extension> = Vec::new();
        let mut iter = data.iter();

        while let Some(first) = iter.next() {
            let second = iter.next().unwrap();
            ret.push(match ((*first as u16) << 8) | (*second as u16) {
    			10 => try!(Extension::parse_supported_groups(&mut iter)),
    			13 => try!(Extension::parse_signature_algorithms(&mut iter)),
    			40 => try!(Extension::parse_keyshare(&mut iter)),
    			41 => try!(Extension::parse_preshared_key(&mut iter)),
    			42 => try!(Extension::parse_earlydata(&mut iter)),
    			43 => try!(Extension::parse_supported_versions(&mut iter)),
    			44 => try!(Extension::parse_cookie(&mut iter)),
    			45 => try!(Extension::parse_psk_key_exchange_modes(&mut iter)),
    			47 => try!(Extension::parse_certificate_authorities(&mut iter)),
    			48 => try!(Extension::parse_oldfilters(&mut iter)),
                _ => return Err(TLSError::InvalidHandshakeError)
            });
        }

		Err(TLSError::InvalidState)
	}

	fn read_clienthello(&mut self) -> Result<ClientHello, TLSError> {
        // Fill our cache before we start reading
        self.drain_recordcache();
        try!(self.fill_recordcache());

        // Make sure we are dealing with a Handshake TLSPlaintext
        if self.ctypecache != ContentType::Handshake {
            return Err(TLSError::InvalidMessage)
        }

        // Grab our legacy version
        let legacy_version: u16 = try!(self.read_u16());
        if legacy_version != 0x0303 {
            return Err(TLSError::InvalidHandshakeError)
        }

        // The client random must be exactly 32 bytes
        let mut random : Random = [0; 32];
        try!(self.read(&mut random));

        // Legacy session ID can be 0-32 bytes
        let lsi_length : usize = try!(self.read_u8()) as usize;
        if lsi_length > 32{
            return Err(TLSError::InvalidHandshakeError)
        }

        let mut legacy_session_id = vec![0; lsi_length];
        try!(self.read(legacy_session_id.as_mut_slice()));

        // Read in the list of valid cipher suites
        // In reality, for TLS 1.3, there are only 5 valid cipher suites, so this list
        // should never have more than 5 elements (10 bytes) in it.
        let cslist_length : usize = try!(self.read_u16()) as usize;
        if cslist_length < 2 || cslist_length > (2^16 - 2) || cslist_length % 2 != 0 {
            return Err(TLSError::InvalidHandshakeError)
        }

        // Process the list of ciphersuites -- in particular, minimal-TLS doesn't support the full list
        let mut cipher_suites : Vec<u8> = vec![0; cslist_length];
        try!(self.read(cipher_suites.as_mut_slice()));

        // Read in legacy compression methods (should just be null compression)
        let comp_length = try!(self.read_u8()) as usize;
        if comp_length != 1 {
            return Err(TLSError::InvalidHandshakeError)
        }

        // 0x00 is null compression
        if try!(self.read_u8()) != 0x00 {
            return Err(TLSError::InvalidHandshakeError)
        }

        // Parse ClientHello extensions
        let ext_length = try!(self.read_u16()) as usize;
        if ext_length < 8 || ext_length > 2^16-1 {
            return Err(TLSError::InvalidHandshakeError)
        }

        let mut extensions : Vec<u8> = vec![0; ext_length];
        // TODO: If there is a pre_shared_key extension, it must be the last
        // extension in the ClientHello
        try!(self.read(extensions.as_mut_slice()));

        Ok(ClientHello{
            legacy_version: legacy_version,
            random: random,
            legacy_session_id: legacy_session_id,
            cipher_suites: try!(self.process_ciphersuites(cipher_suites.as_slice())),
            legacy_compression_methods: vec![0],
            extensions: try!(self.process_extensions(extensions.as_slice()))
        })
	}

	fn negotiate_ciphersuite(&mut self, ciphersuites : &Vec<CipherSuite>) -> Result<CipherSuite, TLSError> {
		// We only support one ciphersuite - TLS_CHACHA20_POLY1305_SHA256

		if !ciphersuites.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256) {
			return Err(TLSError::UnsupportedCipherSuite)
		}

		return Ok(CipherSuite::TLS_CHACHA20_POLY1305_SHA256)
	}

	// FIXME: Implement extension validation logic here
	// Must have "supported_versions"
	// Must have either "key_share" or "pre_shared_key"
	fn validate_extensions(&mut self, clienthello : &ClientHello) -> Result<Vec<Extension>, TLSError> {
		Err(TLSError::InvalidClientHelloExtensions)
	}

	// FIXME: Have to look up how to get high quality rng on every platform
	fn gen_server_random(&mut self) -> Result<[u8; 32], TLSError> {
		Ok([0; 32])
	}

	fn negotiate_serverhello(&mut self, clienthello: &ClientHello) -> Result<HandshakeMessage, TLSError> {
        // Validate the client legacy version
        if clienthello.legacy_version != 0x0303 {
            return Err(TLSError::InvalidClientHello)
        }

        // Choose a cipher suite
        let ciphersuite = try!(self.negotiate_ciphersuite(&clienthello.cipher_suites));

        // Make sure we only have null compression sent
        if clienthello.legacy_compression_methods.len() != 1 ||
            clienthello.legacy_compression_methods[0] != 0x00 {
                return Err(TLSError::InvalidClientHello)
        }

        // Go through extensions and figure out which replies we need to send
        // TODO: It's possible that we decide to return a HelloRetryRequest here,
        // so we should handle that
        let extensions : Vec<Extension> = try!(self.validate_extensions(&clienthello));

        Ok(HandshakeMessage::ServerHello(ServerHello{
            version : 0x0304, random: try!(self.gen_server_random()),
            cipher_suite: ciphersuite, extensions : extensions}))
	}

	fn send_message(&mut self, messagequeue : Vec<HandshakeMessage>) -> Result<(), TLSError> {
		if messagequeue.len() > 0 {
			let mut data : Vec<u8> = Vec::new();

			// Loop over all messages and serialize them
			for x in &messagequeue {
				let ret = x.to_bytes();
				if data.len() + ret.len() > 16384 {
					// Flush the existing messages, then continue
					let tlsplaintext = try!(self.create_tlsplaintext(ContentType::Handshake, &data));
					try!(self.send_tlsplaintext(tlsplaintext));
				}
				data.extend(ret)
			}

			// Flush any remaining messages
			let tlsplaintext = try!(self.create_tlsplaintext(ContentType::Handshake, &data));
			try!(self.send_tlsplaintext(tlsplaintext));
		}
		Ok(())
	}

	fn transition(&mut self, hs_message : HandshakeMessage) -> Result<HandshakeMessage, TLSError> {

		// This queue represents any server messages we need to drain after calling transition
		let mut messagequeue : Vec<HandshakeMessage> = Vec::new();

		let result = match self.state {
			TLSState::Start => {
				// Try to recieve the ClientHello
				let hs_message = HandshakeMessage::ClientHello(try!(self.read_clienthello()));

				// We can transition to the next state
				self.state = TLSState::RecievedClientHello;
				Ok(hs_message)
			},
			TLSState::RecievedClientHello => {
				// We need to evaluate the ClientHello to determine if we want to keep it
                let hs_message = if let HandshakeMessage::ClientHello(clienthello) = hs_message {
                    try!(self.negotiate_serverhello(&clienthello))
                } else {
                    return Err(TLSError::InvalidState)
                };

				// Check if this is a ServerHello or a HelloRetryRequest
				match hs_message {
					HandshakeMessage::ServerHello(_) => {
						// We don't need to do anything except transition state
						self.state = TLSState::Negotiated;
						Ok(hs_message)
					},
					HandshakeMessage::HelloRetryRequest(_) => {
						if self.sent_hello_retry {
							/*
								We have already sent a HelloRetryRequest once, so
								abort to avoid DoS loop
							*/
							return Err(TLSError::InvalidState)
						}
						self.sent_hello_retry = true;

						// Queue the HelloRetryRequest to send back to the client
						messagequeue.push(hs_message);
						self.state = TLSState::Start;
						Ok(HandshakeMessage::InvalidMessage)
					},
					_ => return Err(TLSError::InvalidState)
				}
			},
			TLSState::Negotiated => {
				Err(TLSError::InvalidState)
			},
			TLSState::WaitEndOfEarlyData => {
				Err(TLSError::InvalidState)
			},
			TLSState::WaitFlight2 => {
				Err(TLSError::InvalidState)
			},

            /*
                Because we don't support client certificates, we should
                never reach these states in our state machine
            */
			TLSState::WaitCert => {
				Err(TLSError::InvalidState)
			},
			TLSState::WaitCertificateVerify => {
				Err(TLSError::InvalidState)
			},

			TLSState::WaitFinished => {
				Err(TLSError::InvalidState)
			},
			TLSState::Connected => {
                // Nowhere else to go from here
                Ok(HandshakeMessage::InvalidMessage)
			},
		};

		// Check if we need to send any messages
		try!(self.send_message(messagequeue));

		result
	}

	pub fn tls_start(&mut self) -> Result<(), TLSError> {

		// Ensure we are in the "start" state
		if self.state != TLSState::Start {
			return Err(TLSError::InvalidState)
		}

		/*
			We want to transition through the TLS state machine until we
			encounter an error, or complete the handshake
		*/
        let mut hs_message = HandshakeMessage::InvalidMessage;
		loop {
			match self.transition(hs_message) {
				Err(e) => return Err(e),
				Ok(x) => {
					if self.state == TLSState::Connected {
						break
					}
                    hs_message = x
				}
			}
		};

		// If all goes well, we should be in the "connected" state
		if self.state != TLSState::Connected {
			return Err(TLSError::InvalidState)
		}

		Ok(())
	}
}

// Ideas for functions...
// TLS_start -> handshake and connection setup
// TLS_send -> sends plaintext
// TLS_recieve -> recieves plaintext
// TLS_end -> closes the connection

