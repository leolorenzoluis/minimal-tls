extern crate byteorder;
use serialization::byteorder::{NetworkEndian, WriteBytesExt};

use structures::{HandshakeMessage, TLSPlaintext, CipherSuite, Extension, CertificateEntry, SignatureScheme, KeyUpdateRequest};

pub trait TLSToBytes {
	fn as_bytes(&self) -> Vec<u8>;
}

/*
	We can't use a generic Vec<T> implementation for these two functions
	because TLS 1.3 encodes length differently depending on the max length
	of the vector. If the cap is <= 255, it only uses one byte, but otherwise
	uses two bytes. I think this is really silly but oh well
*/

fn u16_vector_as_bytes<T>(data : &Vec<T>) -> Vec<u8> where T:TLSToBytes {
	let mut ret : Vec<u8> = vec![];
	ret.write_u16::<NetworkEndian>(data.len() as u16).unwrap();
	for x in data.iter() {
		ret.extend(x.as_bytes());
	}
	ret
}

fn u16_bytevec_as_bytes(data : &Vec<u8>) -> Vec<u8> {
	let mut ret : Vec<u8> = vec![];
	ret.write_u16::<NetworkEndian>(data.len() as u16).unwrap();
    ret.extend(data);
	ret
}

fn u8_vector_as_bytes<T>(data : &Vec<T>) -> Vec<u8> where T:TLSToBytes {
	let mut ret : Vec<u8> = vec![];
	ret.push(data.len() as u8);
	for x in data.iter() {
		ret.extend(x.as_bytes());
	}
	ret
}

fn u8_bytevec_as_bytes(data : &Vec<u8>) -> Vec<u8> {
	let mut ret : Vec<u8> = vec![];
    ret.push(data.len() as u8);
    ret.extend(data);
	ret
}

impl TLSToBytes for TLSPlaintext {
	fn as_bytes(&self) -> Vec<u8> {
    	let mut ret : Vec<u8> = Vec::new();

    	// Content type
    	ret.push(self.ctype as u8);

    	// Protocol version
    	ret.write_u16::<NetworkEndian>(self.legacy_record_version).unwrap();

    	// Data length
    	ret.write_u16::<NetworkEndian>(self.length).unwrap();

    	// Data
		ret.extend(self.fragment.clone());

		ret
	}
}

// FIXME: Implement this
impl TLSToBytes for CipherSuite {
    fn as_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl TLSToBytes for CertificateEntry {
    fn as_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl TLSToBytes for KeyUpdateRequest {
    fn as_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl TLSToBytes for SignatureScheme {
    fn as_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

// FIXME: Implement this
impl TLSToBytes for Extension {
    fn as_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl TLSToBytes for HandshakeMessage {
	fn as_bytes(&self) -> Vec<u8> {

        let mut ret : Vec<u8> = vec![];

	    match *self {
			HandshakeMessage::InvalidMessage => (),
			HandshakeMessage::ClientHello(ref inner) => {
                ret.write_u16::<NetworkEndian>(inner.legacy_version).unwrap();
                ret.extend(inner.random.iter());
                ret.extend(u8_bytevec_as_bytes(&inner.legacy_session_id));
                ret.extend(u16_vector_as_bytes(&inner.cipher_suites));
                ret.extend(u8_bytevec_as_bytes(&inner.legacy_compression_methods));
                ret.extend(u16_vector_as_bytes(&inner.extensions));
            },
			HandshakeMessage::ServerHello(ref inner) => {
                ret.write_u16::<NetworkEndian>(inner.version).unwrap();
                ret.extend(inner.random.iter());
                ret.extend(inner.cipher_suite.as_bytes());
                ret.extend(u16_vector_as_bytes(&inner.extensions));
            },
            // This is correct, it is supposed to be empty
			HandshakeMessage::EndOfEarlyData(ref inner) => (),
			HandshakeMessage::HelloRetryRequest(ref inner) => {
                ret.write_u16::<NetworkEndian>(inner.server_version).unwrap();
                ret.extend(inner.cipher_suite.as_bytes());
                ret.extend(u16_vector_as_bytes(&inner.extensions));
            },
			HandshakeMessage::EncryptedExtensions(ref inner) => {
                ret.extend(u16_vector_as_bytes(&inner.extensions));
            },
			HandshakeMessage::CertificateRequest(ref inner) => {
                ret.extend(u8_bytevec_as_bytes(&inner.certificate_request_context));
                ret.extend(u16_vector_as_bytes(&inner.extensions));
            },
			HandshakeMessage::Certificate(ref inner) => {
                ret.extend(u8_bytevec_as_bytes(&inner.certificate_request_context));
                ret.extend(u16_vector_as_bytes(&inner.certificate_list));
            },
			HandshakeMessage::CertificateVerify(ref inner) => {
                ret.extend(inner.algorithm.as_bytes());
                ret.extend(u16_bytevec_as_bytes(&inner.signature));
            },
			HandshakeMessage::Finished(ref inner) => {
                ret.extend(u16_bytevec_as_bytes(&inner.verify_data));
            },
			HandshakeMessage::NewSessionTicket(ref inner) => {
                ret.write_u32::<NetworkEndian>(inner.ticket_lifetime).unwrap();
                ret.write_u32::<NetworkEndian>(inner.ticket_age_add).unwrap();
                ret.extend(u16_bytevec_as_bytes(&inner.ticket));
                ret.extend(u16_vector_as_bytes(&inner.extensions));
            },
			HandshakeMessage::KeyUpdate(ref inner) => {
                ret.extend(inner.request_update.as_bytes());
            },
	    };

        ret
	}
}
