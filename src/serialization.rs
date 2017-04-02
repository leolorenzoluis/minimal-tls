extern crate byteorder;
use serialization::byteorder::{NetworkEndian, WriteBytesExt};

use structures::{HandshakeMessage, TLSPlaintext};

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

fn u8_vector_as_bytes<T>(data : &Vec<T>) -> Vec<u8> where T:TLSToBytes {
	let mut ret : Vec<u8> = vec![];
	ret.push(data.len() as u8);
	for x in data.iter() {
		ret.extend(x.as_bytes());
	}
	ret
}

// FIXME: These need to be implemented
impl<'a> TLSToBytes for &'a TLSPlaintext {
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

impl<'a> TLSToBytes for &'a HandshakeMessage {
	fn as_bytes(&self) -> Vec<u8> {
	    match **self {
			HandshakeMessage::InvalidMessage => vec![],
			HandshakeMessage::ClientHello(ref inner) => vec![],
			HandshakeMessage::ServerHello(ref inner) => vec![],
			HandshakeMessage::EndOfEarlyData(ref inner) => vec![],
			HandshakeMessage::HelloRetryRequest(ref inner) => vec![],
			HandshakeMessage::EncryptedExtensions(ref inner) => vec![],
			HandshakeMessage::CertificateRequest(ref inner) => vec![],
			HandshakeMessage::Certificate(ref inner) => vec![],
			HandshakeMessage::CertificateVerify(ref inner) => vec![],
			HandshakeMessage::Finished(ref inner) => vec![],
			HandshakeMessage::NewSessionTicket(ref inner) => vec![],
			HandshakeMessage::KeyUpdate(ref inner) => vec![],
	    }
	}
}
