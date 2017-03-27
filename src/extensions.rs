use std::slice::Iter;
use structures::{Extension, TLSError, ProtocolVersion};

impl Extension {

	pub fn parse_supported_groups<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_signature_algorithms<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_keyshare<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_preshared_key<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_earlydata<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_supported_versions<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		// TODO: Is it possible for these to ever panic?
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
		let mut ret : Vec<ProtocolVersion> = Vec::new();
		for x in 1..(length/2) {

			let first = iter.next();
			let second = iter.next();
			if first.is_none() || second.is_none() {
				return Err(TLSError::InvalidHandshakeError)
			}

			ret.push(((*first.unwrap() as u16) << 8) | (*second.unwrap() as u16));
		}

		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_cookie<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_psk_key_exchange_modes<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_certificate_authorities<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_oldfilters<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}
}
