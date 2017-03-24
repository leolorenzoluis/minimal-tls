mod structures;

mod minimaltls {
	use structures::ContentType;

	fn main() {
		let x : ContentType = ContentType::Alert;
	}
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
