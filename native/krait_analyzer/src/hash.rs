/// Compute the BLAKE3 hash of the given source code and return it as a hex string.
pub fn blake3_hex(data: &str) -> String {
    let hash = blake3::hash(data.as_bytes());
    hash.to_hex().to_string()
}
