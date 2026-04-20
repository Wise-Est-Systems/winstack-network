//! .win container format — zero dependencies
//!
//! Layout:
//!   [4 bytes]  magic: b"WIN\x01"
//!   [4 bytes]  filename length (u32 little-endian)
//!   [N bytes]  filename (UTF-8, no path separators)
//!   [8 bytes]  file length (u64 little-endian)
//!   [M bytes]  original file bytes (raw, uncompressed)
//!   [rest]     proof JSON (UTF-8, everything from here to EOF)

const MAGIC: &[u8; 4] = b"WIN\x01";

#[derive(Debug)]
pub enum WinError {
    NotAWinFile,
    TooShort,
    BadMagic,
    BadFilename,
    Truncated,
    Io(std::io::Error),
}

impl std::fmt::Display for WinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WinError::NotAWinFile => write!(f, "not a .win file"),
            WinError::TooShort => write!(f, "file too short"),
            WinError::BadMagic => write!(f, "invalid .win header"),
            WinError::BadFilename => write!(f, "invalid filename in .win"),
            WinError::Truncated => write!(f, "truncated .win file"),
            WinError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl std::error::Error for WinError {}

impl From<std::io::Error> for WinError {
    fn from(e: std::io::Error) -> Self {
        WinError::Io(e)
    }
}

/// Pack a file and its proof JSON into a .win container.
pub fn pack(filename: &str, file_bytes: &[u8], proof_json: &str) -> Vec<u8> {
    let name_bytes = sanitize_filename(filename).into_bytes();
    let name_len = name_bytes.len() as u32;
    let file_len = file_bytes.len() as u64;
    let proof_bytes = proof_json.as_bytes();

    let total = 4 + 4 + name_bytes.len() + 8 + file_bytes.len() + proof_bytes.len();
    let mut out = Vec::with_capacity(total);

    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&name_bytes);
    out.extend_from_slice(&file_len.to_le_bytes());
    out.extend_from_slice(file_bytes);
    out.extend_from_slice(proof_bytes);

    out
}

/// Unpack a .win container → (filename, file_bytes, proof_json)
///
/// Security: filename is sanitized (path separators stripped, length capped).
/// File length is bounds-checked against actual data. No panics on malformed input.
pub fn unpack(data: &[u8]) -> Result<(String, Vec<u8>, String), WinError> {
    if data.len() < 16 {
        return Err(WinError::TooShort);
    }

    // Magic
    if &data[0..4] != MAGIC {
        return Err(WinError::BadMagic);
    }

    // Filename length (cap at 4096 to prevent DoS)
    let name_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if name_len > 4096 {
        return Err(WinError::BadFilename);
    }
    let name_end = 8usize.checked_add(name_len).ok_or(WinError::Truncated)?;
    if data.len() < name_end + 8 {
        return Err(WinError::Truncated);
    }

    // Filename — sanitize: strip paths, reject null bytes
    let raw_name = std::str::from_utf8(&data[8..name_end]).map_err(|_| WinError::BadFilename)?;
    if raw_name.contains('\0') {
        return Err(WinError::BadFilename);
    }
    let filename = sanitize_filename(raw_name);
    if filename.is_empty() {
        return Err(WinError::BadFilename);
    }

    // File length — checked arithmetic, no overflow
    let file_len_start = name_end;
    let file_len = u64::from_le_bytes([
        data[file_len_start],
        data[file_len_start + 1],
        data[file_len_start + 2],
        data[file_len_start + 3],
        data[file_len_start + 4],
        data[file_len_start + 5],
        data[file_len_start + 6],
        data[file_len_start + 7],
    ]);

    // Bounds check: file_len must fit in available data
    let file_start = file_len_start + 8;
    let file_len_usize = usize::try_from(file_len).map_err(|_| WinError::Truncated)?;
    let file_end = file_start
        .checked_add(file_len_usize)
        .ok_or(WinError::Truncated)?;
    if data.len() < file_end {
        return Err(WinError::Truncated);
    }

    // File bytes
    let file_bytes = data[file_start..file_end].to_vec();

    // Proof JSON (everything after file bytes)
    let proof_bytes = &data[file_end..];
    if proof_bytes.is_empty() {
        return Err(WinError::Truncated);
    }
    let proof_json = std::str::from_utf8(proof_bytes).map_err(|_| WinError::BadFilename)?;

    Ok((filename, file_bytes, proof_json.to_string()))
}

/// Check if data starts with .win magic bytes.
pub fn is_win_file(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == MAGIC
}

/// Strip path separators from filename.
fn sanitize_filename(name: &str) -> String {
    name.rsplit(['/', '\\']).next().unwrap_or(name).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let packed = pack("test.pdf", b"hello world", r#"{"proof":true}"#);
        let (name, file, proof) = unpack(&packed).unwrap();
        assert_eq!(name, "test.pdf");
        assert_eq!(file, b"hello world");
        assert_eq!(proof, r#"{"proof":true}"#);
    }

    #[test]
    fn is_win_detects_correctly() {
        let packed = pack("f.txt", b"x", "{}");
        assert!(is_win_file(&packed));
        assert!(!is_win_file(b"not a win file"));
        assert!(!is_win_file(b"WIN")); // too short
    }

    #[test]
    fn empty_data_rejected() {
        assert!(unpack(b"").is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        assert!(unpack(b"NOPE0000000000000000").is_err());
    }

    #[test]
    fn truncated_file_region_rejected() {
        let packed = pack("f.txt", b"data", "{}");
        // Cut into the file data region (before proof starts)
        assert!(unpack(&packed[..16]).is_err());
    }

    #[test]
    fn path_separators_stripped() {
        let packed = pack("/Users/someone/docs/file.pdf", b"x", "{}");
        let (name, _, _) = unpack(&packed).unwrap();
        assert_eq!(name, "file.pdf");
    }

    #[test]
    fn empty_file_works() {
        let packed = pack("empty.txt", b"", "{}");
        // empty file_bytes is valid — file_len=0 means proof starts immediately
        // but our unpack requires proof to be non-empty
        let (name, file, proof) = unpack(&packed).unwrap();
        assert_eq!(name, "empty.txt");
        assert!(file.is_empty());
        assert_eq!(proof, "{}");
    }

    #[test]
    fn large_file() {
        let data = vec![0xAB; 500_000];
        let packed = pack("big.bin", &data, r#"{"big":true}"#);
        let (name, file, proof) = unpack(&packed).unwrap();
        assert_eq!(name, "big.bin");
        assert_eq!(file.len(), 500_000);
        assert_eq!(proof, r#"{"big":true}"#);
    }

    #[test]
    fn binary_content_preserved() {
        let data: Vec<u8> = (0..=255).collect();
        let packed = pack("bin.dat", &data, "{}");
        let (_, file, _) = unpack(&packed).unwrap();
        assert_eq!(file, data);
    }

    // ── SECURITY TESTS ──

    #[test]
    fn path_traversal_stripped() {
        let packed = pack("../../../etc/passwd", b"x", "{}");
        let (name, _, _) = unpack(&packed).unwrap();
        assert_eq!(name, "passwd");
        assert!(!name.contains(".."));
        assert!(!name.contains('/'));
    }

    #[test]
    fn windows_path_traversal_stripped() {
        let packed = pack("..\\..\\Windows\\system32\\evil.exe", b"x", "{}");
        let (name, _, _) = unpack(&packed).unwrap();
        assert_eq!(name, "evil.exe");
    }

    #[test]
    fn null_bytes_in_filename_rejected() {
        // Craft raw bytes with null in filename
        let mut payload = Vec::new();
        payload.extend_from_slice(b"WIN\x01");
        payload.extend_from_slice(&8u32.to_le_bytes());
        payload.extend_from_slice(b"test\x00exe");
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.push(b'x');
        payload.extend_from_slice(b"{}");
        assert!(unpack(&payload).is_err());
    }

    #[test]
    fn integer_overflow_file_len() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"WIN\x01");
        payload.extend_from_slice(&4u32.to_le_bytes());
        payload.extend_from_slice(b"test");
        payload.extend_from_slice(&u64::MAX.to_le_bytes());
        payload.extend_from_slice(b"x{}");
        assert!(unpack(&payload).is_err());
    }

    #[test]
    fn filename_length_capped() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"WIN\x01");
        payload.extend_from_slice(&(1_000_000u32).to_le_bytes()); // 1MB filename
        payload.extend_from_slice(&vec![b'a'; 1_000_000]);
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.push(b'x');
        payload.extend_from_slice(b"{}");
        assert!(unpack(&payload).is_err());
    }

    #[test]
    fn unpack_then_repack_identical() {
        let original = pack("doc.pdf", b"PDF content here", r#"{"hash":"abc"}"#);
        let (name, file, proof) = unpack(&original).unwrap();
        let repacked = pack(&name, &file, &proof);
        assert_eq!(original, repacked);
    }
}
