use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::hash::{Hash, Hasher};

struct BinPattern {
    files: HashSet<PathBuf>,
    blobs: Vec<Vec<u8>>,
}

impl BinPattern {
    fn new() -> Self {
        BinPattern {
            files: HashSet::new(),
            blobs: Vec::new(),
        }
    }

    fn crawl(&mut self, path: &Path) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    self.crawl(&path);
                } else if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
                    if extension.eq_ignore_ascii_case("exe") || 
                       extension.eq_ignore_ascii_case("dll") ||
                       extension.eq_ignore_ascii_case("bin") {
                        self.files.insert(path);
                    }
                }
            }
        }
    }

    fn get_code(path: &Path) -> Option<Vec<u8>> {
        let data = fs::read(path).ok()?;
        
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return None;
        }

        let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
        if pe_offset >= data.len() - 4 {
            return None;
        }

        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return None;
        }

        let num_sections = u16::from_le_bytes(data[pe_offset + 6..pe_offset + 8].try_into().ok()?) as usize;
        let section_table_offset = pe_offset + 0xF8;

        for i in 0..num_sections {
            let section_offset = section_table_offset + (i * 40);
            if section_offset + 40 > data.len() {
                break;
            }

            let name = &data[section_offset..section_offset + 8];
            if name.starts_with(b".text") {
                let raw_offset = u32::from_le_bytes(data[section_offset + 20..section_offset + 24].try_into().ok()?) as usize;
                let raw_size = u32::from_le_bytes(data[section_offset + 16..section_offset + 20].try_into().ok()?) as usize;

                if raw_offset + raw_size <= data.len() {
                    return Some(data[raw_offset..raw_offset + raw_size].to_vec());
                }
            }
        }

        None
    }

    fn find_patterns(&self, pattern_len: usize, runtime: &[u8]) {
        if self.blobs.is_empty() {
            return;
        }

        let first_blob = &self.blobs[0];
        let total_len = first_blob.len();
        let mut pattern_count = 0;
        let mut i = 0;
        let mut seen_patterns = HashSet::new();

        while i < total_len.saturating_sub(pattern_len) {
            print!("progress: {}%\r", i * 100 / total_len);

            let pattern = &first_blob[i..i + pattern_len];
            
            if Self::should_skip_pattern(pattern) {
                i += 1;
                continue;
            }

            let mut hasher = DefaultHasher::new();
            pattern.hash(&mut hasher);
            let pattern_hash = hasher.finish();

            if seen_patterns.contains(&pattern_hash) {
                i += 1;
                continue;
            }

            let success_count = self.blobs.iter()
                .filter(|blob| Self::contains_pattern(blob, pattern))
                .count();

            if success_count == self.blobs.len() && !Self::contains_pattern(runtime, pattern) {
                pattern_count += 1;
                let pattern_hex = hex::encode(pattern);
                println!("$code{:02} = {{{}}}", pattern_count, pattern_hex);
                seen_patterns.insert(pattern_hash);
                i += pattern_len;
            } else {
                i += 1;
            }
        }
    }

    fn should_skip_pattern(pattern: &[u8]) -> bool {
        let zeros = pattern.iter().filter(|&&b| b == 0).count();
        let ccs = pattern.iter().filter(|&&b| b == 0xCC).count();
        let nops = pattern.iter().filter(|&&b| b == 0x90).count();

        pattern.is_empty() || 
        pattern.iter().all(|&b| b == 0) ||
        pattern.iter().all(|&b| b == 0xFF) ||
        pattern.iter().all(|&b| b == 0xCC) ||
        zeros > 4 || ccs > 4 || nops > 4
    }

    fn contains_pattern(blob: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() {
            return false;
        }
        
        blob.windows(pattern.len()).any(|window| window == pattern)
    }

    fn detect_compiler(data: &[u8]) -> &'static str {
        // Buscar strings comunes de cada compilador
        let content = String::from_utf8_lossy(data);
        
        if content.contains("rust_panic") || content.contains("rust_begin_unwind") {
            return "Rust";
        }
        
        if content.contains("Go build ID:") || content.contains("golang") {
            return "Golang";
        }
        
        if content.contains("GCC: (GNU)") || content.contains("__MINGW_IMPORT") {
            return "MinGW/GCC";
        }

        if content.contains("Borland\\Delphi") || content.contains("FastMM") {
            return "Delphi";
        }

        // MSVC tiene secciones específicas
        if data.windows(16).any(|window| {
            window.starts_with(b".CRT$XCA") || 
            window.starts_with(b".CRT$XCU") ||
            window.starts_with(b".CRT$XCL")
        }) {
            return "MSVC";
        }

        // Clang/LLVM tiene strings específicos
        if content.contains("clang version") || content.contains("LLVM") {
            return "Clang/LLVM";
        }

        "Unknown"
    }

    fn get_binary_info(path: &Path) -> Option<BinaryInfo> {
        let data = fs::read(path).ok()?;
        
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return None;
        }

        let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
        if pe_offset >= data.len() - 4 {
            return None;
        }

        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return None;
        }

        // Machine type está en PE header offset +4 (2 bytes)
        let machine = u16::from_le_bytes(data[pe_offset + 4..pe_offset + 6].try_into().ok()?);
        
        // Characteristics está en PE header offset +22 (2 bytes)
        let characteristics = u16::from_le_bytes(data[pe_offset + 22..pe_offset + 24].try_into().ok()?);

        // Optional header magic está en PE header offset +24 (2 bytes)
        let magic = u16::from_le_bytes(data[pe_offset + 24..pe_offset + 26].try_into().ok()?);

        let arch = match machine {
            0x014c => "x86",
            0x0200 => "IA64",
            0x8664 => "x64",
            0x01c4 => "ARM",
            0xaa64 => "ARM64",
            _ => "Unknown",
        };

        let is_64bit = magic == 0x20b;
        let is_dll = (characteristics & 0x2000) != 0;
        let is_system = (characteristics & 0x1000) != 0;
        let is_gui = (characteristics & 0x0002) != 0;

        Some(BinaryInfo {
            architecture: arch.to_string(),
            is_64bit,
            is_dll,
            is_system,
            is_gui,
            compiler: Self::detect_compiler(&data).to_string(),
        })
    }
}

#[derive(Debug)]
struct BinaryInfo {
    architecture: String,
    is_64bit: bool,
    is_dll: bool,
    is_system: bool,
    is_gui: bool,
    compiler: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} [folder] [pattern len] [exclude binary]", args[0]);
        return;
    }

    let src = Path::new(&args[1]);
    let pattern_len = args[2].parse::<usize>().unwrap_or(15);
    let runtime_path = Path::new(&args[3]);

    println!("loading ...");
    
    let mut bin_pattern = BinPattern::new();
    bin_pattern.crawl(src);

    if bin_pattern.files.is_empty() {
        println!("no files");
        return;
    }

    println!("\nBinary Information:");
    for file_path in &bin_pattern.files {
        if let Some(info) = BinPattern::get_binary_info(file_path) {
            println!("\n{:?}:", file_path);
            println!("  Compiler: {}", info.compiler);
            println!("  Architecture: {} ({})", info.architecture, if info.is_64bit { "64-bit" } else { "32-bit" });
            if info.is_dll { println!("  Type: DLL"); }
            if info.is_system { println!("  System: Yes"); }
            if info.is_gui { println!("  GUI: Yes"); }
        }
    }
    println!();

    for file_path in &bin_pattern.files {
        if let Some(code) = BinPattern::get_code(file_path) {
            bin_pattern.blobs.push(code);
        }
    }

    if bin_pattern.blobs.is_empty() {
        println!("no .text blobs found");
        return;
    }

    let runtime = match BinPattern::get_code(runtime_path) {
        Some(code) => code,
        None => {
            println!("runtime not valid or not found");
            return;
        }
    };

    println!("loaded {} .text blobs", bin_pattern.blobs.len());
    bin_pattern.find_patterns(pattern_len, &runtime);
}
