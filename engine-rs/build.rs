use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=../vendor/windivert/WinDivert.dll");
    println!("cargo:rerun-if-changed=../vendor/windivert/WinDivert64.sys");
    println!("cargo:rerun-if-changed=WinDivert.dll");
    println!("cargo:rerun-if-changed=WinDivert64.sys");

    let files = ["WinDivert.dll", "WinDivert64.sys"];

    if let Ok(out_dir) = env::var("OUT_DIR") {
        if let Some(target_dir) = Path::new(&out_dir).ancestors().nth(3) {
            for file in &files {
                let source = if Path::new("../vendor/windivert").join(file).exists() {
                    Path::new("../vendor/windivert").join(file)
                } else if Path::new(file).exists() {
                    Path::new(file).to_path_buf()
                } else {
                    continue;
                };

                let dest = target_dir.join(file);
                let _ = fs::copy(&source, dest);
            }
        }
    }
}

