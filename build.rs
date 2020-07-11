use rustc_version::{version, version_meta, Channel};
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::str;

#[cfg(target_os = "macos")]
fn setup_macos() {
    const MACH_EXC_SERVER: &'static str = "mach_excServer";
    let end_of_path = "/usr/include/mach/mach_exc.defs";
    let mach_defs = match Command::new("xcrun").arg("--show-sdk-path").output() {
        Err(_) => end_of_path.to_string(),
        Ok(s) => {
            let root = str::from_utf8(&s.stdout).unwrap_or_default().trim_end();
            format!("{}{}", root, end_of_path)
        }
    };
    println!("mach_exc.defs location {}", mach_defs);

    let mut mach_src_path = PathBuf::from("mach_interface/");
    if !mach_src_path.exists() {
        fs::create_dir(&mach_src_path).unwrap();

        let res = Command::new("mig")
            .arg(&mach_defs)
            .current_dir(&mach_src_path)
            .output();
        if res.is_err() {
            fs::remove_dir(&mach_src_path).unwrap();
            let _ = res.unwrap();
        }
    }
    mach_src_path.push(MACH_EXC_SERVER);
    mach_src_path.set_extension("c");
    cc::Build::new()
        .file(mach_src_path)
        .compile(MACH_EXC_SERVER);
}

fn main() {
    assert!(version().expect("Couldn't get compiler version").major >= 1);

    let channel = version_meta()
        .expect("Couldn't get compiler metadata")
        .channel;
    if channel == Channel::Nightly {
        println!("cargo:rustc-cfg=nightly");
    }
    #[cfg(target_os = "macos")]
    setup_macos();
}
