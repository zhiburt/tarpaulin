#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
fn setup_macos() {
    const MACH_DEFS: &'static str = "/usr/include/mach/mach_exc.defs";
    const MACH_EXC_SERVER: &'static str = "mach_excServer";

    let mut mach_src_path = PathBuf::from("mach_interface/");
    if !mach_src_path.exists() {
        fs::create_dir(&mach_src_path).unwrap();

        Command::new("mig")
            .arg(MACH_DEFS)
            .current_dir(&mach_src_path)
            .output()
            .unwrap();
    }
    mach_src_path.push(MACH_EXC_SERVER);
    mach_src_path.set_extension("c");
    cc::Build::new()
        .file(mach_src_path)
        .compile(MACH_EXC_SERVER);
}

fn main() {
    #[cfg(target_os = "macos")]
    setup_macos();
}
