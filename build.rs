use std::fs;
use std::path::PathBuf;
use std::process::Command;

const MACH_DEFS: &'static str = "/usr/include/mach/mach_exc.defs";
const MACH_EXC_SERVER: &'static str = "mach_excServer";
fn main() {
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
