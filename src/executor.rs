use std::{
    fs::File,
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
};

use libafl::Error;
use memmap2::{Mmap, MmapOptions};

use crate::{Opt, DEFER_SIG, PERSIST_SIG};

// TODO more checks and logging
pub fn check_binary(opt: &mut Opt, shmem_env_var: &str) -> Result<(), Error> {
    let bin_path = &opt.executable;
    let metadata = bin_path.metadata()?;
    let is_reg = !bin_path.is_symlink() && !bin_path.is_dir();

    if opt.nyx_mode {
        if !bin_path.is_symlink() && bin_path.is_dir() {
            let config_file = bin_path.join("config.ron");
            if !config_file.is_symlink() && config_file.is_file() {
                return Ok(());
            }
        }
        return Err(Error::illegal_argument(
            format!(
                "Directory '{}' not found, or is a symlink or is not a nyx share directory",
                bin_path.display()
            )
            .as_str(),
        ));
    }
    let bin_size = metadata.st_size();
    let is_executable = metadata.permissions().mode() & 0o111 != 0;
    if !is_reg || !is_executable || bin_size < 4 {
        return Err(Error::illegal_argument(format!(
            "Program '%s' not found or not executable"
        )));
    }
    // TODO: check $PATH for binary cause bin_path can be just a name for an executable

    /*
    if (afl->afl_env.afl_skip_bin_check || afl->use_wine || afl->unicorn_mode ||
        (afl->fsrv.qemu_mode && getenv("AFL_QEMU_CUSTOM_BIN")) ||
        (afl->fsrv.cs_mode && getenv("AFL_CS_CUSTOM_BIN")) ||
        afl->non_instrumented_mode) {

      return;

    }
      * */
    if opt.skip_bin_check {
        return Ok(());
    }

    let file = File::open(bin_path)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    // check if it's a shell script
    if mmap[0..1] == [0x43, 0x41] {
        // TODO: finish error message
        return Err(Error::illegal_argument(
            "Oops, the target binary looks like a shell script.",
        ));
    }

    // check if the binary is an ELF file
    if mmap[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
        return Err(Error::illegal_argument(format!(
            "Program '{}' is not an ELF binary",
            bin_path.display()
        )));
    }

    // TODO Mach-O binary check

    let is_instrumented = mmap_has_substr(&mmap, shmem_env_var);
    if !is_instrumented {
        return Err(Error::illegal_argument(
            "target binary is not instrumented correctly",
        ));
    }

    // TODO: check if afl-gcc instrumentation

    if mmap_has_substr(&mmap, "__asan_init")
        || mmap_has_substr(&mmap, "__lsan_init")
        || mmap_has_substr(&mmap, "__lsan_init")
    {
        opt.uses_asan = true;
    }

    // Note: this can be overriden by the environment variable AFL_PERSISTENT
    if mmap_has_substr(&mmap, PERSIST_SIG) {
        opt.is_persistent = true;
    }

    // Note: this can be overriden by the environment variable AFL_DEFER_FORKSRV
    if mmap_has_substr(&mmap, DEFER_SIG) {
        opt.defer_forkserver = true;
    }

    Ok(())
}

fn mmap_has_substr(mmap: &Mmap, sub_str: &str) -> bool {
    let mmap_len = mmap.len();
    let substr_len = sub_str.len();
    if mmap_len < substr_len {
        return false;
    }
    for i in 0..(mmap_len - substr_len) {
        if &mmap[i as usize..i + substr_len] == sub_str.as_bytes() {
            return true;
        }
    }
    false
}
