use std::{env, process::Command};

use build_helper::rustc::link_search;

fn add_lib(path: &str, name: &str) {
    let out_dir = env::var("OUT_DIR").unwrap();

    let _ = Command::new("cp")
        .current_dir(path)
        .arg(format!("lib{}.a", name))
        .arg(&out_dir)
        .status()
        .unwrap();
    println!("cargo:rustc-link-lib=static={}", name);
}

fn main() {
    println!("cargo:rerun-if-changed=unicornafl");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=../../include");
    println!("cargo:rerun-if-changed=../../unicornafl.cpp");
    println!("cargo:rerun-if-changed=../../CMakeLists.txt");

    Command::new("make")
        .args(&["-C", "../.."])
        .status()
        .expect("failed to build unicornafl");

    link_search(
        Some(build_helper::SearchKind::Native),
        build_helper::out_dir(),
    );

    add_lib("../../build", "unicornafl");

    add_lib("../../build/unicorn", "unicorn-static");
    add_lib("../../build/unicorn", "unicorn-common");

    //println!("cargo:rustc-link-lib=static=unicorn");
    for arch in [
        "x86_64",
        "arm",
        "aarch64",
        "riscv32",
        "riscv64",
        "mips",
        "mipsel",
        "mips64",
        "mips64el",
        "sparc",
        "sparc64",
        "m68k",
        "ppc",
        "ppc64",
        "s390x",
    ]
    .iter()
    {
        add_lib("../../build/unicorn", &format!("{}-softmmu", arch));
    }
}
