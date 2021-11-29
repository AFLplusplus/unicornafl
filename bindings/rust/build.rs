use std::{env, process::Command};

use build_helper::rustc::{link_lib, link_search};

fn main() {
    println!("cargo:rerun-if-changed=unicornafl");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=../../include");
    println!("cargo:rerun-if-changed=../../unicornafl.cpp");
    println!("cargo:rerun-if-changed=../../CMakeLists.txt");

    let out_dir = env::var("OUT_DIR").unwrap();
    let unicorn = "libunicornafl.a";

    Command::new("make")
        .args(&["-C", "../.."])
        .status()
        .expect("failed to build unicornafl");

    let _ = Command::new("cp")
        .current_dir("../../build")
        .arg(&unicorn)
        .arg(&out_dir)
        .status()
        .unwrap();

    link_search(
        Some(build_helper::SearchKind::Native),
        build_helper::out_dir(),
    );
    link_lib(Some(build_helper::LibKind::Static), "unicornafl");

    //println!("cargo:rustc-link-lib=static=unicorn");
    for arch in [
        "x86_64",
        "arm",
        "armeb",
        "aarch64",
        "aarch64eb",
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
    ]
    .iter()
    {
        let _ = Command::new("cp")
            .current_dir("../../build/unicorn")
            .arg(format!("lib{}-softmmu.a", arch))
            .arg(&out_dir)
            .status()
            .unwrap();

        println!("cargo:rustc-link-lib=static={}-softmmu", arch);
    }

    let _ = Command::new("cp")
        .current_dir("../../build/unicorn")
        .arg("libunicorn-common.a")
        .arg(&out_dir)
        .status()
        .unwrap();
    println!("cargo:rustc-link-lib=static=unicorn-common");
}
