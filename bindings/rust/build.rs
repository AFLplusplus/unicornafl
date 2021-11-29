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
}
