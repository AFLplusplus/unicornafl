use std::{
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
};

use build_helper::rustc::{link_lib, link_search};

fn get_vcvars_path_and_platform() -> (OsString, &'static str) {
    let vswhere_output = Command::new(r"build_tools\vswhere.exe")
        .args(&["-latest", "-legacy", "-property", "installationPath"])
        .output()
        .expect("failed to execute vswhere.exe");

    if !vswhere_output.status.success() {
        fail("vswhere failed to locate Microsoft Visual Studio");
    }

    let visual_studio_path = {
        let vswhere_stdout =
            String::from_utf8(vswhere_output.stdout).expect("vswhere output is not valid UTF-8");
        String::from(vswhere_stdout.trim())
    };

    match build_helper::target::triple().arch() {
        "i686" => {
            let old_style_path = [&visual_studio_path, "VC", "bin", "vcvars32.bat"]
                .iter()
                .collect::<PathBuf>();
            if old_style_path.is_file() {
                return (old_style_path.into_os_string(), "Win32");
            }

            let new_style_path = [
                &visual_studio_path,
                "VC",
                "Auxiliary",
                "Build",
                "vcvars32.bat",
            ]
            .iter()
            .collect::<PathBuf>();
            if new_style_path.is_file() {
                return (new_style_path.into_os_string(), "Win32");
            }

            panic!("failed to locate 'vcvars32.bat'");
        }
        "x86_64" => {
            let old_style_path = [
                &visual_studio_path,
                "VC",
                "bin",
                "x86_amd64",
                "vcvarsx86_amd64.bat",
            ]
            .iter()
            .collect::<PathBuf>();
            if old_style_path.is_file() {
                return (old_style_path.into_os_string(), "x64");
            }

            let new_style_path = [
                &visual_studio_path,
                "VC",
                "Auxiliary",
                "Build",
                "vcvarsx86_amd64.bat",
            ]
            .iter()
            .collect::<PathBuf>();
            if new_style_path.is_file() {
                return (new_style_path.into_os_string(), "x64");
            }

            panic!("failed to locate 'vcvarsx86_amd64.bat'");
        }
        arch => panic!("'{}' is not a valid architecture for MSVC builds", arch),
    }
}

fn main() {
    println!("cargo:rerun-if-changed=unicornafl");

    if !build_helper::windows() {
        if Command::new("pkg-config").output().is_ok()
            && pkg_config::Config::new()
                .atleast_version("1.0.0")
                .probe("unicornafl")
                .is_ok()
        {
            return;
        }
    }

    let out_dir = env::var("OUT_DIR").unwrap();

    let make_args = match os_type::current_platform().os_type {
        os_type::OSType::OSX => ["macos-universal-no"],
        _ => [""],
    };

    if build_helper::target::triple()
        .env()
        .unwrap_or("")
        .contains("msvc")
    {
        let build_cmd_path: PathBuf = [
            env::current_dir()
                .expect("failed to retrieve current directory")
                .as_path(),
            Path::new("build_tools"),
            Path::new("msvc_build.bat"),
        ]
        .iter()
        .collect();

        let platform_toolset = match env::var("PLATFORMTOOLSET") {
            Ok(x) => x,
            Err(_) => "".to_owned(),
        };

        let (vcvars_path, platform) = get_vcvars_path_and_platform();
        let status = match Command::new(build_cmd_path)
            .args(&[
                &vcvars_path,
                OsStr::new(&out_dir),
                OsStr::new(&platform_toolset),
                OsStr::new(platform),
            ])
            .current_dir("../../../")
            .status()
        {
            Ok(status) => status,
            Err(e) => fail(&format!("failed to execute command: {}", e)),
        };
        if !status.success() {
            fail(&format!(
                "command did not execute successfully, got {}",
                status
            ));
        }

        link_search(
            Some(build_helper::SearchKind::Native),
            build_helper::out_dir(),
        );
        link_lib(Some(build_helper::LibKind::Static), "unicornafl_static");
    } else {
        let _ = Command::new("./make.sh")
            .args(&make_args)
            .current_dir("../../../")
            .status();

        let unicorn = "libunicornafl.a";
        let _ = Command::new("cp")
            .current_dir("../../../")
            .arg(&unicorn)
            .arg(&out_dir)
            .status();

        link_search(
            Some(build_helper::SearchKind::Native),
            build_helper::out_dir(),
        );
        link_lib(Some(build_helper::LibKind::Static), "unicornafl");
    }
}

fn fail(s: &str) -> ! {
    panic!("\n{}\n\nbuild script failed, must exit now", s)
}
