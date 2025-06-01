# Rust Usage for UnicornAFL

To use UnicornAFL with Rust, you should create a new Rust package, and add the following line into the `[dependencies]` section in `Cargo.toml`:

```toml
unicornafl = { git = "https://github.com/AFLplusplus/unicornafl", branch = "main" }
```

Before building the new package, make sure that you have installed dependencies to build [Unicorn](https://github.com/unicorn-engine/unicorn).

## API usage

After declaring UnicornAFL as a dependency, you could now write your own fuzzing harness. The API for UnicornAFL is simple but powerful, which is the following two functions: `afl_fuzz` and `afl_fuzz_custom`.

### Simplified API

`unicornafl::afl_fuzz`

```rust
fn afl_fuzz<'a, D: 'a>(
    uc: Unicorn<'a, UnicornFuzzData<D>>,
    input_file: Option<PathBuf>,
    place_input_cb: impl FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'a,
    exits: Vec<u64>,
    persistent_iters: Option<u64>,
) -> Result<(), uc_afl_ret>;
```

Please don't be scared by the lifetime mark in function signature. In most time, you don't need to care about that.

`uc` is a unicorn instance created in advance. See the following [Creating Unicorn Instance](#Creating-Unicorn-Instance) for more details.

`input_file` is a path to input file. If you are using the fuzzing mode, just pass `None` to this argument, and the input seed directory should be passed to `afl-fuzz` instead. For standalone mode, UnicornAFL takes input using this argument.

`place_input_cb` is the callback for UnicornAFL to place received input into Unicorn's memory space. This closure takes three arguments: a mutable reference to the unicorn intance which users could use to read/write unicorn's emulated CPU/memory in this callback, a reference to the input buffer, the persistent round (which means how many times have this harness executed without exiting and forking to another child process). This closure should return a bool, indicating whether this input is acceptable.

`exits` means the exit points for Unicorn. When the Unicorn instance reaches one of the given exit address, UnicornAFL will switch to next round.

`persistent_iters` specifies how many times should this harness being executed persistently until the parent forks another child. For simplicity, you could just pass `Some(1)` here, which means always exiting and forking whenever this harness ends. However, if you want to write a more efficient harness, you should consider running persistently. Passing `None` here means never exiting or forking unless the process crashes, just run persistently.

This function returns a `Result`. If it is an `Err`, this means unexpected things happened during fuzzing that you should take care of.

To use this API, you could write code like this:

```rust
// Creating uc
// Other setup ...

if let Err(err) = unicornafl::afl_fuzz(
    uc,
    None,
    |uc, input, persistent_round| {
        // Custom logics here, use uc.reg_write() or uc.mem_write(), for instance.
        true
    },
    vec![0x4001000, 0x4002000],
    Some(1),
) {
    eprintln!("Unexpected happened! {err:?}");
}
```

### Advanced API

`unicornafl::afl_fuzz_custom`

```rust
fn afl_fuzz_custom<'a, D: 'a>(
    uc: Unicorn<'a, UnicornFuzzData<D>>,
    input_file: Option<PathBuf>,
    callbacks: impl UnicornAflExecutorHook<'a, D>,
    exits: Vec<u64>,
    always_validate: bool,
    persistent_iters: Option<u64>,
) -> Result<(), uc_afl_ret>;
```

Some of the arguments are the same as the simplified API. The only difference is `callbacks` and `always_validate`.

`callbacks` is a structure that users should define and implement on their own. The definition of `UnicornAflExecutorHook` is in [executor.rs](../src/executor.rs), which is well-documented that you should look at first.

There are three methods in `UnicornAflExecutorHook`:

* `place_input`

    This is required to implement. The meaning of this method is the same as `place_input_cb` in simplified API.
* `validate_crash`

    This is optional to implement. This will be invoked if Unicorn encounters exceptions when executing the harness, or users specify `always_validate` to be true. This could be used to eliminate false positives during fuzzing. If this function returns `false`, then the AFL++ main executable will not treat this round as crash.
* `fuzz`

    This is optional to implement. UnicornAFL will use this function to start one execution round, and when this function stops, UnicornAFL knows this round has ended. By default, UnicornAFL will just use `uc.emu_start()`.

Note that all these three methods take `&mut self` as input. This means if there are some data shared across persistent rounds and are used by these callbacks, you could store it in the structure. However, you should be noted that when the max persistent round is reached (which you specified in `persistent_round` argument), current process will exit and the parent will fork a new one whose initial state is just before the invoking of `afl_fuzz_custom`. As a result, you should save your data after `afl_fuzz_custom` ends, and read last round's data before `afl_fuzz_custom`.

To use this API, you could write code like this:

```rust
use unicornafl::UnicornAflExecutorHook;

struct MyOwnExecutorHook {
    my_data: usize
}

impl UnicornAflExecutorHook for MyOwnExecutorHook {
    fn place_input(
        &mut self,
        uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
        input: &[u8],
        persistent_round: u64,
    ) -> bool {
        // Custom logics here, use uc.reg_write() or uc.mem_write(), for instance.
        true
    }

    // I don't need to implement `validate_crash` and `fuzz`.
}

fn main() {
    // Creating uc
    // Other setup ...

    if let Err(err) = unicornafl::afl_fuzz_custom(
        uc,
        None,
        MyOwnExecutorHook { my_data: 0 },
        vec![0x4001000, 0x4002000],
        false,
        Some(1),
    ) {
        eprintln!("Unexpected happened! {err:?}");
    }
}
```

### Creating Unicorn Instance

Before using fuzzing APIs, you should create unicorn instance on your own. It should be noted that, UnicornAFL does not need to know the actual target to fuzz. Instead, you should manually setup your target in Unicorn instance (for example, map the codes in unicorn's memory space). To create a Unicorn instance used for UnicornAFL for fuzzing, you should do things like:

```rust
use unicornafl::UnicornFuzzData;

// Set up arch, mode, and some shared fuzzing data.
let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, UnicornFuzzData::default());
```

`UnicornFuzzData` is a helper for maintaining shared data during execution. In general, there are two kinds of data to share when using UnicornAFL: 1. Data that need to be shared during persistent execution, and is only used in `UnicornAflExecutorHook`'s callbacks, which means these data are only used **before** or **after** one execution round. 2. Data that need to be shared during one execution round, and is used in multiple hooks of Unicorn (code hooks, memory hooks, etc.). The former data should be stored in the structure that implements `UnicornAflExecutorHook`, and the latter one is hat `UnicornFuzzData` is used for.

In fact, `UnicornFuzzData` is a wrapper over arbitrary generic structure, which you could define your own data. Inside Unicorn's hooks, users could use `get_data()` or `get_data_mut()` to access the `UnicornFuzzData` structure, which can be further used to access user-defined data using `.user_data` field.

For example:

```rust
use unicornafl::UnicornFuzzData;

struct MyFuzzData {
    hook_call_count: usize
}

let mut uc = Unicorn::new_with_data(
    Arch::X86,
    Mode::MODE_64,
    UnicornFuzzData::new(
        MyFuzzData {
            hook_call_count: 0
        }
    )
);

uc.add_code_hook(/* ... */, |uc, _, _| {
    let my_fuzz_data = &mut uc.get_data_mut().user_data;
    my_fuzz_data.hook_call_count += 1;
}).unwrap();
```

However, you should note that the `get_data` or `get_data_mut` would require `Rc` check, which may potentially decrease the performance. As a result, you should minimize such data accesses.

## Tips

### Build release version

In Rust, the default profile used for `cargo build` is debug build, which is slow. To optimize fuzzing throughput, you should use release profile by `cargo build --release`. Moreover, inside your `Cargo.toml`, it is suggested to add

```toml
[profile.release]
lto = true
codegen-units = 1
```

This may significantly increase compile time, but the generated binary is very optimized.

### Use a different version of Unicorn

It should be noted that the internal of UnicornAFL depends heavily on some newest Unicorn APIs. As a result, older version of Unicorn may not work. However, if you want to use your own version of Unicorn, you should modify your `Cargo.toml`, add the following blocks:

```toml
[patch.'https://github.com/unicorn-engine/unicorn']
unicorn-engine = { path = "/my/own/path/to/local/unicorn" }
# or
unicorn-engine = { git = "http://my/own/unicorn/fork" }
```

For more, see [Overriding Dependencies](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html).

### Debugging

Inside UnicornAFL, there are many logs could be used for debugging. To enable logging, the easiest way is to add dependency for [env_logger](https://crates.io/crates/env_logger), and at the beginning of your `main` function:

```rust
fn main() {
    env_logger::init();
    // ...
}
```

And when running, passing `RUST_LOG=trace` as environment. (`AFL_DEBUG=1` is also needed if you are using `afl-fuzz` to run the harness)

The logging in UnicornAFL utilizes the [log crate](https://crates.io/crates/log), which supports various type of logging backend. If you want to customize the logging behavior, you are suggested to read that crate's document. `env_logger` also supports many customizations. For example, if you only want to see your own logs, and don't want to see logs from UnicornAFL, you could use environment variable `RUST_LOG=trace,unicornafl=off`.
