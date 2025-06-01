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
    always_validate: bool,
    persistent_iters: Option<u64>,
) -> Result<(), uc_afl_ret>;
```

Please don't be scared by the lifetime mark in function signature. In most time, you don't need to care about that.

`uc` is a unicorn instance created in advance. See the following [Creating Unicorn Instance](#Creating-Unicorn-Instance) for more details.

`input_file` is a path to input file. If you are using the fuzzing mode, just pass `None` to this argument, and the input seed directory should be passed to `afl-fuzz` instead. For standalone mode, UnicornAFL takes input using this argument.

`place_input_cb` is the callback for UnicornAFL to place received input into Unicorn's memory space. This closure takes three arguments: a mutable reference to the unicorn intance, a reference to the input buffer, the persistent round (which means how many times have this harness executed without exiting and forking to another child process). This closure should return a bool, indicating whether this input is acceptable.

`exits` means the exit points for Unicorn. When the Unicorn instance reaches one of the given exit address, UnicornAFL will switch to next round.

`always_validate`

### Advanced API

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

### Creating Unicorn Instance

## Tips


