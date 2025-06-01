# Python Usage for UnicornAFL

To use UnicornAFL with Python, you should clone this repository and build it yourself:

```shell
git clone --depth 1 https://github.com/AFLplusplus/unicornafl && cd unicornafl
cargo build --release
maturin build --release
```

Before building this repo, make sure that you have installed dependencies to build [Unicorn](https://github.com/unicorn-engine/unicorn), and installed stable Rust compiler with at least 1.87.0, and you should also install [maturin](https://www.maturin.rs).

After building this repo, there will be a wheel in `./target/wheels`, just use it.

## API usage

The API for UnicornAFL is simple but powerful, which is the following two functions: `uc_afl_fuzz` and `uc_afl_fuzz_custom`.

### Simplified API

`uc_afl_fuzz`

```python
def uc_afl_fuzz(uc: Uc,
                input_file: str,
                place_input_callback: Callable,
                exits: List[int],
                validate_crash_callback: Callable = None,
                always_validate: bool = False,
                persistent_iters: int = 1,
                data: Any = None): ...
```

`uc` is a unicorn instance created in advance. See the following [Creating Unicorn Instance](#Creating-Unicorn-Instance) for more details.

`input_file` is a path to input file. If you are using the fuzzing mode, just pass `None` to this argument, and the input seed directory should be passed to `afl-fuzz` instead. For standalone mode, UnicornAFL takes input using this argument.

`place_input_callback` is the callback for UnicornAFL to place received input into Unicorn's memory space. This callback takes four arguments: a pointer to the unicorn intance which users could use to read/write unicorn's emulated CPU/memory in this callback, input buffer, the persistent round (which means how many times have this harness executed without exiting and forking to another child process), and custom data. This callback should return a Bool, indicating whether this input is acceptable.

`exits` means the exit points for Unicorn. When the Unicorn instance reaches one of the given exit address, UnicornAFL will switch to next round.

`validate_crash_callback` is the callback for UnicornAFL when an error encounted when executing the harness. It takes five arguments: a pointer to the unicorn intance, a value indicating the error of Unicorn when exuecting the harness, the input buffer, the persistent round, and custom data. This callback should return a Bool, if it is `False`, then the AFL++ main executable will not treat this round as crash. This could be used to eliminate false positives during fuzzing.

`always_validate` means whether the `validate_crash_callback` will be invoked even if the Unicorn does not face errors during execution.

`persistent_iters` specifies how many times should this harness being executed persistently until the parent forks another child. For simplicity, you could just pass `1` here, which means always exiting and forking whenever this harness ends. However, if you want to write a more efficient harness, you should consider running persistently. Passing `0` here means never exiting or forking unless the process crashes, just run persistently.

`data` is a custom data. In each callback listed above, this pointer will also passed as the callback argument. By this way you could maintain some shared data across execution.

This function returns a `UcAflError` or value `UC_AFL_RET_OK`. If the return value is not `UC_AFL_RET_OK`, this means unexpected things happened during fuzzing that you should take care of.

### Advanced API

`uc_afl_fuzz_custom`

```python
def uc_afl_fuzz_custom(uc: Uc,
                       input_file: str,
                       place_input_callback: Callable,
                       fuzzing_callback: Callable,
                       validate_crash_callback: Callable = None,
                       always_validate: bool = False,
                       persistent_iters: int = 1,
                       data: Any = None): ...
```

Some of the arguments are the same as the simplified API. The only difference is the `fuzz_callbck` argument. UnicornAFL will use this function to start one execution round, and when this function stops, UnicornAFL knows this round has ended. By default, UnicornAFL will just use `uc_emu_start()`.

### Creating Unicorn Instance

Before using fuzzing APIs, you should create unicorn instance on your own. It should be noted that, UnicornAFL does not need to know the actual target to fuzz. Instead, you should manually setup your target in Unicorn instance (for example, map the codes in unicorn's memory space).

## Tips

### Use a different version of Unicorn

It should be noted that the internal of UnicornAFL depends heavily on some newest Unicorn APIs. As a result, older version of Unicorn may not work. However, if you want to use your own version of Unicorn, you should modify the `Cargo.toml` in this repo.

First, find the following line:

```toml
unicorn-engine = { git = "https://github.com/unicorn-engine/unicorn", branch = "dev" }
```

If you want to use a Unicorn in local filesystem, you should change this line to

```toml
unicorn-engine = { path = "/path/to/unicorn/bindings/rust" }
```

Note that the `bindings/rust` suffix is necessary.

If you want to use a forked Unicorn or Unicorn in remote Git server, you should change this line to

```toml
unicorn-engine = { git = "http://my/own/unicorn/fork" }
```

### Debugging

Inside UnicornAFL, there are many logs could be used for debugging. To enable logging, you should compile this repo using

```shell
cargo build --release --features env_logger
```

And when running, passing `RUST_LOG=trace` as environment. (`AFL_DEBUG=1` is also needed if you are using `afl-fuzz` to run the harness)
