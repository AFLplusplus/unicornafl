# Fuzzing using UnicornAFL

UnicornAFL is a bridge between AFL++ and Unicorn. 

## Running Mode

The harness built with UnicornAFL supports two running mode: standalone mode and fuzzing mode.

### Standalone Mode

This mode is not intended for fuzzing. Instead, you should use this mode to check whether you have written the correct harness, and it is also helpful to analyze the crashes found by AFL++.

To run harness in standalone mode, you should directly execute the harness executable that uses UnicornAFL without using `afl-fuzz`. The commandline options for executing this harness is defined by users. Users need to then pass correct value to the parameter of UnicornAFL API, especially the `input_file` argument. The commandline harness executable should take a path to a file, then if it is passed to the `input_file`, UnicornAFL will use that file as input to execute the Unicorn engine for the target being tested.

Before any fuzzing, you should create a normal input seed that don't expect to crash the harness. Then you should run in standalone mode to check that the harness can execute normally. Then if anything unexpected happened during standalone mode, this means you write the wrong harness.

### Fuzzing mode

After testing the correctness of the harness, then you can fuzz the harness using `afl-fuzz`. To use `afl-fuzz` with UnicornAFL, you should first make sure how you build the harness.

If you are using Rust, or if you are using C/C++ that statically link the `libunicornafl.a`, then the minimized working example is

```shell
afl-fuzz \
    -i input \
    -o output \
    -- \
    ./your-harness --and-your-own-harness-options
```

If you are using Python, or if you are using C/C++ that dynamically link the `libunicornafl.so`, then the minimized working example is

```shell
afl-fuzz \
    -U \
    -i input \
    -o output \
    -- \
    ./your-harness --and-your-own-harness-options
```

The `-U` option specifies that this is the legacy Unicorn mode.

Note that you don't need to use `@@` to specify input file, we use shared memory to get input seed.

## Persistent Fuzzing

UnicornAFL supports persistent fuzzing. Instead of forking at the beginning of each execution round, persistent fuzzing will just do a `for`-loop to execute the target. The overall steps are:

1. Users invoke `afl-fuzz` and pass the path to your UnicornAFL harness.
2. `afl-fuzz` spawns a harness process (which we call it harness parent).
3. The harness process will execute until the beginning of one of the UnicornAFL's APIs (`uc_afl_fuzz` and `uc_afl_fuzz_custom`). Then it will fork itself, producing another process (which we call it harness child).
4. The harness child contains a loop that executes the target with Unicorn engine repeatly. Each round is counted as a execution for `afl-fuzz`.
5. When the user specified `persistent_round` is achieved, or the harness child process crashes (which is rare, since the exceptions shall be captured by Unicorns already), the harness child end. The harness parent will fork a new harness child and do the same thing.

Since in the harness child, the target is executed repeatly, it is very important that **you should restore the Unicorn's state after each round** unless you can make sure the target does not modify Unicorn's CPU and memory in this round. To make things easier, you can just specify `persistent_round` as 1, which downgrade to the legacy forkserver-based fuzzing, which is significantly slower.

## CMPLOG and CMPCOV

UnicornAFL also supprost CMPLOG and CMPCOV in AFL++. If you don't know these terms, please refer to the AFL++'s documentation. In short, this is aimed to bypass the long comparison like `CMP RAX, 0x114514`.

To use CMPCOV mode, you should specify `UNICORN_AFL_CMPCOV=1` environment in `afl-fuzz`.

To use CMPLOG mode, you can just add `-c 0` option to `afl-fuzz`.

## Which language should I choose to use?

The language to choose may have a little affect on the throughput of fuzzing, while you should keep in mind that the main overhead is the target itself.

Although not benchmarked, Rust may be a slightly faster than C/C++ due to the power of inlining and LTO. The python version is much more slower. However, since the it only have a little affect, it is more appropriate if you choose the language that you are good at. Don't struggle with language itself, it is fuzzing that is all you need :)
