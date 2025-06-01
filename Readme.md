# UnicornAFL

UnicornAFL is a bridge between AFL++ and the [unicorn engine](https://github.com/unicorn-engine/unicorn). Generally, it allows you to fuzz any machine code in a few setups, with coverage, cmpcov, and cmplog support.

Starting from v3.0.0, unicornafl is fully rewritten with `libafl_targets` in Rust though we still provide Python and C bindings.

## Usage

### Rust

To use `unicornafl` as a library, just add this to your `Cargo.toml`

```toml
unicornafl = { git = "https://github.com/AFLplusplus/unicornafl", branch = "main" }
```

`main` is used here because `unicorn` is not released yet. We will make it ready shortly.

For more details, please refer to [Rust usage](./docs/rust-usage.md).

### Python

At this moment, manual building is required (see below) but we will soon release wheels.

For more details, please refer to [Python usage](./docs/python-usage.md).

### C/C++

After building this repo, you could link the generated static archive or shared library with included C/C++ header file in [include/unicornafl.h](./include/unicornafl.h).

For more details, please refer to [C/C++ usage](./docs/c-usage.md).

## Build

Simply do:

```bash
git clone https://github.com/AFLplusplus/unicornafl
cd unicornafl
cargo build --release
```

For python bindings, we have:

```bash
maturin build --release
```

## Example && Minimal Tutorial

We provide a sample harness at [the examples](https://github.com/AFLplusplus/AFLplusplus/tree/stable/unicorn_mode/samples).

The target assembly is:

```
mov rax, rdx;
cmp rax, 0x114514;
je die;
xor rax, rax;
die:
  mov rax, [rax];
xor rax, rax;
```

We artifically make our harness stops at any of the `xor rax, rax` instruction. Therefore, if `rax==0x114514` is true, our harness will have an unmapped read error, which will be captured by `unicornafl` as a crash. Otherwise, it just stops without any crashes. You could start fuzzing by:

```bash
cargo build --example sample --release
# assume AFL++ is installed
afl-fuzz -i ./input -o ./output-8 -b 1 -g 8 -G 8 -V 60 -c 0 -- ./target/release/examples/sample @@ true
```

This shall find the crash instantly, thanks to the `cmplog` integration.

For more details, please refer to [Fuzzing using UnicornAFL](./docs/fuzzing.md).

## Migration

There should be nothing special migrating from unicornafl v2.x to unicornafl v3.x, execpt the way integrating with AFL++. If your harness builds and statically links against unicornafl directly, there is no longer needed for the unicorn mode with AFL++. However, if you are using Python, or using C/C++ with `libunicornafl.so` dynamically linked, unicorn mode (`-U` option) is still needed for `afl-fuzz` command line.
