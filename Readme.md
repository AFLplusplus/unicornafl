# UnicornAFL

UnicornAFL is a bridge between AFL++ and the [unicorn engine](https://github.com/unicorn-engine/unicorn). Generally, it allows you to fuzz any machine code in a few setups, with coverage, cmpcov, and cmplog support.

Starting from v3.0.0, unicornafl is fully rewritten with `libafl_targets` in Rust though we still provide Python and C bindings.

## Example

We provide a sample harness at [the examples](https://github.com/AFLplusplus/AFLplusplus/tree/stable/unicorn_mode/samples). We also have CI to test this for every commit and release.