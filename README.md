Unicorn Engine for AFLplusplus
==============================

This fork of [Unicorn Engine](http://www.unicorn-engine.org/) enables the fuzzing of arbitrary binary code under [AFLplusplus](https://github.com/vanhauser-thc/AFLplusplus).

The API design and implementation differs from the old afl-unicorn and are by @domenukk.

Those API permits a more fine-grained control in the harness and enabled persistent mode.

CompareCoverage and NeverZero counter are ported from AFL++ QEMU by @andreafioraldi.

API
---

The new exposed API is:

```c
uc_afl_ret uc_afl_forkserver_start(uc_engine *uc, uint64_t *exits, size_t exit_count)
```

```c
int uc_afl_emu_start(uc_engine *uc)
```

```c
uc_afl_ret uc_afl_next(uc_engine *uc)
```

```c
uc_afl_ret uc_afl_fuzz(
        uc_engine *uc, 
        char* input_file, 
        uc_afl_cb_place_input_t place_input_callback, 
        uint64_t *exits, 
        size_t exit_count, 
        uc_afl_cb_validate_crash_t validate_crash_callback, 
        bool always_validate,
        uint32_t persistent_iters,
        void *data
)
```

Unicorn Engine
==============

[![Join the chat at https://gitter.im/unicorn-engine/chat](https://badges.gitter.im/unicorn-engine/unicorn.svg)](https://gitter.im/unicorn-engine/chat?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/unicorn-engine/unicorn.svg?branch=master)](https://travis-ci.org/unicorn-engine/unicorn)
[![pypi downloads](https://pepy.tech/badge/unicorn)](https://pepy.tech/project/unicorn)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/unicorn.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:unicorn)

Unicorn is a lightweight, multi-platform, multi-architecture CPU emulator framework
based on [QEMU](http://qemu.org).

Unicorn offers some unparalleled features:

- Multi-architecture: ARM, ARM64 (ARMv8), M68K, MIPS, PowerPC, SPARC, and X86 (16, 32, 64-bit)
- Clean/simple/lightweight/intuitive architecture-neutral API
- Implemented in pure C language, with bindings for Crystal, Clojure, Visual Basic, Perl, Rust, Ruby, Python, Java, .NET, Go, Delphi/Free Pascal, Haskell, Pharo, and Lua.
- Native support for Windows & *nix (with Mac OSX, Linux, *BSD & Solaris confirmed)
- High performance via Just-In-Time compilation
- Support for fine-grained instrumentation at various levels
- Thread-safety by design
- Distributed under free software license GPLv2

Further information is available at http://www.unicorn-engine.org


License
-------

This project is released under the [GPL license](COPYING).


Compilation & Docs
------------------

See [docs/COMPILE.md](docs/COMPILE.md) file for how to compile and install Unicorn.

More documentation is available in [docs/README.md](docs/README.md).


Contact
-------

[Contact us](http://www.unicorn-engine.org/contact/) via mailing list, email or twitter for any questions.


Contribute
----------

If you want to contribute, please pick up something from our [Github issues](https://github.com/unicorn-engine/unicorn/issues).

We also maintain a list of more challenged problems in a [TODO list](https://github.com/unicorn-engine/unicorn/wiki/TODO).

[CREDITS.TXT](CREDITS.TXT) records important contributors of our project.

