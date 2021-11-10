## Unicorn2AFL

The project name `Unicorn2afl` stands for both "Uncorn2 AFL" and "Unicorn to(2) AFL". The code is mostly from original [unicornafl](https://github.com/AFLplusplus/unicornafl).

## Compile

Don't forget to update submodule before building.

```bash
git submodule update --init --recursive
mkdir build
cd build
cmake ..
make
```

Or if you would like python bindings.

```bash
git submodule update --init --recursive
cd bindings/python/
python3 -m pip install -e .
```

## API

The only API currently unicorn2afl exposes is:

```C
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

## Migration

While trying to keep the maximum compatiblity with unicornafl, unicorn2afl still needs some minor changes to your existing fuzzer.

If you are writing your fuzzer in C, in most cases it should work as a drop-in replacement. However with python, you need to change

```python
import unicornafl as UcAfl

UcAfl.monkeypatch()
```

to

```python
import unicorn2afl as UcAfl
from unicorn import * # unicorn2afl no longer provide unicorn related definition.
```