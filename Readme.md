# UnicornAFL

The project builds a bridge between AFL++ and unicorn engine.

## Compile

If you have unicorn installed globally, you may just:

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

Or if you prefer a latest build, don't forget to update submodule before building.

```bash
git submodule update --init --recursive
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DUCAFL_NO_LOG=on # disable logging for the maximum speed
make
```

Or if you would like python bindings.

```bash
python3 -m pip install unicornafl
```

Or build it by yourself.

```bash
git submodule update --init --recursive
cd bindings/python/
python3 -m pip install -e .
```

## API

The only API currently unicornafl exposes is:

```C
//
//  Start our fuzzer.
//
//  If no afl-fuzz instance is found, this function is almost identical to uc_emu_start()
//  
//  @uc: The uc_engine return-ed from uc_open().
//  @input_file: This usually is the input file name provided by the command argument.
//  @place_input_callback: This callback is triggered every time a new child is generated. It returns 
//                         true if the input is accepted, or the input would be skipped.
//  @exits: All possible exits.
//  @exit_count: The count of the @exits array.
//  @validate_crash_callback: This callback is triggered every time to check if we are crashed.                     
//  @always_validate: If this is set to False, validate_crash_callback will be only triggered if
//                    uc_emu_start (which is called internally by uc_afl_fuzz) returns an error. Or
//                    the validate_crash_callback will be triggered every time.
//  @persistent_iters: Fuzz how many times before forking a new child.
//  @data: The extra data user provides.
//
//  @uc_afl_ret: The error the fuzzer returns.
UNICORNAFL_EXPORT
uc_afl_ret uc_afl_fuzz(uc_engine* uc, char* input_file,
                       uc_afl_cb_place_input_t place_input_callback,
                       uint64_t* exits, size_t exit_count,
                       uc_afl_cb_validate_crash_t validate_crash_callback,
                       bool always_validate, uint32_t persistent_iters,
                       void* data);
```

## Migration

unicornafl 2.x remains the same API compatible to unicornafl 1.x so there is no extra work to migrate.

However, a change in unicornafl 2.x is that the monkey patch is no longer needed for Python, which is a bit more elegant. For instance:

```python
# works with both unicornafl 1.x and unicornafl 2.x
import unicornafl

unicornafl.monkeypatch()

uc.afl_fuzz(...)
```

In unicornafl 2.x, we recommend:

```python
# unicornafl 2.x only!
import unicornafl

unicornafl.uc_afl_fuzz(uc, ...)
```