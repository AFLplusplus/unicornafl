# Compatibility and ensure we use the unicorn library from the unicorn bindings
from unicorn import *

# Now we load unicornafl.abi3.so and since we already loaded libunicorn.so by 
# unicorn bindings, we won't load a duplicate one.
from unicornafl.unicornafl import uc_afl_fuzz as uc_afl_fuzz_impl
from unicornafl.unicornafl import uc_afl_fuzz_custom as uc_afl_fuzz_custom_impl
from unicornafl.unicornafl import UC_AFL_RET_OK, \
    UC_AFL_RET_ERROR, \
    UC_AFL_RET_CHILD, \
    UC_AFL_RET_NO_AFL, \
    UC_AFL_RET_CALLED_TWICE, \
    UC_AFL_RET_FINISHED, \
    UC_AFL_RET_INVALID_UC, \
    UC_AFL_RET_UC_ERR, \
    UC_AFL_RET_LIBAFL, \
    UC_AFL_RET_FFI
import ctypes
from typing import Any, Callable, List, Optional


UC_AFL_PLACE_INPUT_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p
)

UC_AFL_VALIDATE_CRASH_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p
)

UC_AFL_FUZZ_CALLBACK_CB = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p
)

_data_dict = {}
_data_idx = 0

def _place_input_cb(uc, input, input_len, persistent_round, idx):
    cb, _, _, uc, data = _data_dict[idx]
    input_bs = ctypes.cast(input, ctypes.POINTER(ctypes.c_char * input_len)).contents
    if cb is not None:
        ret = cb(uc, input_bs, persistent_round, data)
        if ret is False: # None is considered as True, for unicornafl compatibility
            return False
        return True
    else:
        return True


def _validate_crash_cb(uc, result, input, input_len, persistent_round, idx):
    _, cb, _, uc, data = _data_dict[idx]
    input_bs = ctypes.cast(input, ctypes.POINTER(ctypes.c_char * input_len)).contents
    if cb is not None:
        ret = cb(uc, result, input_bs, persistent_round, data)
        if ret is False: # None is considered as True, for unicornafl compatibility
            return False
        return True
    else:
        return True

def _fuzz_callback_cb(uc, idx):
    _, _, cb, uc, data = _data_dict[idx]

    return cb(uc, data)


class UcAflError(Exception):

    def __init__(self, errno=UC_AFL_RET_ERROR, message=None):
        super().__init__()
        self.errno = errno
        self.message = message

    def __str__(self):
        # type: (UcAflError) -> str
        if self.message:
            return self.message
        return {
            UC_AFL_RET_CHILD: "Fork worked. we are a child (no Error)",
            UC_AFL_RET_NO_AFL: "No AFL, no need to fork (but no real Error)",
            UC_AFL_RET_FINISHED: "We forked before but now AFL is gone (time to quit)",
            UC_AFL_RET_CALLED_TWICE: "Forkserver already running. This may be an error.",
            UC_AFL_RET_ERROR: "Something went horribly wrong in the parent!",
            UC_AFL_RET_FFI: "Unexpected FFI error, probably the unicorn version unicornafl built is not the same as Python dependency, consider rerun with RUST_LOG=trace",
            UC_AFL_RET_LIBAFL: "Error in LibAFL, consider rerun with RUST_LOG=trace",
            UC_AFL_RET_INVALID_UC: "Invalid unicorn pointer.",
            UC_AFL_RET_UC_ERR: "Error from unicorn."
        }[self.errno]

    def __eq__(self, other):
        # type: (UcAflError) -> str
        if isinstance(other, int):
            return self.errno == other
        elif isinstance(other, str):
            return self.message == other
        elif isinstance(other, UcAflError):
            return self.errno == other.errno
        elif other is None:
            return None
        else:
            raise ValueError("Tried to compare UcAflError to {} ({})".format((type(other), other)))

def __handle_input_string(input_file: Optional[str | bytes]) -> int:
    if isinstance(input_file, str):
        return \
            ctypes.cast(
                ctypes.create_string_buffer(input_file.encode('utf-8')),
                ctypes.c_void_p
            ).value
    elif isinstance(input_file, bytes):
        return \
           ctypes.cast(
               ctypes.create_string_buffer(input_file),
               ctypes.c_void_p
           ).value
    elif input_file is None:
        return 0
    else:
        raise TypeError("Input file should be string or bytes or None")

def uc_afl_fuzz(uc: Uc,
                input_file: Optional[str | bytes],
                place_input_callback: Callable,
                exits: List[int],
                validate_crash_callback: Callable = None,
                always_validate: bool = False,
                persistent_iters: int = 1,
                data: Any = None):
    global _data_idx, _data_dict

    # Someone else is fuzzing, quit!
    # For unicornafl compatiblity
    if len(_data_dict) != 0:
        raise UcAflError(UC_AFL_RET_CALLED_TWICE)

    _data_idx += 1
    idx = _data_idx # 1 will be interpreted as None so we skip it
    _data_dict[idx] = (place_input_callback, validate_crash_callback, None, uc, data)
    exits_len = len(exits)
    exits_array = (ctypes.c_uint64 * exits_len)()

    for i, exit in enumerate(exits):
        exits_array[i] = exit

    cb1 = ctypes.cast(UC_AFL_PLACE_INPUT_CB(
        _place_input_cb), UC_AFL_PLACE_INPUT_CB)
    cb2 = ctypes.cast(UC_AFL_VALIDATE_CRASH_CB(
        _validate_crash_cb), UC_AFL_VALIDATE_CRASH_CB)

    input_file = __handle_input_string(input_file)
    err = uc_afl_fuzz_impl(
        uc._uch.value,
        input_file,
        ctypes.cast(cb1, ctypes.c_void_p).value,
        ctypes.cast(
            exits_array, ctypes.c_void_p
        ).value,
        exits_len,
        ctypes.cast(cb2, ctypes.c_void_p).value,
        always_validate,
        persistent_iters,
        ctypes.cast(idx, ctypes.c_void_p).value
    )
    if err != UC_AFL_RET_OK:
        del _data_dict[idx]
        raise UcAflError(err)

    del _data_dict[idx]
    # Really?
    return err

def uc_afl_fuzz_custom(uc: Uc,
                       input_file: Optional[str | bytes],
                       place_input_callback: Callable,
                       fuzzing_callback: Callable,
                       validate_crash_callback: Callable = None,
                       always_validate: bool = False,
                       persistent_iters: int = 1,
                       data: Any = None):
    global _data_idx, _data_dict

    # Someone else is fuzzing, quit!
    # For unicornafl compatiblity
    if len(_data_dict) != 0:
        raise UcAflError(UC_AFL_RET_CALLED_TWICE)

    _data_idx += 1
    idx = _data_idx # 1 will be interpreted as None so we skip it
    _data_dict[idx] = (place_input_callback, validate_crash_callback, fuzzing_callback, uc, data)

    cb1 = ctypes.cast(UC_AFL_PLACE_INPUT_CB(
        _place_input_cb), UC_AFL_PLACE_INPUT_CB)
    cb2 = ctypes.cast(UC_AFL_VALIDATE_CRASH_CB(
        _validate_crash_cb), UC_AFL_VALIDATE_CRASH_CB)
    cb3 = ctypes.cast(UC_AFL_FUZZ_CALLBACK_CB(
        _fuzz_callback_cb), UC_AFL_FUZZ_CALLBACK_CB)

    input_file = __handle_input_string(input_file)
    err = uc_afl_fuzz_custom_impl(
        uc._uch.value,
        input_file,
        ctypes.cast(cb1, ctypes.c_void_p).value,
        ctypes.cast(cb3, ctypes.c_void_p).value,
        ctypes.cast(cb2, ctypes.c_void_p).value,
        always_validate,
        persistent_iters,
        ctypes.cast(idx, ctypes.c_void_p).value
    )
    
    if err != UC_AFL_RET_OK:
        del _data_dict[idx]
        raise UcAflError(err)

    del _data_dict[idx]
    # Really?
    return err

# Compatibility monkeypatch
def monkeypatch():
    Uc.afl_fuzz = uc_afl_fuzz