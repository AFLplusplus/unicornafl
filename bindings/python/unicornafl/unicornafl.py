from typing import Any, Callable, List
from unicorn import *
import ctypes
import pkg_resources
import sys
import distutils
import os

from pathlib import Path

_lib = {'darwin': 'libunicornafl.dylib',
        'linux': 'libunicornafl.so',
        'linux2': 'libunicornafl.so'}.get(sys.platform, "libunicornafl.so")

_path_list = [Path(pkg_resources.resource_filename(__name__, 'lib')),
              Path(os.path.realpath(__file__)).parent / "lib",
              Path(''),
              Path(distutils.sysconfig.get_python_lib()),
              Path("/usr/local/lib/" if sys.platform ==
                   'darwin' else '/usr/lib64'),
              Path(os.getenv('PATH', ''))]


def _load_lib(path: Path):
    try:
        return ctypes.cdll.LoadLibrary(path / _lib)
    except OSError as e:
        return None


_uc2afl = None

for _p in _path_list:
    _uc2afl = _load_lib(_p)
    if _uc2afl is not None:
        break
else:
    raise ImportError("Fail to load the dynamic library for unicornafl.")


# typedef enum uc_afl_ret {
#     UC_AFL_RET_OK = 0,
#     UC_AFL_RET_ERROR,
#     UC_AFL_RET_CHILD,
#     UC_AFL_RET_NO_AFL,
#     UC_AFL_RET_CALLED_TWICE,
#     UC_AFL_RET_FINISHED,
# } uc_afl_ret;


UC_AFL_RET_OK = 0
UC_AFL_RET_ERROR = 1
UC_AFL_RET_CHILD = 2
UC_AFL_RET_NO_AFL = 3
UC_AFL_RET_CALLED_TWICE = 4
UC_AFL_RET_FINISHED = 5

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
            UC_AFL_RET_ERROR: "Something went horribly wrong in the parent!"
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

# typedef bool (*uc_afl_cb_place_input_t)(uc_engine* uc, char* input,
#                                         size_t input_len,
#                                         uint32_t persistent_round, void* data);

# typedef bool (*uc_afl_cb_validate_crash_t)(uc_engine* uc, uc_err unicorn_result,
#                                            char* input, int input_len,
#                                            int persistent_round, void* data);

# typedef uc_err (*uc_afl_fuzz_cb_t)(uc_engine *uc, void *data);

UC_AFL_PLACE_INPUT_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p
)

UC_AFL_VALIDATE_CRASH_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p
)

UC_AFL_FUZZ_CALLBACK_CB = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p
)

# uc_afl_ret uc_afl_fuzz(uc_engine* uc, char* input_file,
#                        uc_afl_cb_place_input_t place_input_callback,
#                        uint64_t* exits, size_t exit_count,
#                        uc_afl_cb_validate_crash_t validate_crash_callback,
#                        bool always_validate, uint32_t persistent_iters,
#                        void* data);
_uc2afl.uc_afl_fuzz.restype = ctypes.c_int
_uc2afl.uc_afl_fuzz.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.c_void_p, ctypes.c_bool, ctypes.c_uint32, ctypes.c_void_p)

# uc_afl_ret uc_afl_fuzz_custom(uc_engine* uc, char* input_file,
#                            uc_afl_cb_place_input_t place_input_callback,
#                            uc_afl_fuzz_cb_t fuzz_callbck,
#                            uc_afl_cb_validate_crash_t validate_crash_callback,
#                            bool always_validate, uint32_t persistent_iters,
#                            void* data)
_uc2afl.uc_afl_fuzz_custom.restype = ctypes.c_int
_uc2afl.uc_afl_fuzz_custom.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_bool, ctypes.c_uint32, ctypes.c_void_p)
# Is it necessary?
_data_dict = {}
_data_idx = 0


def _place_input_cb(uc, input, input_len, persistent_round, idx):
    cb, _, _, uc, data = _data_dict[idx]
    input_bs = ctypes.string_at(input, input_len)
    if cb is not None:
        ret = cb(uc, input_bs, persistent_round, data)
        if ret is False: # None is considered as True, for unicornafl compatibility
            return False
        return True
    else:
        return True


def _validate_crash_cb(uc, result, input, input_len, persistent_round, idx):
    _, cb, _, uc, data = _data_dict[idx]
    input_bs = ctypes.string_at(input, input_len)
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


def uc_afl_fuzz(uc: Uc,
                input_file: str,
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

    err = _uc2afl.uc_afl_fuzz(uc._uch, input_file.encode("utf-8"), cb1, ctypes.cast(
        exits_array, ctypes.c_void_p), exits_len, cb2, always_validate, persistent_iters, ctypes.cast(idx, ctypes.c_void_p))

    if err != UC_AFL_RET_OK:
        del _data_dict[idx]
        raise UcAflError(err)

    del _data_dict[idx]
    # Really?
    return err

def uc_afl_fuzz_custom(uc: Uc,
                       input_file: str,
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

    err = _uc2afl.uc_afl_fuzz_custom(uc._uch, input_file.encode("utf-8"), cb1, cb3, 
        cb2, always_validate, persistent_iters, ctypes.cast(idx, ctypes.c_void_p))

    if err != UC_AFL_RET_OK:
        del _data_dict[idx]
        raise UcAflError(err)

    del _data_dict[idx]
    # Really?
    return err

# Compatibility monkeypatch
def monkeypatch():
    Uc.afl_fuzz = uc_afl_fuzz
