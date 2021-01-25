# Unicorn Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
import ctypes.util
import distutils.sysconfig
try:
    from typing import Optional, List, Callable, Any
except ImportError as _:
    pass

import pkg_resources
import inspect
import os.path
import sys
import weakref
import gc

from . import x86_const, arm64_const, unicorn_const as uc

def monkeypatch():
    # type: () -> None
    """
    If you call monkeypatch() before importing any other unicorn-based lib, it'll "just work".
    Any normal `import unicorn` will from now on return unicornafl.
    Good for 3rd Party libs using unicorn.
    They won't even notice the difference - but they can now use the AFL forkserver.
    """
    sys.modules["unicorn"] = sys.modules["unicornafl"]

if not hasattr(sys.modules[__name__], "__file__"):
    __file__ = inspect.getfile(inspect.currentframe())

_python2 = sys.version_info[0] < 3
if _python2:
    range = xrange

_lib = { 'darwin': 'libunicornafl.dylib',
         'win32': 'unicornafl.dll',
         'cygwin': 'cygunicornafl.dll',
         'linux': 'libunicornafl.so',
         'linux2': 'libunicornafl.so' }


# Windows DLL in dependency order
_all_windows_dlls = (
    "libwinpthread-1.dll",
    "libgcc_s_seh-1.dll",
    "libgcc_s_dw2-1.dll",
)

_loaded_windows_dlls = set()

def _load_win_support(path):
    for dll in _all_windows_dlls:
        if dll in _loaded_windows_dlls:
            continue

        lib_file = os.path.join(path, dll)
        if ('/' not in path and '\\' not in path) or os.path.exists(lib_file):
            try:
                #print('Trying to load Windows library', lib_file)
                ctypes.cdll.LoadLibrary(lib_file)
                #print('SUCCESS')
                _loaded_windows_dlls.add(dll)
            except OSError as e:
                #print('FAIL to load %s' %lib_file, e)
                continue

# Initial attempt: load all dlls globally
if sys.platform in ('win32', 'cygwin'):
    _load_win_support('')

def _load_lib(path):
    try:
        if sys.platform in ('win32', 'cygwin'):
            _load_win_support(path)

        lib_file = os.path.join(path, _lib.get(sys.platform, 'libunicornafl.so'))
        #print('Trying to load shared library', lib_file)
        dll = ctypes.cdll.LoadLibrary(lib_file)
        #print('SUCCESS')
        return dll
    except OSError as e:
        #print('FAIL to load %s' %lib_file, e)
        return None

_uc = None

# Loading attempts, in order
# - user-provided environment variable
# - pkg_resources can get us the path to the local libraries
# - we can get the path to the local libraries by parsing our filename
# - global load
# - python's lib directory
# - last-gasp attempt at some hardcoded paths on darwin and linux

_path_list = [os.getenv('LIBUNICORNAFL_PATH', None),
              pkg_resources.resource_filename(__name__, 'lib'),
              os.path.join(os.path.split(__file__)[0], 'lib'),
              '',
              distutils.sysconfig.get_python_lib(),
              "/usr/local/lib/" if sys.platform == 'darwin' else '/usr/lib64',
              os.getenv('PATH', '')]

#print(_path_list)
#print("-" * 80)

for _path in _path_list:
    if _path is None: continue
    _uc = _load_lib(_path)
    if _uc is not None: break
else:
    raise ImportError("ERROR: fail to load the dynamic library.")

__version__ = "%u.%u.%u" % (uc.UC_VERSION_MAJOR, uc.UC_VERSION_MINOR, uc.UC_VERSION_EXTRA)
__hasafl__ = True

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

ucerr = ctypes.c_int
ucaflret = ctypes.c_int
uc_engine = ctypes.c_void_p
uc_context = ctypes.c_void_p
uc_hook_h = ctypes.c_size_t

class _uc_mem_region(ctypes.Structure):
    _fields_ = [
        ("begin", ctypes.c_uint64),
        ("end",   ctypes.c_uint64),
        ("perms", ctypes.c_uint32),
    ]

#typedef bool (*uc_afl_cb_place_input_t)(uc_engine *uc, char *input,
#                                       size_t input_len, uint32_t persistent_round, void *data);
AFL_PLACE_INPUT_CB = ctypes.CFUNCTYPE(ctypes.c_bool, uc_engine, ctypes.POINTER(ctypes.c_char),
                                        ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p)

#typedef bool (*uc_afl_cb_validate_crash_t)(uc_engine *uc, uc_err unicorn_result, char *input,
#                                       int input_len, int persistent_round, void *data);
AFL_VALIDATE_CRASH_CB = ctypes.CFUNCTYPE(ctypes.c_bool, uc_engine, ucerr, ctypes.POINTER(ctypes.c_char),
                                        ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p)

def from_param(cls, obj):
    """
    Allow NULL pointer for crash cb
    See https://sourceforge.net/p/ctypes/mailman/message/9636230/
    """
    if obj is None:
        return None # return a NULL pointer
    return ctypes._CFuncPtr.from_param(obj)

AFL_VALIDATE_CRASH_CB.from_param = classmethod(from_param)

_setup_prototype(_uc, "uc_version", ctypes.c_uint, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
_setup_prototype(_uc, "uc_arch_supported", ctypes.c_bool, ctypes.c_int)
_setup_prototype(_uc, "uc_open", ucerr, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(uc_engine))
_setup_prototype(_uc, "uc_close", ucerr, uc_engine)
_setup_prototype(_uc, "uc_strerror", ctypes.c_char_p, ucerr)
_setup_prototype(_uc, "uc_errno", ucerr, uc_engine)
_setup_prototype(_uc, "uc_reg_read", ucerr, uc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_reg_write", ucerr, uc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_read", ucerr, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_write", ucerr, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_start", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_stop", ucerr, uc_engine)
_setup_prototype(_uc, "uc_hook_del", ucerr, uc_engine, uc_hook_h)
_setup_prototype(_uc, "uc_mem_map", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_mem_map_ptr", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_unmap", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_protect", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_query", ucerr, uc_engine, ctypes.c_uint32, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_uc, "uc_context_alloc", ucerr, uc_engine, ctypes.POINTER(uc_context))
_setup_prototype(_uc, "uc_free", ucerr, ctypes.c_void_p)
_setup_prototype(_uc, "uc_context_save", ucerr, uc_engine, uc_context)
_setup_prototype(_uc, "uc_context_restore", ucerr, uc_engine, uc_context)
_setup_prototype(_uc, "uc_context_size", ctypes.c_size_t, uc_engine)
_setup_prototype(_uc, "uc_context_free", ucerr, uc_context)
_setup_prototype(_uc, "uc_mem_regions", ucerr, uc_engine, ctypes.POINTER(ctypes.POINTER(_uc_mem_region)), ctypes.POINTER(ctypes.c_uint32))
_setup_prototype(_uc, "uc_afl_forkserver_start", ucaflret, uc_engine, ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t)
_setup_prototype(_uc, "uc_afl_fuzz", ucaflret,
        uc_engine, # unicorn engine
        ctypes.c_char_p, # input file
        AFL_PLACE_INPUT_CB, # place input cb
        ctypes.POINTER(ctypes.c_uint64), # exits
        ctypes.c_size_t, # exit_count
        AFL_VALIDATE_CRASH_CB, # validate crash cb
        ctypes.c_bool, # always_validate,
        ctypes.c_uint32, # persistent_iters
        ctypes.c_void_p) # data

# uc_hook_add is special due to variable number of arguments
_uc.uc_hook_add = _uc.uc_hook_add
_uc.uc_hook_add.restype = ucerr

UC_HOOK_CODE_CB = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p)
UC_HOOK_INSN_INVALID_CB = ctypes.CFUNCTYPE(ctypes.c_bool, uc_engine, ctypes.c_void_p)
UC_HOOK_MEM_INVALID_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool, uc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)
UC_HOOK_MEM_ACCESS_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)
UC_HOOK_INTR_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint32, ctypes.c_void_p
)
UC_HOOK_INSN_IN_CB = ctypes.CFUNCTYPE(
    ctypes.c_uint32, uc_engine, ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p
)
UC_HOOK_INSN_OUT_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint32,
    ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p
)
UC_HOOK_INSN_SYSCALL_CB = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_void_p)

# access to error code via @errno of UcError
class UcError(Exception):
    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        return _uc.uc_strerror(self.errno).decode('ascii')


# AFL Errors
class UcAflError(UcError):
    """
    Unicode Afl Error class
    """
    def __init__(self, afl_ret=uc.UC_AFL_RET_ERROR, message=None):
        # type: (UcAflError, int, Optional[str]) -> None
        self.errno = afl_ret # type: int
        self.message = message # type: str

    def __str__(self):
        # type: (UcAflError) -> str
        if self.message:
            return self.message
        return {
            uc.UC_AFL_RET_CHILD: "Fork worked. we are a child (no Error)",
            uc.UC_AFL_RET_NO_AFL: "No AFL, no need to fork (but no real Error)",
            uc.UC_AFL_RET_FINISHED: "We forked before but now AFL is gone (time to quit)",
            uc.UC_AFL_RET_CALLED_TWICE: "Forkserver already running. This may be an error.",
            uc.UC_AFL_RET_ERROR: "Something went horribly wrong in the parent!"
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


# return the core's version
def uc_version():
    major = ctypes.c_int()
    minor = ctypes.c_int()
    combined = _uc.uc_version(ctypes.byref(major), ctypes.byref(minor))
    return (major.value, minor.value, combined)


# return the binding's version
def version_bind():
    return (
        uc.UC_API_MAJOR, uc.UC_API_MINOR,
        (uc.UC_API_MAJOR << 8) + uc.UC_API_MINOR,
    )


# check to see if this engine supports a particular arch
def uc_arch_supported(query):
    return _uc.uc_arch_supported(query)


class uc_x86_mmr(ctypes.Structure):
    """Memory-Management Register for instructions IDTR, GDTR, LDTR, TR."""
    _fields_ = [
        ("selector", ctypes.c_uint16),  # not used by GDTR and IDTR
        ("base", ctypes.c_uint64),      # handle 32 or 64 bit CPUs
        ("limit", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),     # not used by GDTR and IDTR
    ]

class uc_x86_msr(ctypes.Structure):
    _fields_ = [
        ("rid", ctypes.c_uint32),
        ("value", ctypes.c_uint64),
    ]

class uc_x86_float80(ctypes.Structure):
    """Float80"""
    _fields_ = [
        ("mantissa", ctypes.c_uint64),
        ("exponent", ctypes.c_uint16),
    ]


class uc_x86_xmm(ctypes.Structure):
    """128-bit xmm register"""
    _fields_ = [
        ("low_qword", ctypes.c_uint64),
        ("high_qword", ctypes.c_uint64),
    ]

class uc_x86_ymm(ctypes.Structure):
    """256-bit ymm register"""
    _fields_ = [
        ("first_qword", ctypes.c_uint64),
        ("second_qword", ctypes.c_uint64),
        ("third_qword", ctypes.c_uint64),
        ("fourth_qword", ctypes.c_uint64),
    ]

class uc_arm64_neon128(ctypes.Structure):
    """128-bit neon register"""
    _fields_ = [
        ("low_qword", ctypes.c_uint64),
        ("high_qword", ctypes.c_uint64),
    ]

# Subclassing ref to allow property assignment.
class UcRef(weakref.ref):
    pass

# This class tracks Uc instance destruction and releases handles.
class UcCleanupManager(object):
    def __init__(self):
        self._refs = {}

    def register(self, uc):
        ref = UcRef(uc, self._finalizer)
        ref._uch = uc._uch
        ref._class = uc.__class__
        self._refs[id(ref)] = ref

    def _finalizer(self, ref):
        # note: this method must be completely self-contained and cannot have any references
        # to anything else in this module.
        #
        # This is because it may be called late in the Python interpreter's shutdown phase, at
        # which point the module's variables may already have been deinitialized and set to None.
        #
        # Not respecting that can lead to errors such as:
        #     Exception AttributeError:
        #       "'NoneType' object has no attribute 'release_handle'"
        #       in <bound method UcCleanupManager._finalizer of
        #       <unicorn.unicorn.UcCleanupManager object at 0x7f0bb83e4310>> ignored
        #
        # For that reason, we do not try to access the `Uc` class directly here but instead use
        # the saved `._class` reference.
        del self._refs[id(ref)]
        ref._class.release_handle(ref._uch)

class Uc(object):
    _cleanup = UcCleanupManager()

    def __init__(self, arch, mode):
        # verify version compatibility with the core before doing anything
        (major, minor, _combined) = uc_version()
        if major != uc.UC_API_MAJOR or minor != uc.UC_API_MINOR:
            self._uch = None
            # our binding version is different from the core's API version
            raise UcError(uc.UC_ERR_VERSION)

        self._arch, self._mode = arch, mode
        self._uch = ctypes.c_void_p()
        status = _uc.uc_open(arch, mode, ctypes.byref(self._uch))
        if status != uc.UC_ERR_OK:
            self._uch = None
            raise UcError(status)
        # internal mapping table to save callback & userdata
        self._callbacks = {}
        self._ctype_cbs = {}
        self._callback_count = 0
        self._cleanup.register(self)

        self.afl_is_forkserver_child = False # type: bool
        self.afl_called_before = False # type: bool

    @staticmethod
    def release_handle(uch):
        if uch:
            try:
                status = _uc.uc_close(uch)
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
            except:  # _uc might be pulled from under our feet
                pass

    # emulate from @begin, and stop when reaching address @until
    def emu_start(self, begin, until, timeout=0, count=0):
        """
        emulate from @begin, and stop when reaching address @until
        Unless forkserver is started, in which case only the exit points set in afl_forksever_start will work!
        """
        status = _uc.uc_emu_start(self._uch, begin, until, timeout, count)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # stop emulation
    def emu_stop(self):
        status = _uc.uc_emu_stop(self._uch)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    def afl_fuzz(
            self,                   # type: Uc
            input_file,             # type: str
            place_input_callback,   # type: Callable[[Uc, bytes, int, Any], Optional[bool]]
            exits,                  # type: List[int]
            validate_crash_callback=None,  # type: Optional[Callable[[Uc, UcError, bytes, int, Any], Optional[bool]]]
            always_validate=False,  # type: bool
            persistent_iters=1,     # type: int
            data=None,              # type: Any
    ):
        # type: (...) -> bool
        """
        The main fuzzer.
        Starts the forkserver, then beginns a persistent loop.
        Reads input, calls the place_input callback, emulates, repeats.
        If unicorn errors out, will call the validate_crash_callback, if set.
        Will only return in the parent after the whole fuzz thing has been finished and afl died.
        The child processes never return from here.

        :param input_file: filename/path to the (AFL) inputfile. Usually supplied on the commandline.
        :param place_input_callback: Callback function that will be called before each test runs.
                This function needs to write the input from afl to the correct position on the unicorn object.
                This function is mandatory.
                It's purpose is to place the input at the right place in unicorn.

                    @uc: (Uc) Unicorn instance
                    @input: (bytes) The current input we're working on. Place this somewhere in unicorn's memory now.
                    @persistent_round: (int) which round we are currently crashing in, if using persistent mode.
                    @data: (Any) Data pointer passed to uc_afl_fuzz(...).

                    @return: (bool)
                        If you return is True (or None) all is well. Fuzzing starts.
                        If you return False, the input is rejected; we will continue with the next input.
        :param exits: address list of exits where fuzzing should stop
        :param persistent_iters:
                The amount of loop iterations in persistent mode before restarting with a new forked child.
                If your target cannot be fuzzed using persistent mode (global state changes a lot),
                set persistent_iters = 1 for the normal fork-server experience.
                Else, the default is usually around 1000.
                If your target is super stable (and unicorn is, too - not sure about that one),
                you may pass persistent_iter = 0 for that an infinite fuzz loop.
        :param validate_crash_callback: Optional callback (if not needed, pass NULL), that determines
                if a non-OK uc_err is an actual error. If false is returned, the test-case will not crash.
                Callback function called after a non-UC_ERR_OK returncode was returned by Unicorn.
                This function is not mandatory.
                    @uc: Unicorn instance
                    @unicorn_result: The error state returned by the current testcase
                    @input: The current input we're working with.
                    @persistent_round: which round we are currently crashing in, if using persistent mode.
                    @data: Data pointer passed to uc_afl_fuzz(...).

                    @Return:
                    If you return false, the crash is considered invalid and not reported to AFL.
                        -> Next loop iteration begins.
                    If return is true, the crash is reported // the program crashes.
                        -> The child will die and the forkserver will spawn a new child.
        :param always_validate: If false, validate_crash_callback will only be called for crashes.
        :param data: Your very own data pointer. This will passed into every callback.

        :return:
                True, if we fuzzed.
                False, if AFL was not available but we ran once.
                raises UcAflException if nothing worked.
        """
        if self.afl_called_before:
            raise UcAflError(uc.UC_AFL_RET_CALLED_TWICE)
        self.afl_called_before = True
        self._pre_afl(exits)
        exit_count = len(exits)

        def place_input_wrapper(c_uc, input, input_len, persistent_round, c_data):
            # print("Calling back home. :)", c_uc, input, input_len, persistent_round, c_data)
            ret = place_input_callback(
                self,
                ctypes.cast(input, ctypes.POINTER(ctypes.c_char * input_len)).contents,
                persistent_round,
                data
            )
            if ret is False:
                return False
            return True

        def validate_crash_wrapper(c_uc, uc_err, input, input_len, persistent_round, c_data):
            # print("Calling after crash!", c_uc, input, input_len, persistent_round, c_data)
            # assert type(uc_err) == int
            ret = validate_crash_callback(
                self,
                UcError(uc_err),
                ctypes.cast(input, ctypes.POINTER(ctypes.c_char * input_len)).contents,
                persistent_round,
                data
            )
            if ret is False or (ret is None and uc_err == uc.UC_ERR_OK):
                return False
            return True

        # This only returns in the parent, child processes all die or loop or other things.
        status = _uc.uc_afl_fuzz(
                self._uch,
                input_file.encode('utf-8'),
                AFL_PLACE_INPUT_CB(place_input_wrapper),
                (ctypes.c_uint64 * exit_count)(*exits),
                exit_count,  # bad languages, like c, need more params.
                AFL_VALIDATE_CRASH_CB(validate_crash_wrapper) if validate_crash_callback else None,
                always_validate,
                persistent_iters,
                None  # no need to pass the user data through C as the callback keeps it as closure.
        )
        if status == uc.UC_AFL_RET_CALLED_TWICE:
            raise UcAflError(status)
        elif status == uc.UC_AFL_RET_NO_AFL:
            return False
        elif status == uc.UC_AFL_RET_FINISHED:
            return True
        # Something went wrong.
        raise UcAflError(status)

    def _pre_afl(self, exits):
        # type: (Uc, List[int]) -> None
        """
        Internal func making sure exits are set and flushing buffers/gc
        :param exits: exits
        """
        try:
            exits = [int(exit) for exit in exits]
        except Exception as ex:
            raise UcAflError(message="Exit addresses need to be a list of addresses where the fuzzer should stop - {} "
                                         "provided instead ({})".format(ex, exits))
        if self.afl_is_forkserver_child:
            raise UcAflError(message="Already in a forkserver child. Nesting not possible.")
        sys.stdout.flush()  # otherwise children will inherit the unflushed buffer
        gc.collect()  # Collect all unneeded memory, No need to clone it on fork.

    def afl_forkserver_start(self, exits):
        # type: (Uc, List[int]) -> int
        """
        This will start the forkserver.
        Call this to kick off afl forkserver mode (when running as child of AFL)
        If you just want to fuzz, use uc.afl_fuzz instead.
        It forks internally, leaving the parent running in an endless loop.
        The child notifies the parent about any new block encountered.
        The parent then also translates this block for the next AFL iteration.
        Since the parent won't know about any exits set after this point, there is no use in using
        emu_start params like until or count.
        Instead, the exit list of int addresses is passed directly to the parent.
        Everything beyond this func is done for every. single. child. Make sure to do the important stuff before.
        Will raise UcAflError if something went wrong or AFL died (in which case we want to exit)
        :param exits: A list of exits at which the Uc execution will stop.
        :return: UC_AFL_RET_CHILD:
                   You're now in the child. Over and over again.
                 UC_AFL_RET_NO_AFL:
                   No AFL to communicate with. Running on as sole process. :)
                   It's probably best to just continue to emulate from here on.
                 UC_AFL_RET_CALLED_TWICE:
                   Forkserver is already running! Likely a bug in your code.
                 UC_AFL_RET_FINISHED:
                   Successful fuzz run ended. Probably not much else to do.
        -> Prints to stderr and raises UcAflError on error.
        (See stderr of your child in AFL with `AFL_DEBUG_CHILD_OUTPUT=1` env)
        """
        if self.afl_called_before:
            return uc.UC_AFL_RET_CALLED_TWICE
        self.afl_called_before = True
        self._pre_afl(exits)
        exit_count = len(exits)
        self.afl_is_forkserver_child = True # Set this before we fork for speed :)
        # everything beyond this point is done for every. single. child. Make sure to do the important stuff before.
        status = _uc.uc_afl_forkserver_start(self._uch, (ctypes.c_uint64 * exit_count)(*exits), exit_count)
        if status == uc.UC_AFL_RET_CHILD:
            # We're in the child. Let's go fuzz.
            return uc.UC_AFL_RET_CHILD

        if status == uc.UC_AFL_RET_CALLED_TWICE:
            # We are already running.
            return status

        # No AFL or we finished fuzzing. Either way we're in the parent.
        self.afl_is_forkserver_child = False
        if status == uc.UC_AFL_RET_NO_AFL or status == uc.UC_AFL_RET_FINISHED:
            return status
        else:
            # Error creating forkserver :(
            raise UcAflError(status)

    # return the value of a register
    def reg_read(self, reg_id, opt=None):
        if self._arch == uc.UC_ARCH_X86:
            if reg_id in [x86_const.UC_X86_REG_IDTR, x86_const.UC_X86_REG_GDTR, x86_const.UC_X86_REG_LDTR, x86_const.UC_X86_REG_TR]:
                reg = uc_x86_mmr()
                status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
                return reg.selector, reg.base, reg.limit, reg.flags
            if reg_id in range(x86_const.UC_X86_REG_FP0, x86_const.UC_X86_REG_FP0+8):
                reg = uc_x86_float80()
                status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
                return reg.mantissa, reg.exponent
            if reg_id in range(x86_const.UC_X86_REG_XMM0, x86_const.UC_X86_REG_XMM0+8):
                reg = uc_x86_xmm()
                status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
                return reg.low_qword | (reg.high_qword << 64)
            if reg_id in range(x86_const.UC_X86_REG_YMM0, x86_const.UC_X86_REG_YMM0+16):
                reg = uc_x86_ymm()
                status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
                return reg.first_qword | (reg.second_qword << 64) | (reg.third_qword << 128) | (reg.fourth_qword << 192)
            if reg_id is x86_const.UC_X86_REG_MSR:
                if opt is None:
                    raise UcError(uc.UC_ERR_ARG)
                reg = uc_x86_msr()
                reg.rid = opt
                status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
                return reg.value

        if self._arch == uc.UC_ARCH_ARM64:
            if reg_id in range(arm64_const.UC_ARM64_REG_Q0, arm64_const.UC_ARM64_REG_Q31+1) or range(arm64_const.UC_ARM64_REG_V0, arm64_const.UC_ARM64_REG_V31+1):
                reg = uc_arm64_neon128()
                status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
                return reg.low_qword | (reg.high_qword << 64)

        # read to 64bit number to be safe
        reg = ctypes.c_uint64(0)
        status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return reg.value

    # write to a register
    def reg_write(self, reg_id, value):
        reg = None

        if self._arch == uc.UC_ARCH_X86:
            if reg_id in [x86_const.UC_X86_REG_IDTR, x86_const.UC_X86_REG_GDTR, x86_const.UC_X86_REG_LDTR, x86_const.UC_X86_REG_TR]:
                assert isinstance(value, tuple) and len(value) == 4
                reg = uc_x86_mmr()
                reg.selector = value[0]
                reg.base = value[1]
                reg.limit = value[2]
                reg.flags = value[3]
            if reg_id in range(x86_const.UC_X86_REG_FP0, x86_const.UC_X86_REG_FP0+8):
                reg = uc_x86_float80()
                reg.mantissa = value[0]
                reg.exponent = value[1]
            if reg_id in range(x86_const.UC_X86_REG_XMM0, x86_const.UC_X86_REG_XMM0+8):
                reg = uc_x86_xmm()
                reg.low_qword = value & 0xffffffffffffffff
                reg.high_qword = value >> 64
            if reg_id in range(x86_const.UC_X86_REG_YMM0, x86_const.UC_X86_REG_YMM0+16):
                reg = uc_x86_ymm()
                reg.first_qword = value & 0xffffffffffffffff
                reg.second_qword = (value >> 64) & 0xffffffffffffffff
                reg.third_qword = (value >> 128) & 0xffffffffffffffff
                reg.fourth_qword = value >> 192
            if reg_id is x86_const.UC_X86_REG_MSR:
                reg = uc_x86_msr()
                reg.rid = value[0]
                reg.value = value[1]

        if self._arch == uc.UC_ARCH_ARM64:
            if reg_id in range(arm64_const.UC_ARM64_REG_Q0, arm64_const.UC_ARM64_REG_Q31+1) or range(arm64_const.UC_ARM64_REG_V0, arm64_const.UC_ARM64_REG_V31+1):
                reg = uc_arm64_neon128()
                reg.low_qword = value & 0xffffffffffffffff
                reg.high_qword = value >> 64

        if reg is None:
            # convert to 64bit number to be safe
            reg = ctypes.c_uint64(value)

        status = _uc.uc_reg_write(self._uch, reg_id, ctypes.byref(reg))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # read from MSR - X86 only
    def msr_read(self, msr_id):
        return self.reg_read(x86_const.UC_X86_REG_MSR, msr_id)

    # write to MSR - X86 only
    def msr_write(self, msr_id, value):
        return self.reg_write(x86_const.UC_X86_REG_MSR, (msr_id, value))

    # read data from memory
    def mem_read(self, address, size):
        data = ctypes.create_string_buffer(size)
        status = _uc.uc_mem_read(self._uch, address, data, size)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return bytearray(data)

    # write to memory
    def mem_write(self, address, data):
        status = _uc.uc_mem_write(self._uch, address, data, len(data))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # map a range of memory
    def mem_map(self, address, size, perms=uc.UC_PROT_ALL):
        status = _uc.uc_mem_map(self._uch, address, size, perms)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # map a range of memory from a raw host memory address
    def mem_map_ptr(self, address, size, perms, ptr):
        status = _uc.uc_mem_map_ptr(self._uch, address, size, perms, ptr)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # unmap a range of memory
    def mem_unmap(self, address, size):
        status = _uc.uc_mem_unmap(self._uch, address, size)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # protect a range of memory
    def mem_protect(self, address, size, perms=uc.UC_PROT_ALL):
        status = _uc.uc_mem_protect(self._uch, address, size, perms)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # return CPU mode at runtime
    def query(self, query_mode):
        result = ctypes.c_size_t(0)
        status = _uc.uc_query(self._uch, query_mode, ctypes.byref(result))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return result.value

    def _hookcode_cb(self, handle, address, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, address, size, data)

    def _hook_mem_invalid_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, access, address, size, value, data)

    def _hook_mem_access_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, access, address, size, value, data)

    def _hook_intr_cb(self, handle, intno, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, intno, data)

    def _hook_insn_invalid_cb(self, handle, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, data)

    def _hook_insn_in_cb(self, handle, port, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, port, size, data)

    def _hook_insn_out_cb(self, handle, port, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, port, size, value, data)

    def _hook_insn_syscall_cb(self, handle, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, data)

    # add a hook
    def hook_add(self, htype, callback, user_data=None, begin=1, end=0, arg1=0):
        _h2 = uc_hook_h()

        # save callback & user_data
        self._callback_count += 1
        self._callbacks[self._callback_count] = (callback, user_data)
        cb = None

        if htype == uc.UC_HOOK_INSN:
            insn = ctypes.c_int(arg1)
            if arg1 == x86_const.UC_X86_INS_IN:  # IN instruction
                cb = ctypes.cast(UC_HOOK_INSN_IN_CB(self._hook_insn_in_cb), UC_HOOK_INSN_IN_CB)
            if arg1 == x86_const.UC_X86_INS_OUT:  # OUT instruction
                cb = ctypes.cast(UC_HOOK_INSN_OUT_CB(self._hook_insn_out_cb), UC_HOOK_INSN_OUT_CB)
            if arg1 in (x86_const.UC_X86_INS_SYSCALL, x86_const.UC_X86_INS_SYSENTER):  # SYSCALL/SYSENTER instruction
                cb = ctypes.cast(UC_HOOK_INSN_SYSCALL_CB(self._hook_insn_syscall_cb), UC_HOOK_INSN_SYSCALL_CB)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end), insn
            )
        elif htype == uc.UC_HOOK_INTR:
            cb = ctypes.cast(UC_HOOK_INTR_CB(self._hook_intr_cb), UC_HOOK_INTR_CB)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        elif htype == uc.UC_HOOK_INSN_INVALID:
            cb = ctypes.cast(UC_HOOK_INSN_INVALID_CB(self._hook_insn_invalid_cb), UC_HOOK_INSN_INVALID_CB)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        else:
            if htype in (uc.UC_HOOK_BLOCK, uc.UC_HOOK_CODE):
                # set callback with wrapper, so it can be called
                # with this object as param
                cb = ctypes.cast(UC_HOOK_CODE_CB(self._hookcode_cb), UC_HOOK_CODE_CB)
                status = _uc.uc_hook_add(
                    self._uch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )
            elif htype & (uc.UC_HOOK_MEM_READ_UNMAPPED |
                          uc.UC_HOOK_MEM_WRITE_UNMAPPED |
                          uc.UC_HOOK_MEM_FETCH_UNMAPPED |
                          uc.UC_HOOK_MEM_READ_PROT |
                          uc.UC_HOOK_MEM_WRITE_PROT |
                          uc.UC_HOOK_MEM_FETCH_PROT):
                cb = ctypes.cast(UC_HOOK_MEM_INVALID_CB(self._hook_mem_invalid_cb), UC_HOOK_MEM_INVALID_CB)
                status = _uc.uc_hook_add(
                    self._uch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )
            else:
                cb = ctypes.cast(UC_HOOK_MEM_ACCESS_CB(self._hook_mem_access_cb), UC_HOOK_MEM_ACCESS_CB)
                status = _uc.uc_hook_add(
                    self._uch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )

        # save the ctype function so gc will leave it alone.
        self._ctype_cbs[self._callback_count] = cb

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        return _h2.value

    # delete a hook
    def hook_del(self, h):
        _h = uc_hook_h(h)
        status = _uc.uc_hook_del(self._uch, _h)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        h = 0

    def context_save(self):
        context = UcContext(self._uch)
        status = _uc.uc_context_save(self._uch, context.context)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

        return context

    def context_update(self, context):
        status = _uc.uc_context_save(self._uch, context.context)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    def context_restore(self, context):
        status = _uc.uc_context_restore(self._uch, context.context)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # this returns a generator of regions in the form (begin, end, perms)
    def mem_regions(self):
        regions = ctypes.POINTER(_uc_mem_region)()
        count = ctypes.c_uint32()
        status = _uc.uc_mem_regions(self._uch, ctypes.byref(regions), ctypes.byref(count))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

        try:
            for i in range(count.value):
                yield (regions[i].begin, regions[i].end, regions[i].perms)
        finally:
            _uc.uc_free(regions)


class UcContext:
    def __init__(self, h):
        self._context = uc_context()
        self._size = _uc.uc_context_size(h)
        self._to_free = True
        status = _uc.uc_context_alloc(h, ctypes.byref(self._context))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
    
    @property
    def context(self):
        return self._context

    @property
    def size(self):
        return self._size

    # Make UcContext picklable
    def __getstate__(self):
        return (bytes(self), self.size)
    
    def __setstate__(self, state):
        self._size = state[1]
        self._context = ctypes.cast(ctypes.create_string_buffer(state[0], self._size), uc_context)
        # __init__ won'e be invoked, so we are safe to set it here.
        self._to_free = False
        
    def __bytes__(self):
        return ctypes.string_at(self.context, self.size)

    def __del__(self):
        # We need this property since we shouldn't free it if the object is constructed from pickled bytes.
        if self._to_free:
            _uc.uc_context_free(self._context)


# print out debugging info
def debug():
    archs = {
        "arm": uc.UC_ARCH_ARM,
        "arm64": uc.UC_ARCH_ARM64,
        "mips": uc.UC_ARCH_MIPS,
        "sparc": uc.UC_ARCH_SPARC,
        "m68k": uc.UC_ARCH_M68K,
        "x86": uc.UC_ARCH_X86,
    }

    all_archs = ""
    keys = archs.keys()
    for k in sorted(keys):
        if uc_arch_supported(archs[k]):
            all_archs += "-%s" % k

    major, minor, _combined = uc_version()

    return "python-%s-c%u.%u-b%u.%u" % (
        all_archs, major, minor, uc.UC_API_MAJOR, uc.UC_API_MINOR
    )
