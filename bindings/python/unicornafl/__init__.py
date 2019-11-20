# Unicorn Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
from . import arm_const, arm64_const, mips_const, sparc_const, m68k_const, x86_const
from .unicorn_const import *
from .unicorn import (Uc, uc_version, uc_arch_supported, version_bind, debug, UcError, __version__,
    monkeypatch, UcAflError, # Unicorn AFL additions.
    UC_AFL_RET_ERROR, # Something went horribly wrong in the parent
    UC_AFL_RET_CHILD, # Fork worked. we are a child
    UC_AFL_RET_NO_AFL, # No AFL, no need to fork.
    UC_AFL_RET_FINISHED, # We forked before but now AFL is gone (parent)
)