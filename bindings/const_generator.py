#!/usr/bin/env python3
# Unicorn Engine
# By Dang Hoang Vu, 2013
from __future__ import print_function
import sys, re, os

INCL_DIR = os.path.join('..', 'include', 'unicorn')

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'sparc.h', 'm68k.h', 'unicorn.h' ]

def rust_emit_subprefix(subprefix):
    c_struct = """}}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum {} {{
"""
    i32_struct = """}}

#[repr(i32)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum {} {{
"""
    if subprefix == "uc_x86_insn":
        return c_struct.format("InsnX86")
    elif subprefix == "uc_err":
        return c_struct.format("Error")
    elif subprefix == "uc_afl_ret":
        return c_struct.format("AflRet")
    elif subprefix == "uc_mem_type":
        return c_struct.format("MemType")
    elif subprefix == "uc_hook_type":
        return i32_struct.format("HookType")
    elif subprefix == "uc_arch":
        return c_struct.format("Arch")
    elif subprefix == "uc_mode":
        return c_struct.format("Mode")
    elif subprefix == "uc_query_type":
        return c_struct.format("Query")
    elif subprefix == "uc_prot":
        return """}

bitflags! {
#[repr(C)]
pub struct Protection : u32 {
"""
    return ""

# This state is needed as the rust bindings start new structs for sub-files.
def rust_const_name_func(prefix, subprefix, const):
    if not prefix:  # unicorn_const.rs
        if const == "MODE_ARM":
            return "// use LITTLE_ENDIAN.\n    // " + const
        reg_name = const.split("_",1)[1] # X86_REG_RAX -> RAX
        if ord(reg_name[0]) >= ord("0") and ord(reg_name[0]) <= ord("9"):
            # Special case for MIPS REG_0 - REG_31
            return "MODE_" + reg_name
        else:
            if subprefix == "uc_prot":
                return "const " + reg_name
            if reg_name in ["MAJOR", "MINOR", "EXTRA", "SCALE"]:
                return "pub const " + const + ": u64"
            return reg_name
    else:
        reg_name = const.split("_",2)[2] # X86_REG_RAX -> RAX
        if ord(reg_name[0]) >= ord("0") and ord(reg_name[0]) <= ord("9"):
            # Special case for MIPS REG_0 - REG_31 -> multiple enum entries with same name not allowed in rust
            return "// R" + reg_name
        if len(reg_name) == 3 and (reg_name.startswith("LO") or reg_name.startswith("HI")):
            return "// " + reg_name
        if reg_name in ["R9", "R10", "R11", "R12", "R13", "R14", "R15", "X16", "X17", "X29", "X30", "I6", "O6", "S8"]:
            return "// " + reg_name
        else:
            return reg_name
    return ""

def rust_header_func(prefix, header):
    if prefix == "unicorn":
        return "#![allow(non_camel_case_types)]\n// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\nuse bitflags::bitflags;\n\n{\n"
    if prefix in ["mips", "arm", "arm64", "x86", "sparc", "m68k"]:
        prefix = prefix.upper()
    return header % (prefix,)

def rust_footer_func(prefix, footer):
    if prefix == None:
        return "    }\n" + footer
    return footer

template = {
    'python': {
            'header': "# For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.py]\n",
            'footer': "",
            'line_format': 'UC_%s = %s\n',
            'out_file': './python/unicornafl/%s_const.py',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'm68k.h': 'm68k',
            'unicorn.h': 'unicorn',
            'comment_open': '#',
            'comment_close': '',
        },
    'ruby': {
            'header': "# For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n{\n[%s_const.rb]\n\nmodule UnicornEngine\n",
            'footer': "end",
            'line_format': '\tUC_%s = %s\n',
            'out_file': './ruby/unicorn_gem/lib/unicorn_engine/%s_const.rb',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'm68k.h': 'm68k',
            'unicorn.h': 'unicorn',
            'comment_open': '#',
            'comment_close': '',
        },
    'go': {
            'header': "package unicorn\n// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.go]\nconst (\n",
            'footer': ")",
            'line_format': '\t%s = %s\n',
            'out_file': './go/unicorn/%s_const.go',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'm68k.h': 'm68k',
            'unicorn.h': 'unicorn',
            'comment_open': '//',
            'comment_close': '',
        },
    'rust': {
            'header': "#![allow(non_camel_case_types)]\n// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\n#[repr(C)]\n#[derive(PartialEq, Debug, Clone, Copy)]\npub enum Register%s {\n\n",
            'header_func': rust_header_func,
            'footer': "\n}",
            'footer_func': rust_footer_func,
            'line_format': '    %s = %s,\n',
            'const_name_func': rust_const_name_func,
            'emit_subprefix': rust_emit_subprefix,
            'out_file': './rust/src/%s_const.rs',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'm68k.h': 'm68k',
            'unicorn.h': 'unicorn',
            'comment_open': '    //',
            'comment_close': '',
        },
        'java': {
            'header': "// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\npackage unicorn;\n\npublic interface %sConst {\n",
            'footer': "\n}\n",
            'line_format': '   public static final int UC_%s = %s;\n',
            'out_file': './java/unicorn/%sConst.java',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'Arm',
            'arm64.h': 'Arm64',
            'mips.h': 'Mips',
            'x86.h': 'X86',
            'sparc.h': 'Sparc',
            'm68k.h': 'M68k',
            'unicorn.h': 'Unicorn',
            'comment_open': '//',
            'comment_close': '',
        },
    'dotnet': {
            'header': "// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\nnamespace UnicornManaged.Const\n\nopen System\n\n[<AutoOpen>]\nmodule %s =\n",
            'footer': "\n",
            'line_format': '    let UC_%s = %s\n',
            'out_file': os.path.join('dotnet', 'UnicornManaged', 'Const', '%s.fs'),
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'Arm',
            'arm64.h': 'Arm64',
            'mips.h': 'Mips',
            'x86.h': 'X86',
            'sparc.h': 'Sparc',
            'm68k.h': 'M68k',
            'unicorn.h': 'Common',
            'comment_open': '    //',
            'comment_close': '',
        },
    'pascal': {
            'header': "// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\nunit %sConst;\n\ninterface\n\nconst",
            'footer': "\nimplementation\nend.",
            'line_format': '  UC_%s = %s;\n',
            'out_file': os.path.join('pascal', 'unicorn', '%sConst.pas'),
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'Arm',
            'arm64.h': 'Arm64',
            'mips.h': 'Mips',
            'x86.h': 'X86',
            'sparc.h': 'Sparc',
            'm68k.h': 'M68k',
            'unicorn.h': 'Unicorn',
            'comment_open': '//',
            'comment_close': '',
        },
}

# markup for comments to be added to autogen files
MARKUP = '//>'

def gen(lang):
    global include, INCL_DIR
    templ = template[lang]
    for target in include:
        prefix = templ[target]
        subprefix = ""
        outfile = open(templ['out_file'] %(prefix), 'wb')   # open as binary prevents windows newlines
        if 'header_func' in templ.keys():
            outfile.write(templ['header_func'](prefix, templ['header']).encode("utf-8"))
        else:
            outfile.write((templ['header'] % (prefix)).encode("utf-8"))
        if target == 'unicorn.h':
            prefix = ''
        with open(os.path.join(INCL_DIR, target)) as f:
            lines = f.readlines()

        previous = {}
        count = 0
        for line in lines:
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                outfile.write(("\n%s%s%s\n" %(templ['comment_open'], \
                            line.replace(MARKUP, ''), templ['comment_close'])).encode("utf-8"))
                continue

            if line == '' or line.startswith('//'):
                continue

            if line.startswith("typedef enum"):
                subprefix = line.split()[2] # typedef enum uc_x86_reg {
                if "emit_subprefix" in templ.keys():
                    outfile.write(templ["emit_subprefix"](subprefix).encode("utf-8"))

            tmp = line.strip().split(',')
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                f = re.split('\s+', t)

                # parse #define UC_TARGET (num)
                if f[0] == '#define' and len(f) >= 3:
                    f.pop(0)
                    f.insert(1, '=')

                if f[0].startswith("UC_" + prefix.upper()):
                    if len(f) > 1 and f[1] not in ('//', '='):
                        print("WARNING: Unable to convert %s" % f)
                        print("  Line =", line)
                        continue
                    elif len(f) > 1 and f[1] == '=':
                        rhs = ''.join(f[2:])
                    else:
                        rhs = str(count)

                    lhs = f[0].strip()
                    # evaluate bitshifts in constants e.g. "UC_X86 = 1 << 1"
                    match = re.match(r'(?P<rhs>\s*\d+\s*<<\s*\d+\s*)', rhs)
                    if match:
                        rhs = str(eval(match.group(1)))
                    else:
                        # evaluate references to other constants e.g. "UC_ARM_REG_X = UC_ARM_REG_SP"
                        match = re.match(r'^([^\d]\w+)$', rhs)
                        if match:
                            rhs = previous[match.group(1)]

                    if not rhs.isdigit():
                        for k, v in previous.items():
                            rhs = re.sub(r'\b%s\b' % k, v, rhs)
                        rhs = str(eval(rhs))

                    lhs_strip = re.sub(r'^UC_', '', lhs)
                    count = int(rhs) + 1
                    if (count == 1):
                        outfile.write(("\n").encode("utf-8"))
                    # If the template has a const_name_func that alters the var name, do it now.
                    if 'const_name_func' in templ.keys():
                        lhs_strip = templ['const_name_func'](prefix, subprefix, lhs_strip)
                    outfile.write((templ['line_format'] % (lhs_strip, rhs)).encode("utf-8"))
                    previous[lhs] = str(rhs)

        if 'footer_func' in templ:
            outfile.write(templ['footer_func'](prefix, templ['footer']).encode("utf-8"))
        else:
            outfile.write((templ['footer']).encode("utf-8"))
        outfile.close()

def main():
    lang = sys.argv[1]
    if lang == "all":
        for lang in template.keys():
            print("Generating constants for {}".format(lang))
            gen(lang)
    else:
        if not lang in template:
            raise RuntimeError("Unsupported binding %s" % lang)
        gen(lang)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:", sys.argv[0], " <python>")
        print("Supported: {}".format(["all"] + [x for x in template.keys()]))
        sys.exit(1)
    main()
