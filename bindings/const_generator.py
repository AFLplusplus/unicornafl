#!/usr/bin/env python3
# Unicorn Engine
# By Dang Hoang Vu, 2013
from __future__ import print_function
import sys, re, os

INCL_DIR = os.path.join('..', 'include', 'unicorn')

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'sparc.h', 'm68k.h', 'ppc.h', 'unicorn.h' ]

rust_subprefix_enum_struct_names = {
    "uc_x86_insn": "InsnX86",
    "uc_err": "Error",
    "uc_afl_ret": "AflRet",
    "uc_mem_type": "MemType",
    "uc_hook_type": "HookType",
    "uc_arch": "Arch",
    "uc_mode": "Mode",
    "uc_query_type": "Query",
    "uc_prot": "Protection"
}

def rust_emit_subprefix(prefix, subprefix):

    if subprefix in [
                    "uc_x86_insn", 
                    "uc_err",
                    "uc_afl_ret",
                    "uc_mem_type",
                    "uc_arch",
                    "uc_mode",
                    "uc_query_type"
                    ]:
        return """
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum {} {{
""".format(rust_subprefix_enum_struct_names[subprefix])

    elif subprefix == "uc_hook_type":
        return """
#[repr(i32)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum HookType {"""

    elif subprefix == "uc_prot":
        return """
bitflags! {
#[repr(C)]
pub struct Protection : u32 {"""

    return ""



rust_line_format_taken_vals = {}
rust_line_format_duplicates = {}
# This state is needed as the rust bindings start new structs for sub-files.
def rust_line_format_func(prefix, subprefix, const, val, format):
    global rust_line_format_taken_vals
    global rust_line_format_duplicates
    
    if prefix != "unicorn":  # unicorn_const.rs
        reg_name = const.split("_",2)[2] 
    elif const == "MODE_ARM":
        return format % ("// use LITTLE_ENDIAN.\n    // " + const, val)
    elif subprefix == "uc_afl_ret":
        return format % (const.split("_",2)[2], val) # AFL_RET_NO_AFL -> NO_AFL
    else:
        reg_name = const.split("_",1)[1] # X86_REG_RAX -> RAX

    if ord(reg_name[0]) >= ord("0") and ord(reg_name[0]) <= ord("9"):
        if subprefix == "uc_mode":
            # 16,32,64 bit modes
            reg_name = "MODE_{}".format(reg_name)
        else:
            # Special case for MIPS REG_0 - REG_31
            reg_name = "R{}".format(reg_name)
    if subprefix == "uc_prot":
        return "{}const {} = {};\n".format(" "*8, reg_name, val)
    if reg_name in ["MAJOR", "MINOR", "EXTRA", "SCALE"]:
        return "pub const {}: u64 = {};\n".format(const, val)

    if val in rust_line_format_taken_vals.keys():
        # Special handling: Rust does not directly support multiple enum values with the same content
        rust_line_format_duplicates[reg_name] = rust_line_format_taken_vals[val]
        return format % ("// (assoc) {}".format(reg_name), val)
    #if reg_name in ["V9", "SPARC64", "MIPS64", "SPARC32", "QPX", "PPC64", "PPC32", "MIPS32", "V8", "MCLASS", "MICRO"]:
    rust_line_format_taken_vals[val] = reg_name
    return format % (reg_name, val)


def rust_header_func(prefix, header):
    if prefix == "unicorn":
        return "#![allow(non_camel_case_types)]\n// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\nuse bitflags::bitflags;\n\n"
    if prefix in ["mips", "arm", "arm64", "x86", "sparc", "m68k"]:
        prefix = prefix.upper()
    return header % (prefix,)


def rust_get_associated_consts(prefix, subprefix):
    # Enums in rust do not allow multiple enum values with the same int value.
    # Instead, we add them as associated const (alias) in the next step (impl).
    global rust_line_format_taken_vals
    global rust_line_format_duplicates
    if prefix in ["mips", "arm", "arm64", "x86", "sparc", "m68k"]:
        struct = "Register{}".format(prefix.upper())
    else:
        struct = rust_subprefix_enum_struct_names[subprefix]
    rust_line_format_taken_vals = {}
    if len(rust_line_format_duplicates) == 0:
        return ""
    ret = "\nimpl {} {{\n".format(struct)
    for dst, src in rust_line_format_duplicates.items():
        ret += "    pub const {dst}: {struct} = {struct}::{src};\n".format(dst=dst, struct=struct, src=src)
    rust_line_format_duplicates = {}
    return ret + "}\n"


skipped_mem_hook_ctr = False
def rust_emit_subprefix_end_func(prefix, subprefix):
    if prefix == "unicorn":
        if subprefix == "uc_hook_type":
            # some defines follow. Hack it away.
            global skipped_mem_hook_ctr
            if not skipped_mem_hook_ctr:
                skipped_mem_hook_ctr = True
                return ""
            else:
                skipped_mem_hook_ctr = False # in case we come back here at some point
                return "}\n" + rust_get_associated_consts(prefix, subprefix)
        if subprefix == "uc_prot":
            return "    }\n}\n" + rust_get_associated_consts(prefix, subprefix)
        else:
            return "}\n" + rust_get_associated_consts(prefix, subprefix)
    return "}"  + rust_get_associated_consts(prefix, subprefix)

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
            'ppc.h': 'ppc',
            'unicorn.h': 'unicorn',
            'comment_open': '#',
            'comment_close': '',
        },
    'ruby': {
            'header': "# For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rb]\n\nmodule UnicornEngine\n",
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
            'ppc.h': 'ppc',
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
            'ppc.h': 'ppc',
            'unicorn.h': 'unicorn',
            'comment_open': '//',
            'comment_close': '',
        },
    'rust': {
            'header': "#![allow(non_camel_case_types)]\n// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\n#[repr(C)]\n#[derive(PartialEq, Debug, Clone, Copy)]\npub enum Register%s {\n\n",
            'header_func': rust_header_func,
            'footer': "",
            'line_format': '    %s = %s,\n',
            'line_format_func': rust_line_format_func,
            'emit_subprefix_func': rust_emit_subprefix,
            'emit_subprefix_end_func': rust_emit_subprefix_end_func,
            'out_file': './rust/libunicorn-sys/src/%s_const.rs',
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
            'ppc.h': 'ppc',
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
            'ppc.h': 'ppc',
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
            'ppc.h': 'ppc',
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
        func_prefix = prefix if prefix else "unicorn"

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
                if "emit_subprefix_func" in templ.keys():
                    outfile.write(templ["emit_subprefix_func"](func_prefix, subprefix).encode("utf-8"))

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
                    if 'line_format_func' in templ.keys():
                        outfile.write(templ['line_format_func'](func_prefix, 
                                                                subprefix, 
                                                                lhs_strip, 
                                                                rhs, 
                                                                templ['line_format']
                        ).encode("utf-8"))
                    else:
                        outfile.write((templ['line_format'] % (lhs_strip, rhs)).encode("utf-8"))
                    previous[lhs] = str(rhs)

            if line.startswith("}") and line.strip().endswith(";") and 'emit_subprefix_end_func' in templ.keys() and subprefix:
                outfile.write(templ['emit_subprefix_end_func'](func_prefix, subprefix).encode("utf-8"))

        if 'footer_func' in templ.keys():
            outfile.write(templ['footer_func'](func_prefix, templ['footer']).encode("utf-8"))
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
