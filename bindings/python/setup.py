import setuptools
import sys
import os
import subprocess
import shutil
import struct
import re
import platform
from distutils.util import get_platform
from distutils.command.build import build as _build
from distutils.command.sdist import sdist as _sdist
from setuptools.command.bdist_egg import bdist_egg as _bdist_egg
from setuptools.command.develop import develop as _develop
from distutils.command.clean import clean as _clean
from pathlib import Path

SYSTEM = sys.platform

# sys.maxint is 2**31 - 1 on both 32 and 64 bit mingw
IS_64BITS = platform.architecture()[0] == '64bit'

# are we building from the repository or from a source distribution?
ROOT_DIR = Path(os.path.realpath(__file__)).parent
LIBS_DIR = ROOT_DIR / 'unicornafl' / 'lib'
HEADERS_DIR = ROOT_DIR / 'unicornafl' / 'include'
SRC_DIR = ROOT_DIR / '..' / '..'
BUILD_DIR = SRC_DIR / 'build_python'

VERSION = "2.0.2"

if SYSTEM == 'darwin':
    LIBRARY_FILE = "libunicornafl.dylib"
    STATIC_LIBRARY_FILE = None
else:
    LIBRARY_FILE = "libunicornafl.so"
    STATIC_LIBRARY_FILE = None

def clean_builds():
    shutil.rmtree(LIBS_DIR, ignore_errors=True)
    shutil.rmtree(HEADERS_DIR, ignore_errors=True)

def build_uc2afl():
    prev_cwd = os.getcwd()
    clean_builds()
    os.mkdir(LIBS_DIR)
    os.mkdir(HEADERS_DIR)

    shutil.copytree(SRC_DIR / "include" / "unicornafl", HEADERS_DIR / "unicornafl") 
    
    os.chdir(SRC_DIR)

    if not os.path.exists(BUILD_DIR):
        os.mkdir(BUILD_DIR)
    
    if os.getenv("DEBUG", ""):
        args = ["cmake", "-B", BUILD_DIR, "-DCMAKE_BUILD_TYPE=Debug"]
    else:
        args = ["cmake", "-B", BUILD_DIR, "-DCMAKE_BUILD_TYPE=Release"]
    
    if os.getenv("UCAFL_NO_LOG", ""):
        args += ["-DUCAFL_NO_LOG=on"]

    subprocess.check_call(args)

    os.chdir(BUILD_DIR)
    threads = os.getenv("THREADS", "6")
    subprocess.check_call(["make", "-j" + threads])

    shutil.copy(LIBRARY_FILE, LIBS_DIR)

    os.chdir(prev_cwd)


class build(_build):
    def run(self):
        build_uc2afl()
        return _build.run(self)

class clean(_clean):
    def run(self):
        clean_builds()
        return _clean.run(self)

class develop(_develop):
    def run(self):
        build_uc2afl()
        return _develop.run(self)

class bdist_egg(_bdist_egg):
    def run(self):
        self.run_command('build')
        return _bdist_egg.run(self)

# https://stackoverflow.com/questions/45150304/how-to-force-a-python-wheel-to-be-platform-specific-when-building-it
# https://github.com/unicorn-engine/unicorn/blob/198e432a1d7edbed6f4726acc42c50c3a4141b6b/bindings/python/setup.py#L229
if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    idx = sys.argv.index('bdist_wheel') + 1
    sys.argv.insert(idx, '--plat-name')
    name = get_platform()
    if 'linux' in name:
        # linux_* platform tags are disallowed because the python ecosystem is fubar
        # linux builds should be built in the centos 5 vm for maximum compatibility
        # see https://github.com/pypa/manylinux
        # see also https://github.com/angr/angr-dev/blob/master/bdist.sh
        sys.argv.insert(idx + 1, 'manylinux1_' + platform.machine())
    elif 'mingw' in name:
        if IS_64BITS:
            sys.argv.insert(idx + 1, 'win_amd64')
        else:
            sys.argv.insert(idx + 1, 'win32')
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.insert(idx + 1, name.replace('.', '_').replace('-', '_'))

long_desc = '''
Unicornafl
-----------

Bring Unicorn to afl++.

'''

setuptools.setup(
    provides=['unicornafl'],
    packages=['unicornafl'],
    name='unicornafl',
    version=VERSION,
    author='Lazymio',
    author_email='mio@lazym.io',
    description='Unicornafl',
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url='https://github.com/AFLplusplus/unicornafl',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
    ],
    requires=['ctypes'],
    cmdclass={
        "build" : build,
        "develop" : develop,
        "bdist_egg" : bdist_egg,
        "clean" : clean
    },
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        "unicorn>=2.0.0rc7"
    ],
    is_pure=False,
    package_data={
        'unicornafl': ['lib/*', 'include/*']
    }
)
