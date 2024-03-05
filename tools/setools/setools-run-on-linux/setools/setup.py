#!/usr/bin/env python3

import glob
from setuptools import setup
import distutils.log as log
from distutils.core import Extension
from distutils.cmd import Command
from distutils.command.clean import clean
import subprocess
import sys
import os
import shutil
from os.path import join
from itertools import chain
from contextlib import suppress
from Cython.Build import cythonize
import os.path


class CleanCommand(clean):
    """
    Extend the clean command to clean cython and Qt files.

    This will clean the .c intermediate file, and if --all is
    specified, will remove __pycache__ and Qt help files.
    """

    def run(self):
        extensions_to_remove = [".so", ".c"]
        files_to_remove = []
        dirs_to_remove = ["setools.egg-info"]

        if self.all:
            # --all includes Qt help files
            self.announce("Cleaning __pycache__ dirs and Qt help files", level=log.INFO)
            extensions_to_remove.extend((".qhc", ".qch"))

        # collect files and dirs to delete
        for root, dirs, files in chain(os.walk("setools"),
                                       os.walk("setoolsgui"),
                                       os.walk("tests"),
                                       os.walk("qhc")):
            for f in files:
                if os.path.splitext(f)[-1] in extensions_to_remove:
                    files_to_remove.append(join(root, f))

            for d in dirs:
                if d == "__pycache__" and self.all:
                    dirs_to_remove.append(join(root, d))

        for file in files_to_remove:
            with suppress(Exception):
                os.unlink(file)

        for dir_ in dirs_to_remove:
            with suppress(Exception):
                shutil.rmtree(dir_, ignore_errors=True)

        clean.run(self)

class QtHelpCommand(Command):
    description = "Build Qt help files."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        command = ['qcollectiongenerator', 'qhc/apol.qhcp']
        self.announce("Building Qt help files", level=log.INFO)
        self.announce(' '.join(command), level=log.INFO)
        subprocess.check_call(command)
        self.announce("Moving Qt help files to setoolsgui/apol")
        os.rename('qhc/apol.qhc', 'setoolsgui/apol/apol.qhc')
        os.rename('qhc/apol.qch', 'setoolsgui/apol/apol.qch')


# Library linkage
lib_dirs = ['.', '/usr/lib64', '/usr/lib', '/usr/local/lib']
include_dirs = []

with suppress(KeyError):
    userspace_src = os.environ["USERSPACE_SRC"]
    include_dirs.insert(0, userspace_src + "/libsepol/include")
    include_dirs.insert(1, userspace_src + "/libselinux/include")
    lib_dirs.insert(0, userspace_src + "/libsepol/src")
    lib_dirs.insert(1, userspace_src + "/libselinux/src")

if sys.platform.startswith('darwin'):
    macros=[('DARWIN',1)]
else:
    macros=[]

# Code coverage.  Enable this to get coverage in the cython code.
enable_coverage = bool(os.environ.get("SETOOLS_COVERAGE", False))
if enable_coverage:
    macros.append(("CYTHON_TRACE", 1))

cython_annotate = bool(os.environ.get("SETOOLS_ANNOTATE", False))

ext_py_mods = [Extension('setools.policyrep', ['setools/policyrep.pyx'],
                         include_dirs=include_dirs,
                         libraries=['selinux', 'sepol'],
                         library_dirs=lib_dirs,
                         define_macros=macros,
                         extra_compile_args=['-Werror', '-Wextra',
                                             '-Waggregate-return',
                                             '-Wfloat-equal',
                                             '-Wformat', '-Wformat=2',
                                             '-Winit-self',
                                             '-Wmissing-format-attribute',
                                             '-Wmissing-include-dirs',
                                             '-Wnested-externs',
                                             '-Wold-style-definition',
                                             '-Wpointer-arith',
                                             '-Wstrict-prototypes',
                                             '-Wunknown-pragmas',
                                             '-Wwrite-strings',
                                             '-Wno-unused-parameter',
                                             '-Wno-suggest-attribute=format',
                                             '-Wno-sign-compare',
                                             '-Wno-cast-qual',
                                             '-Wno-unreachable-code',
                                             '-Wno-implicit-fallthrough',
                                             '-Wno-cast-function-type',
                                             '-fno-exceptions'])]

installed_data = [('share/man/man1', glob.glob("man/*.1"))]

linguas = ["ru"]

with suppress(KeyError):
    linguas = os.environ["LINGUAS"].split(" ")

for lang in linguas:
    if lang and os.path.exists(join("man", lang)):
        installed_data.append((join('share/man', lang, 'man1'), glob.glob(join("man", lang, "*.1"))))

setup(name='setools',
      version='4.3.0-dev',
      description='SELinux policy analysis tools.',
      author='Chris PeBenito',
      author_email='pebenito@ieee.org',
      url='https://github.com/SELinuxProject/setools',
      cmdclass={'build_qhc': QtHelpCommand, 'clean': CleanCommand},
      packages=['setools', 'setools.diff', 'setoolsgui', 'setoolsgui.apol'],
      scripts=['apol', 'sediff', 'seinfo', 'seinfoflow', 'sesearch', 'sedta'],
      data_files=installed_data,
      package_data={'': ['*.ui', '*.qhc', '*.qch'], 'setools': ['perm_map']},
      ext_modules=cythonize(ext_py_mods, include_path=['setools/policyrep'],
                            annotate=cython_annotate,
                            compiler_directives={"language_level": 3,
                                                 "c_string_type": "str",
                                                 "c_string_encoding": "ascii",
                                                 "linetrace": enable_coverage}),
      test_suite='tests',
      license='GPLv2+, LGPLv2.1+',
      classifiers=[
          'Environment :: Console',
          'Environment :: X11 Applications :: Qt',
          'Intended Audience :: Information Technology',
          'Topic :: Security',
          'Topic :: Utilities',
      ],
      keywords='SELinux SETools policy analysis tools seinfo sesearch sediff sedta seinfoflow apol',
      python_requires='>=3.4',
      # setup also requires libsepol and libselinux
      # C libraries and headers to compile.
      setup_requires=['setuptools', 'Cython>=0.27'],
      install_requires=['setuptools', 'networkx>=2.0']
      )
