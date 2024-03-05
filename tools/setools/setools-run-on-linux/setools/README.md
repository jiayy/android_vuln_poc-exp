# SETools: Policy analysis tools for SELinux
https://github.com/SELinuxProject/setools/wiki

## Overview

This file describes SETools.  SETools is a collection of graphical tools,
command-line tools, and libraries designed to facilitate SELinux policy
analysis.  Please consult the KNOWN-BUGS file prior to reporting bugs.

## Installation

SETools uses the Python setuptools build system to build, and install.
As such it contains a setup.py script that will install the tools.

To run SETools command line tools, the following packages are required:
* Python 3.4+
* NetworkX 2.0+
* setuptools
* libselinux
* libsepol 2.8+

To run SETools graphical tools, the following packages are also required:
* PyQt5
* qt5-assistant
* qt-devel (only if rebuilding the help file)

To build SETools, the following development packages are required, in
addition to the development packages from the above list:
* gcc
* cython 0.27+

To run SETools unit tests, the following packages are required, in
addition to the above dependencies:
* tox (optional)

### Obtaining SETools

SETools is included in most Linux distributions which support
SELinux, such as Fedora, Red Hat Enterprise Linux, Gentoo,
and Debian.

Official releases of SETools may be freely downloaded from:

https://github.com/SELinuxProject/setools/releases

SETools source code is maintained within a GitHub repository.
From the command line do:
```
  $ git clone https://github.com/SELinuxProject/setools.git
```
You may also browse the GitHub repository at
https://github.com/SELinuxProject/setools.  The master branch
has development code that may not be stable.  Each release series
is considered stable, and has its own branch, e.g. "4.0" for all
4.0.* releases.  To checkout a stable branch, do:
```
  $ git checkout 4.0
```
Where `4.0` is the release series.  Each release will have a tag.

### Building SETools for Local Use

To use SETools locally, without installing it onto the system,
unpack the official distribution or check out the git repository,
and perform the following at the root:
```
  $ python setup.py build_ext -i
```
This will compile the C portion of SETools locally, and then
the tools can be ran from the current directory (e.g. ```./seinfo```).

### Rebuilding the Apol Help File

For convenience, a prebuilt copy of the apol help data file is included.
To rebuild this file, the Qt5 development tools are required
(particularly, the ```qcollectiongenerator``` tool).  At the root
of the SETools sources, perform the following:
```
  $ python setup.py build_qhc
```

### Installing SETools

Unpack the official distribution or check out the git repository,
and perform the following at the root:
```
  $ python setup.py build_ext
  $ python setup.py build
  $ python setup.py install
```
This will put the applications in /usr/bin, data files in /usr/share/setools,
and libraries in /usr/lib/pythonX.Y/site-packages/setools.

### Building SETools with a Local Libsepol and Libselinux

At times, SETools requires a newer libsepol than is available from
distributions.  To use a locally-built libsepol instead of the libsepol
provided by the Linux distribution, build the libsepol sources and then
set the USERSPACE_SRC environmental variable to the path to the root of
SELinux userspace source tree. The libsepol and libselinux must already
be compiled.

```
  $ export USERSPACE_SRC=/home/user/src/selinux
  $ python setup.py build_ext
  $ python setup.py build
  $ python setup.py install
```

This feature assumes that the directory structure at $USERSPACE_SRC is the
same as the SELinux userspace code checked out from GitHub. 

Since SETools is dynamically linked to libsepol and libselinux, you must
specify the path to the libsepol/src and libselinux/src directories by
using LD_LIBRARY_PATH so that the newer versions of the libraries are used.

```
  $ export LD_LIBRARY_PATH="/home/user/src/selinux/libsepol/src:/home/user/src/selinux/libselinux/src"
  $ ./seinfo policy.31
  $ ./sesearch -A sysadm_t policy.31
```

### Installation Options

Please see `python setup.py --help` or `python setup.py install --help`
for up-to-date information on build and install options, respectively.

### Unit Tests

One goal for SETools is to provide confidence in the validity of the
output for the tools.  The unit tests for SETools can be run with
the following command
```
  $ python setup.py test
```

## Features

SETools encompasses a number of tools, both graphical and command
line, and libraries.  Many of the programs have help files accessible
during runtime.

### Graphical tools

Tool Name  | Use
---------- | -------------------------------------------
apol       | A Qt graphical analysis tool.  Use it to perform various types of analyses.

### Command-line tools

Tool Name  | Use
---------- | -------------------------------------------
sediff     | Compare two policies to find differences.
sedta      | Perform domain transition analyses.
seinfo     | List policy components.
seinfoflow | Perform information flow analyses.
sesearch   | Search rules (allow, type_transition, etc.)

### Analysis Libraries

The SETools libraries are available for use in third-party
applications.  Although this is not officially supported, we will
do our best to maintain API stability.

### Reporting bugs

Bugs can be reported in the SETools GitHub issues tracker:

https://github.com/SELinuxProject/setools/issues

### Copyright license

The intent is to allow free use of this source code.  All programs'
source files are copyright protected and freely distributed under the
GNU General Public License (see COPYING.GPL).  All library source
files are copyright under the GNU Lesser General Public License (see
COPYING.LGPL).  All files distributed with this package indicate the
appropriate license to use.  Absolutely no warranty is provided or implied.
