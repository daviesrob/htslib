[![Build Status](https://travis-ci.org/samtools/htslib.svg?branch=develop)](https://travis-ci.org/samtools/htslib)
[![Build status](https://ci.appveyor.com/api/projects/status/v46hkwyfjp3l8nd3/branch/develop?svg=true)](https://ci.appveyor.com/project/samtools/htslib/branch/develop)
[![Github All Releases](https://img.shields.io/github/downloads/samtools/htslib/total.svg)](https://github.com/samtools/htslib)

### HTSlib crypt4gh demonstrator

This version of HTSlib supports the experimental crypt4gh file encryption
standard.
It adds a crypt4gh plug-in which can read and write the format along with
code to detect encrypted files that have been opened for reading and route
them through the plug-in.
If this version of HTSlib is linked into samtools or bcftools, these programs
will also gain the ability to read and write the encrypted format.

#### Building this version

As well as the dependencies listed in the [INSTALL](INSTALL) file, the crypt4gh
plug-in currently requires libsodium for encryption support.
An up-to-date copy can be obtained from [the libsodium web site.](https://download.libsodium.org/libsodium/releases/LATEST.tar.gz)

First download, extract and build libsodium:

```
wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
tar xvf LATEST.tar.gz
cd libsodium-stable/
./configure --prefix=$HOME/opt/libsodium
make
make install
cd ..
```

Next configure and build HTSlib:

```
cd htslib
autoconf
autoheader
./configure --enable-hfile-crypt4gh CPPFLAGS="-I$HOME/opt/libsodium/include" LDFLAGS="-L$HOME/opt/libsodium/lib -Wl,-R$HOME/opt/libsodium/lib"
make
cd ..
```

This will build HTSlib, the programs `bgzip`, `htsfile` and `tabix`, and
the agent program `crypt4gh_agent` which is in the `crypto/` directory.

To build a copy of samtools that works with this copy of HTSlib, build it
in a directory next to the htslib one:

```
cd samtools
autoconf
autoheader
./configure
make
cd ..
```

#### Reading and writing encrypted files

First start the agent.
A key pair can be created using the `-g` option:

```
cd htslib       # If not there already
./crypto/crypt4gh_agent -g my_key
```

It will prompt for a passphrase, which is used to protect the secret key.
To ensure that it was enetered correctly it will also ask for the
passphrase to be repeated.
The security of the system depends on having a good passphrase, so it is best
to use a long one.

Starting the agent in this way will generate two files.
`my_key.sec` is the private key used to decrypt files.
`my_key.pub` is the public key used to encrypt them.

The secret key must be kept secure.
The public one can be given to anyone who may want to send you an encrypted file.

If the keys are already available then the agent can instead be started
using the `-k` option to read the keys:

```
cd htslib       # If not there already
./crypto/crypt4gh_agent -k my_key.pub -k my_key.sec
```

In this case the agent will prompt for the passphrase for any secret keys.

Keys can be passed to the agent in any order.
By default, when encrypting files the first public key listed will be used.
When decrypting, each secret key will be tried in turn until either one
works or none are left.
If necessary, the default choice can be overridden using the CRYPT4GH_PUBLIC
and CRYPT4GH_SECRET environment variables.

When run in either way, the agent will start a new shell.
In this shell, the environment variable CRYPT4GH_AGENT will have been set
with the location of a socket that the plug-in uses to communicate with the
agent.
When the agent is no longer needed, simply close the shell by typing `exit`.

A simple way to encrypt and decrypt files is to use the `htsfile` copy option:

```
./htsfile -C test/ce#1.sam crypt4gh:/tmp/encrypted.sam
./htsfile -C /tmp/encrypted.sam /tmp/decrypted.sam
```

If `samtools` has been built, it should be able to read and write
the encrypted data too:

```
cd ../samtools   # if not there already
./samtools view -h -o crypt4gh:/tmp/encrypted.sam test/dat/view.001.sam
./samtools view -h /tmp/encrypted.sam
```

### Original README.md

HTSlib is an implementation of a unified C library for accessing common file
formats, such as [SAM, CRAM and VCF][1], used for high-throughput sequencing
data, and is the core library used by [samtools][2] and [bcftools][3].
HTSlib only depends on [zlib][4].
It is known to be compatible with gcc, g++ and clang.

HTSlib implements a generalized BAM index, with file extension `.csi`
(coordinate-sorted index). The HTSlib file reader first looks for the new index
and then for the old if the new index is absent.

This project also includes the popular tabix indexer, which indexes both `.tbi`
and `.csi` formats, and the bgzip compression utility.

[1]: http://samtools.github.io/hts-specs/
[2]: http://github.com/samtools/samtools
[3]: http://samtools.github.io/bcftools/
[4]: http://zlib.net/

### Building HTSlib

See [INSTALL](INSTALL) for complete details.
[Release tarballs][download] contain generated files that have not been
committed to this repository, so building the code from a Git repository
requires extra steps:

```sh
autoheader     # If using configure, generate the header template...
autoconf       # ...and configure script (or use autoreconf to do both)
./configure    # Optional but recommended, for choosing extra functionality
make
make install
```

[download]: http://www.htslib.org/download/
