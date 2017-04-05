### HTSlib encryption test

This branch is a test to see how encryption might work in the HTSlib framework.
It adds an experimental plug-in that transparently encrypts and decrypts
files.  This plug-in is a proof of concept so a few short-cuts have been
taken.  It requires a `/dev/urandom` device driver to generate random keys.
It also uses `gpg` for part of the encryption - a real implementation would
be unlikely to work this way.


** WARNING:  hfile_crypto is for EXPERIMENTAL use only.  The file format is
liable to change.  Do not expect future versions to be able to read anything
written by this one.   Do not expect files encrypted by this module to actually
be secure. **

** It should not be used by anyone, apart from as a toy implementation. **

#### To build

As well as the normal HTSlib dependencies, you will need `libssl-dev`.
You also need `gpg`, installed as `/usr/bin/gpg`.

Run configure:

```
./configure --enable-plugins --enable-hfile_crypto --with-plugin-path=`pwd`
```

Run make:

```
make
```

This will build HTSlib and `hfile_crypto.so`

Next build samtools, in the directory next-door to htslib:

```
cd ../samtools
make
```

#### To use

First if you don't have one, generate a gpg key-pair using `gpg --gen-key`

Set the environment variable `HTS_CRYPT_TO` to identify the gpg public
key that you want to use to encrypt the file.  If you just made a key pair,
this would be the email address given to gpg when generating the key:

```
export HTS_CRYPT_TO=user@example.com
```

To encrypt a file, use the scheme `crypto:` in front of the file name.  So, to
create an encrypted BAM file:

```
./samtools view -b -o crypto:/tmp/example.bam test/dat/view.001.sam
```

To create an encrypted CRAM file:

```
./samtools view -C -T test/dat/view.001.fa  -o crypto:/tmp/example.cram  test/dat/view.001.sam
```

If you see something like this:

```
gpg: foo@bar.com: skipped: public key not found
gpg: [stdin]: encryption failed: public key not found
Error running gpg.
[E::hts_open_format] fail to open file 'crypto:/tmp/example.cram'
samtools view: failed to open "crypto:/tmp/example.cram" for writing
```

Then `gpg` didn't know about the recipient in your `HTS_CRYPT_TO` environment
variable.  To find out which recipients it knows about, run `gpg --list-keys`.

A file can be decrypted like this:

```
./samtools view -h crypto:/tmp/example.bam
```

HTSlib can also automatically detect encrypted files:
```
./samtools view -h /tmp/example.bam
```

`gpg` will ask for a passphrase to unlock the secret key needed to decrypt
the file.  To avoid having to type the passphrase in repeatedly, it's
recommended to use `gpg-agent`.  If it does not start up automatically,
it can be run like this:

```
gpg-agent --daemon /bin/bash
```

That will start up the agent, and open a new shell with the `GPG_AGENT_INFO`
environment variable set so that gpg will talk to it.  To stop the agent
process, simply exit the shell.

This plug-in can encrypt any type of file, not just bam or cram.  So it
is possible to create an encrypted index.  This will create an encrypted
bam index.  Note that the `crypto:` scheme has been left in front of
the input file name.  Samtools will add a `.bai` suffix to make the index
file name `crypto:/tmp/example.bam.bai`, causeing HTSlib to write an
encrypted index.

```
./samtools index crypto:/tmp/example.bam
```

The index can then be used in the normal way to extract reads:

```
./samtools view /tmp/example.bam ref1:10-11
```

(Note that currently it is not possible to make an encrypted cram index.
This is due to the cram indexing code not currently using the `hfile`
interface, and will be fixed at some point in the future.)

### Original HTSlib README

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
./configure    # Optional, needed for choosing optional functionality
make
make install
```

[download]: http://www.htslib.org/download/
