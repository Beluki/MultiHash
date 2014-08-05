
## About

MultiHash is a small Python 3 program that can calculate file digests,
like those generated by the [coreutils][] tools [md5sum][], [sha1sum][], etc...

The main selling point is that it reads all the input files once,
calculating all the requested algorithms in one go. For example,
the following command:

```bash
$ MultiHash.py md5 sha1 -i *.iso -o md5sums sha1sums
```

Is equivalent to:

```bash
$ md5sum *.iso > md5sums
$ sha1sum *.iso > sha1sums
```

[coreutils]: http://www.gnu.org/software/coreutils
[md5sum]: http://www.gnu.org/software/coreutils/manual/html_node/md5sum-invocation.html#md5sum-invocation
[sha1sum]: http://www.gnu.org/software/coreutils/manual/html_node/sha1sum-invocation.html#sha1sum-invocation

## Installation and usage

To install, just make sure you are using Python 3. MultiHash will use the
[python-fadvise][] module if it is installed. There are no other dependencies.
MultiHash is a single Python script that you can put in your PATH.

[python-fadvise]: https://github.com/lamby/python-fadvise

Using it is pretty simple. One algorithm, one file:

```bash
$ MultiHash.py md5 -i debian-7.1.0-i386-DVD-1.iso
6986e23fc4b8b7ffdb37a82da7446e8a *debian-7.1.0-i386-DVD-1.iso
```

Multiple algorithms, one file:

```bash
$ MultiHash.py md5 sha1 -i debian-7.1.0-i386-DVD-1.iso
6986e23fc4b8b7ffdb37a82da7446e8a *debian-7.1.0-i386-DVD-1.iso
cea26c7764188426da8c96bdf40eff138eb26fdc *debian-7.1.0-i386-DVD-1.iso
```

Multiple algorithms, multiple files:

```bash
$ MultiHash.py md5 sha1 -i *.iso -o md5sums sha1sums

$ cat md5sums
6986e23fc4b8b7ffdb37a82da7446e8a *debian-7.1.0-i386-DVD-1.iso
8a1bf570e05ac4f378c24a4bcd6c7085 *debian-7.1.0-i386-DVD-2.iso
6ee99fe1f80e1c197cd35c404448e6af *debian-7.1.0-i386-DVD-3.iso
f84fe104755ae19c76c5d7ef09eff06d *debian-7.1.0-i386-DVD-4.iso
c8a99e4474f259e42093d1219eba0cf3 *debian-7.1.0-i386-DVD-5.iso

$ cat sha1sums
cea26c7764188426da8c96bdf40eff138eb26fdc *debian-7.1.0-i386-DVD-1.iso
60d918b8f5fded013dc5f53ad0d6e9510a5cb2ee *debian-7.1.0-i386-DVD-2.iso
0cfe71a98e48140be53e3a5023ad0dd112ac45aa *debian-7.1.0-i386-DVD-3.iso
f6bef688c7e21c9d89bd601f7d382ac84531a8bf *debian-7.1.0-i386-DVD-4.iso
b3112b29d6430c77b8653d8b615d2699bff20fa3 *debian-7.1.0-i386-DVD-5.iso
```

## Command-line options

MultiHash has some options that can be used to change the behavior:

* `-i file [file ...]` specifies input files to checksum. If no files
  are specified or if the filename is `-` stdin will be used.

* `-o file [file ...]` specifies output files where the results will
  be written. There must be the same number of output files as algorithms.
  If no output files are specified, stdout will be used.

* `--newline [dos, mac, unix, system]` changes the newline format.
  I tend to use unix newlines everywhere, even on Windows. The default is
  `system`, which uses the current platform newline format.

* `--threads n` runs n threads in parallel. Threads are spread accross
  input files, where each thread calculates all the algorithms for one file.
  Regardless of which thread completes first, results will be printed in
  the same order specified as input. The default is to use a single thread.

## Portability

Information and error messages are written to stdout and stderr
respectively, using the current platform newline format and encoding.

The output is compatible to that of the coreutils tools and can be checked
with them (e.g. `md5sum -c`). When using the same `--newline format`, output
should be byte by byte identical between platforms.

MultiHash always reads input in binary mode, prepending an asterisk to the
filename (like md5sum) on output. It makes no sense to read input as text
and md5sum defaulting to text has been a source of problems (e.g. on Cygwin
and Windows) in the past.

The exit status is 0 on success and 1 on errors. After an error,
MultiHash skips the current file and proceeds with the next one
instead of aborting. It can be interrupted with Control + C.

MultiHash is tested on Windows 7 and 8 and on Debian (both x86 and x86-64)
using Python 3.3+. Python 2.x is not supported.

## Performance

The performance of MultiHash depends on many factors:

* Whether the operation is IO-bound (slow hard disks, single algorithm)
  or CPU-bound (RAID or SSD, multiple or more complex algorithms).

* Whether the filesystem has fadvise support.

* Performance of the IO-scheduler when running multiple threads. In
  particular, Windows is known to dramatically [degrade][] performance
  when multiple threads read multiple files at the same time.

* Whether the input files are currently cached. Unlikely on big ISOs.

[degrade]: http://stackoverflow.com/questions/9191/how-to-obtain-good-concurrent-read-performance-from-disk

Worst case scenario. A laptop with a very slow disk, a single core,
Windows 32 bit, calculating a single algorithm with one thread:

```bash
$ time md5sum *.iso
e44ea9c993ce105ae71c5723f0369b45 *1.iso
0f031b720f08bb2ec818f0743fdff9c7 *2.iso
30e0076948fba2777fce9fca3de304ae *3.iso
e764e45f5fd6c0459af1329572a68318 *4.iso

real    0m23.520s
user    0m0.000s
sys     0m0.000s

$ time MultiHash.py md5 -i *.iso
e44ea9c993ce105ae71c5723f0369b45 *1.iso
0f031b720f08bb2ec818f0743fdff9c7 *2.iso
30e0076948fba2777fce9fca3de304ae *3.iso
e764e45f5fd6c0459af1329572a68318 *4.iso

real    0m23.570s
user    0m0.000s
sys     0m0.000s
```

Best case scenario. A server with a fast RAID, quad core, Debian Wheezy 64 bit,
calculating multiple algorithms with multiple threads:

```bash
$ cat run-coreutils.sh
#!/bin/sh
md5sum *.iso > md5.1
sha1sum *.iso > sha1.1
sha256sum *.iso > sha256.1
sha512sum *.iso > sha512.1

$ time ./run-coreutils.sh
real    4m39.582s
user    0m0.030s
sys     0m0.045s

$ time MultiHash.py md5 sha1 sha256 sha512 --threads 4 \
      -i *.iso -o md5.2 sha1.2 sha256.2 sha512.2
real    0m40.721s
user    0m0.000s
sys     0m0.015s
```

Ensuring the generated files are identical:

```bash
$ diff md5.1 md5.2
$ diff sha1.1 sha1.2
$ diff sha256.1 sha256.2
$ diff sha512.1 sha512.2
```

Your mileage may vary. Both systems were rebooted before running each benchmark
(both before running the coreutils tools and before running MultiHash) to minimize
caching impact. Remember, there are Lies, Damn Lies and Benchmarks.

## Status

This program is feature-complete and has no known bugs. Unless new issues
are reported or requests are made I plan no further development on it other
than maintenance.

## License

Like all my hobby projects, this is Free Software. See the [Documentation][] folder
for more information. No warranty though.

[Documentation]: https://github.com/Beluki/MultiHash/tree/master/Documentation

