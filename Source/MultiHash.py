#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MultiHash.
Calculate multiple checksum digests reading each input file once.
"""


import hashlib
import os
import time
import sys

from queue import Queue
from threading import Thread

from argparse import ArgumentParser, RawDescriptionHelpFormatter


# Information and error messages:

def outln(line):
    """ Write 'line' to stdout, using UTF-8 and platform newline. """
    print(line)


def errln(line):
    """ Write 'line' to stderr, using UTF-8 and platform newline. """
    print(line, file = sys.stderr)


# Use FADVISE when available:

try:
    from fadvise import posix_fadvise, POSIX_FADV_SEQUENTIAL

    def fadvise_sequential(descriptor):
        """ Try to advise the kernel to read from 'descriptor' sequentially. """
        try:
            posix_fadvise(descriptor.fileno(), 0, 0, POSIX_FADV_SEQUENTIAL)
        except:
            pass

except ImportError:

    def fadvise_sequential(descriptor):
        """ No fadvise support. """
        pass


# IO utils:

def walk_binary_file(filepath, buffer_size):
    """ Yield 'buffer_size' bytes from 'filepath' until EOF. """
    with open(filepath, 'rb') as descriptor:
        fadvise_sequential(descriptor)

        while True:
            chunk = descriptor.read(buffer_size)
            if chunk:
                yield chunk
            else:
                break


def walk_binary_stdin(buffer_size):
    """ Yield 'buffer_size' bytes from stdin until EOF. """

    # sys.stdin is a TextIOWrapper instance, use the internal buffer:
    descriptor = sys.stdin.buffer

    while True:
        chunk = descriptor.read(buffer_size)
        if chunk:
            yield chunk
        else:
            break


def walk_binary_file_or_stdin(filepath, buffer_size = 32768):
    """
    Yield 'buffer_size' bytes from filepath until EOF, or from
    standard input when 'filepath' is '-'.
    """
    if filepath == '-':
        return walk_binary_stdin(buffer_size)
    else:
        return walk_binary_file(filepath, buffer_size)


def utf8_bytes(string):
    """ Convert 'string' to bytes using UTF-8. """
    return bytes(string, 'UTF-8')


# For portability, all checksum output is done in bytes
# to avoid Python automatic newline conversion:

BYTES_NEWLINES = {
    'dos'    : b'\r\n',
    'mac'    : b'\r',
    'unix'   : b'\n',
    'system' : utf8_bytes(os.linesep),
}


def binary_file_writelines(filepath, lines, newline):
    """
    Open 'filepath' in binary mode and write 'lines' (as bytes) to it
    using the specified 'newline' format (as bytes).
    """
    with open(filepath, mode = 'wb') as descriptor:
        for line in lines:
            descriptor.write(line)
            descriptor.write(newline)


def binary_stdout_writeline(line, newline):
    """
    Write 'line' (as bytes) to stdout without buffering
    using the specified 'newline' format (as bytes).
    """
    sys.stdout.buffer.write(line)
    sys.stdout.buffer.write(newline)
    sys.stdout.flush()


# Threads, tasks and a thread pool:

class Worker(Thread):
    """
    Thread that pops tasks from a '.todo' Queue, executes them, and puts
    the completed tasks in a '.done' Queue.

    A task is any object that has a run() method.
    Tasks themselves are responsible to hold their own results.
    """

    def __init__(self, todo, done):
        Thread.__init__(self)
        self.todo = todo
        self.done = done
        self.daemon = True
        self.start()

    def run(self):
        while True:
            task = self.todo.get()
            task.run()
            self.done.put(task)
            self.todo.task_done()


class HashTask(object):
    """
    A task that calculates multiple checksum algorithms for a given file
    reading it once and storing the results in itself.
    """

    def __init__(self, filepath, algorithms):
        self.filepath = filepath
        self.algorithms = algorithms

        # will hold the computed digests after executing run():
        self.digests = None

        # since we run in a thread with its own context
        # exception information is captured here:
        self.exception = None

    def run(self):
        try:
            instances = [hashlib.new(algorithm) for algorithm in self.algorithms]

            for chunk in walk_binary_file_or_stdin(self.filepath):
                for instance in instances:
                    instance.update(chunk)

            self.digests = [instance.hexdigest() for instance in instances]

        except:
            self.exception = sys.exc_info()


class ThreadPool(object):
    """
    Mantains a list of 'todo' and 'done' tasks and a number of threads
    consuming the tasks. Child threads are expected to put the tasks
    in the 'done' queue when those are completed.
    """

    def __init__(self, threads):
        self.threads = threads

        self.tasks = []
        self.results = set()

        self.todo = Queue()
        self.done = Queue()

    def start(self, tasks):
        """ Start computing tasks. """
        self.tasks = tasks

        for task in self.tasks:
            self.todo.put(task)

        for x in range(self.threads):
            Worker(self.todo, self.done)

    def wait_for_task(self):
        """ Wait for one task to complete. """
        while True:
            try:
                task = self.done.get(block = False)
                self.results.add(task)
                break

            # give tasks processor time:
            except:
                time.sleep(0.1)

    def poll_completed_tasks(self):
        """
        Yield the computed tasks, in the order specified when 'start(tasks)'
        was called, as soon as they are finished.
        """
        for task in self.tasks:
            while True:
                if task in self.results:
                    yield task
                    break
                else:
                    self.wait_for_task()

        # at this point, all the tasks are completed:
        self.todo.join()


# Parser:

def make_parser():
    parser = ArgumentParser(
        description = __doc__,
        formatter_class = RawDescriptionHelpFormatter,
        epilog = 'example: MultiHash.py md5 sha1 -i *.iso -o md5sums sha1sums',
        usage  = 'MultiHash.py algorithm [algorithm ...] [option [options ...]]',
    )

    # positional:
    parser.add_argument('algorithms',
        help = 'algorithms to compute for each file',
        choices = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
        nargs = '+')

    # optional:
    parser.add_argument('-i',
        help = 'files to checksum (default: stdin)',
        default = ['-'],
        dest = 'input', metavar = 'file',
        nargs = '+')

    parser.add_argument('-o',
        help = 'files to write computed checkums to (default: stdout)',
        dest = 'output', metavar = 'file',
        nargs = '+')

    parser.add_argument('--newline',
        help = 'use a specific newline mode (default: system)',
        choices = ['dos', 'mac', 'unix', 'system'],
        default = 'system')

    parser.add_argument('--threads',
        help = 'number of threads to use',
        default = 1,
        type = int)

    return parser


# Running modes:

def run(filepaths, algorithms, threads):
    """
    Create a thread pool and compute all the 'algorithms' for 'filepaths'
    yielding the completed tasks. On error, print exception messages.
    """
    pool = ThreadPool(threads)
    tasks = [HashTask(filepath, algorithms) for filepath in filepaths]

    pool.start(tasks)
    for task in pool.poll_completed_tasks():
        if task.exception:
            exc_type, exc_obj, exc_trace = task.exception
            errln(str(exc_obj))

        yield task


def run_stdout(filepaths, algorithms, threads, newline):
    """ Print all the digests for 'filepaths' to stdout. """
    status = 0

    for task in run(filepaths, algorithms, threads):
        if task.exception:
            status = 1
        else:
            for digest in task.digests:
                line = utf8_bytes('%s *%s' % (digest, task.filepath))
                binary_stdout_writeline(line, newline)

    sys.exit(status)


def run_files(filepaths, algorithms, threads, newline, targets):
    """ Write each algorithm digests to target files. """
    status = 0

    # compute digests and collect the result lines by algorithm:
    lines = { algorithm: [] for algorithm in algorithms }

    for task in run(filepaths, algorithms, threads):
        if task.exception:
            status = 1
        else:
            for digest, algorithm in zip(task.digests, task.algorithms):
                line = utf8_bytes('%s *%s' % (digest, task.filepath))
                lines[algorithm].append(line)

    # write to the target files:
    for algorithm, target in zip(algorithms, targets):
        if lines[algorithm]:
            try:
                binary_file_writelines(target, lines[algorithm], newline)

            except OSError:
                errln('error: %s: unable to write, skipped.' % target)
                status = 1

    sys.exit(status)


# Entry point:

def main():
    parser = make_parser()
    options = parser.parse_args()

    algorithms = options.algorithms
    filepaths = options.input
    targets = options.output
    threads = options.threads
    newline = BYTES_NEWLINES[options.newline]

    if threads < 1:
        errln('error: the number of threads must be positive.')
        sys.exit(1)

    if targets:
        if len(targets) != len(algorithms):
            errln('error: incorrect number of target files.')
            sys.exit(1)

        run_files(filepaths, algorithms, threads, newline, targets)

    else:
        run_stdout(filepaths, algorithms, threads, newline)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

