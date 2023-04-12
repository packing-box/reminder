# -*- coding: UTF-8 -*-
import logging
from argparse import ArgumentParser, RawTextHelpFormatter
from ast import literal_eval
from os.path import exists
from time import perf_counter

from .__info__ import __author__, __copyright__, __license__, __reference__, __source__, __version__
from .__init__ import REMINDer


def valid_file(path):
    if not exists(path):
        raise ValueError("input file does not exist")
    return path


class Positive:
    def __init__(self, *types):
        self._types = types
    
    def __call__(self, string):
        try:
            n = literal_eval(string)
        except ValueError:
            raise ValueError(string)
        if not isinstance(n, self._types) or n < 0.:
            raise ValueError(string)
        return self._types[0](n)
    
    def __repr__(self):
        return "positive %s" % "|".join(map(lambda x: x.__name__, self._types))


def main():
    """ Tool's main function """
    descr = "REMINDer {}\n\nAuthor   : {}\nCopyright: {}\nLicense  : {}\nReference: {}\nSource   : {}\n" \
            "\nThis tool applies a custom heuristic based on the entropy of the Entry Point section to determine if" \
            " an executable is packed or not.\n\n"
    descr = descr.format(__version__, __author__, __copyright__, __license__, __reference__, __source__)
    examples = "usage examples:\n- " + "\n- ".join([
        "reminder program.exe",
        "reminder /bin/ls --entropy-threshold 6.9",
    ])
    parser = ArgumentParser(description=descr, epilog=examples, formatter_class=RawTextHelpFormatter, add_help=False)
    parser.add_argument("path", type=valid_file, help="path to the executable file")
    opt = parser.add_argument_group("optional arguments")
    opt.add_argument("--entropy-threshold", type=Positive(float, int),
                     help="threshold for the entropy of the Entry Point section")
    extra = parser.add_argument_group("extra arguments")
    extra.add_argument("-b", "--benchmark", action="store_true",
                       help="enable benchmarking, output in seconds (default: False)")
    extra.add_argument("-h", "--help", action="help", help="show this help message and exit")
    extra.add_argument("-v", "--verbose", action="store_true", help="display debug information (default: False)")
    args = parser.parse_args()
    logging.basicConfig()
    args.logger = logging.getLogger("reminder")
    args.logger.setLevel([logging.INFO, logging.DEBUG][args.verbose])
    code = 0
    # execute the tool
    if args.benchmark:
        t1 = perf_counter()
    try:
        r = REMINDer(**vars(args)).detect(args.path)
        dt = str(perf_counter() - t1) if args.benchmark else ""
        if r is not None:
            print(str(r))
        if dt != "":
            print(dt)
    except Exception as e:
        if "magic not found." in str(e):
            e.value = "Not a valid executable file"
        if str(e) != "no result":
            args.logger.exception(e)
        code = 1
    return code

