import cProfile
import logging
import pstats
import sys
from contextlib import contextmanager


logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(levelname)-8.8s [%(name)s:%(lineno)s] %(message)s'


def setup_logging(
        log="-", log_level=logging.DEBUG, log_format=LOG_FORMAT):
    """
    Initialize logging for the app.
    """
    root = logging.getLogger()
    formatter = logging.Formatter(log_format)

    if log == "-":
        sh = logging.StreamHandler()
        sh.setLevel(log_level)
        sh.setFormatter(formatter)
        root.addHandler(sh)
    elif log:
        fh = logging.FileHandler(filename=log, mode='w')
        fh.setLevel(log_level)
        fh.setFormatter(formatter)
        root.addHandler(fh)

    root.setLevel(logging.DEBUG)


@contextmanager
def cli_context(obj):
    """
    Context manager for CLI options.
    """
    if obj.profiling:
        logger.info("enabling profiling")
        pr = cProfile.Profile()
        pr.enable()

    yield obj

    if obj.profiling:
        pr.disable()
        prof = pstats.Stats(pr, stream=sys.stdout)
        ps = prof.sort_stats('cumulative')
        ps.print_stats(300)


def stub():
    return True
