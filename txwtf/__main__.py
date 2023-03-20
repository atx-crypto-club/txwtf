import logging
import os
import subprocess
import sys
import unittest

import click

import txwtf.core


logger = logging.getLogger(__name__)


@click.group(context_settings={"help_option_names": ['-h', '--help']})
@click.option(
    "--log", envvar="TXWTF_LOG", default="-",
    help="Log file. Use '-' for stdout.")
@click.option(
    "--log-level", default="WARNING",
    help="Log output level.")
@click.option(
    '--profiling/--no-profiling', default=False,
    help="Print performance profiling info on exit.")
@click.pass_context
def root(context, log, log_level, profiling):
    """
    tx.wtf web application
    """
    class Obj:
        pass

    context.obj = obj = Obj()
    obj.log = log
    obj.log_level = log_level
    obj.profiling = profiling

    level = getattr(logging, obj.log_level.upper())
    txwtf.core.setup_logging(obj.log, level)


@root.command()
@click.option(
    '--pattern', '-p', default='test*.py',
    help="test files to match")
@click.pass_obj
def test(obj, pattern):
    """
    Run test suite.
    """
    with txwtf.core.cli_context(obj):
        loader = unittest.TestLoader()
        suite = loader.discover(
            os.path.abspath(os.path.dirname(__file__)),
            pattern=pattern)
        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(suite)


@root.command()
@click.pass_obj
def flake8(obj):
    """
    Run flake8.
    """
    try:
        subprocess.check_call([sys.executable, '-m', 'flake8'])
        print("flake8 OK")
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            print("\nThere were flake8 errors!")


@root.command()
@click.pass_obj
def version(obj):
    """
    Print version.
    """
    import txwtf
    print(txwtf.__version__)


@root.command()
@click.option(
    '--host', '-s', default='localhost',
    help="host interface to bind to")
@click.option(
    '--port', '-p', default='8086',
    help="service port")
@click.option(
    '--threaded/--no-threaded', default=True,
    help="Whether to thread request handling or not")
@click.option(
    '--debug/--no-debug', default=False,
    help="Toggle flask debugging")
@click.pass_obj
def webapp(obj, host, port, threaded, debug):
    """
    Run the flask app
    """
    import txwtf.webapp
    app = txwtf.webapp.create_app()
    app.run(host=host, port=port, threaded=threaded, debug=debug)


if __name__ == '__main__':
    root(prog_name="txwtf")
