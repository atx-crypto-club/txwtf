#                                      .,;;,.
#                                     ,xOOOOo.
#                                     ;O0000x,
#                                     .,lxxl'
#                                       .cc.
#               'cll;.                  .::.                  .:ll:.
#              'x000Oc                  .cc.                 .o000Oo.
#              .lk0Okc                  .::.                 .oOOOkc.
#                .'..,;.                .:c.                .;,'''.
#                     .,,..         ..',cddc'..          .,,,.
#                       .',;'   .,coxkOO00000Okxoc'    ';'..
#                          .c,.'dKK0OO000000000O0K0o..,c.
#                           .cdk00000000OkkkkO000000ko:.
#                           :k0OO000Oo:,.....',cxO0000k,
#                        .'o00OO00Oo'   ......  'x000000c
#                        l0000O00Oc.  .:dkkOkkdclkO00000O:.
#     .','..            'kK0000O0d.   cOkkkkOkxxO000000O0d:.            .,,,'.
#   .,dO0OOd;..........'lO00000O0c   .xO:...;'..cO0O00OO0kx:...........:x000Oo'
#   .;k0000kc'''''''''',o000000OOc   'xk,    .;:oO0O00O00Okl'''''''''',lO0000x,.
#    .':c:;'            ,kK0O00O0l.  .ok,   ,x00000O000O0x:.            ,:cc;.
#                       .oK0O0OO0x,   'c'   ;kOxdO0OO0000c.
#                        .:xKOOOOOd,        .,'.'d000000o.
#                          .o00OOOOko;..      .,lO0000O:.
#                           .lkO0OO000OxooooodkO00000k:
#                           ,:,cOK0OOO0000000000O0Kk:':,
#                        .,;,.  .:dkO0000000000Oko;.  .,;..
#                      .,,'.       ..,::oxxo:;,..       .,,,.
#                .....;'.               .::.               .';....
#              .:dkkdc.                 .::.                 .lxkkd,
#              'x0000c                  .::.                 .o00OOd.
#               ;oxdc.                  .::.                  'lddl'
#                 .                     .::.                    .
#                                      .:dd:.
#                                     ,x00OOd'
#                                     ;k0000x'
#                                     .':c::.
#
# Utility to instrument the package in the production environment

import logging
import os
import unittest

import click

import txwtf.core


logger = logging.getLogger(__name__)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--log-file", envvar="LOG_FILE", default="-", help="Log file. Use '-' for stdout."
)
@click.option(
    "--log-level", envvar="LOG_LEVEL", default="INFO", help="Log output level."
)
@click.option(
    "--profiling/--no-profiling",
    default=False,
    help="Print performance profiling info on exit.",
)
@click.pass_context
def root(context, log_file, log_level, profiling):
    """
    tx.wtf run utility
    """

    class Obj:
        pass

    context.obj = obj = Obj()
    obj.log = log_file
    obj.log_level = log_level

    obj.profiling = profiling

    level = getattr(logging, obj.log_level.upper())
    txwtf.core.setup_logging(obj.log, level)


@root.command()
@click.option("--pattern", "-p", default="test*.py", help="test files to match")
@click.option("--verbosity", "-v", default=1, help="test output verbosity")
@click.pass_obj
def test(obj, pattern, verbosity):
    """
    Run test suite.
    """
    with txwtf.core.cli_context(obj):
        loader = unittest.TestLoader()
        suite = loader.discover(
            os.path.abspath(os.path.dirname(__file__)),
            pattern=pattern,
            top_level_dir=os.path.dirname(__file__),
        )
        runner = unittest.TextTestRunner(verbosity=verbosity)
        runner.run(suite)


if __name__ == "__main__":
    root(prog_name="run.py")
