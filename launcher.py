from __future__ import print_function

import os
import shutil
import subprocess
import sys
import tempfile
from os.path import abspath, dirname, expanduser, join


def _get_default_environment_root():
    return os.environ.get(
        "ENV_ROOT", join(expanduser("~"), "python-runtime", "txwtf"))


def _get_default_edm_install_prefix():
    return os.environ.get(
        "EDM_INSTALL_PREFIX", join(_get_default_environment_root(), "edm"))


def _get_default_edm_root():
    root = os.environ.get(
        "EDM_ROOT", join(_get_default_environment_root(), "edm-envs"))
    if "EDM_VIRTUAL_ENV" in os.environ:
        root = os.path.abspath(
            join(os.environ["EDM_VIRTUAL_ENV"], "..", ".."))
    return root


def _get_default_edm_bin():
    return os.environ.get(
        "EDM_BIN", join(_get_default_edm_install_prefix(), "bin", "edm"))


EDM_BIN = _get_default_edm_bin()
EDM_ROOT = _get_default_edm_root()
BOOTSTRAP_PY_VER = os.environ.get("BOOTSTRAP_PY_VER", "3.8")
BOOTSTRAP_ENV = os.environ.get(
    "BOOTSTRAP_ENV", "txwtf-bootstrap-" + BOOTSTRAP_PY_VER)
BOOTSTRAP_ENV_DEPS = ["click"]
BOOTSTRAP_SOURCE = abspath(dirname(__file__))

TXWTF_PY_VER = os.environ.get("TXWTF_PY_VER", "3.8")
TXWTF_ENV = os.environ.get(
    "TXWTF_ENV", "txwtf-prod-" + TXWTF_PY_VER)

if __name__ == '__main__':
    env = os.environ.copy()
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] += ":" + BOOTSTRAP_SOURCE
    else:
        env["PYTHONPATH"] = BOOTSTRAP_SOURCE

    cmd_base = [EDM_BIN, "-r", EDM_ROOT]
    cmd_run_base = cmd_base + ["run", "-e", BOOTSTRAP_ENV, "--"]
    txwtf_ci = cmd_run_base + ["python", "-m", "txwtf_ci"]

    args = [
        "bootstrap", "install-dev", "migrate", "test", "txwtf", "webapp"]
    if len(sys.argv) > 1:
        args = sys.argv[1:]

    do_tempdir = False

    while len(args) > 0:
        arg = args[0]
        cmds = []

        if arg == "bootstrap":
            cmds = [
                cmd_base + [   # set up the EDM environment
                    "envs", "create", BOOTSTRAP_ENV,
                    "--version={}".format(BOOTSTRAP_PY_VER)],
                cmd_base + [   # install bootstrap deps
                    "install", "-e", BOOTSTRAP_ENV, "-y"] + BOOTSTRAP_ENV_DEPS,
                txwtf_ci + [   # bootstrap txwtf dev env
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "--edm-py-version={}".format(TXWTF_PY_VER),
                    "bootstrap"]]
            args = args[1:]

        elif arg == "install":
            cmds = [
                txwtf_ci + [   # install txwtf into dev env
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "install"]]
            args = args[1:]

        elif arg == "install-dev":
            cmds = [
                txwtf_ci + [   # editable install txwtf into dev env
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "install-dev"]]
            args = args[1:]

        elif arg == "migrate":
            cmds = [
                txwtf_ci + [
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "migrate"]]
            args = args[1:]

        elif arg == "clean":
            cmds = [
                cmd_base + [
                    "envs", "remove", "--force", "-y", TXWTF_ENV],
                cmd_base + [
                    "envs", "remove", "--force", "-y", BOOTSTRAP_ENV]]
            args = args[1:]

        elif arg == "nuke":
            shutil.rmtree(_get_default_environment_root())
            args = args[1:]

        elif arg == "test":
            cmds = [           # run tests
                txwtf_ci + [
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "test"]]
            args = args[1:]

        elif arg == "flake8":
            cmds = [           # run linter
                txwtf_ci + [
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "flake8"]]
            args = args[1:]

        elif arg == "shell":
            cmds = [
                txwtf_ci + [
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "shell"]]
            args = args[1:]

        elif arg == "run":
            cmds = [
                txwtf_ci + [
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "run"] + args[1:]]
            args = []  # run consumes the rest of the arguments

        elif arg == "txwtf":
            cmds = [
                txwtf_ci + [
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "run-txwtf"] + args[1:]]
            args = []  # run consumes the rest of the arguments

        elif arg == "wsgi":
            cmds = [
                txwtf_ci + [
                    "--edm-bin={}".format(EDM_BIN),
                    "--edm-root={}".format(EDM_ROOT),
                    "--edm-env={}".format(TXWTF_ENV),
                    "run-wsgi"] + args[1:]]
            args = []  # run consumes the rest of the arguments

        elif arg == "tmpdir":
            do_tempdir = True
            args = args[1:]
        else:
            print("Unknown command {}".format(arg), file=sys.stderr)
            args = args[1:]

        if do_tempdir:
            td = tempfile.mkdtemp()
            cwd = os.getcwd()
            try:
                for cmd in cmds:
                    try:
                        subprocess.check_call(cmd, env=env, cwd=td)
                    except subprocess.CalledProcessError:
                        pass
            finally:
                os.chdir(cwd)
                os.rmdir(td)
        else:
            for cmd in cmds:
                try:
                    subprocess.check_call(cmd, env=env)
                except subprocess.CalledProcessError:
                    pass