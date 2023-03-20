import os
import subprocess
from os.path import dirname, expanduser, join

import click


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


@click.group(context_settings={"help_option_names": ['-h', '--help']})
@click.option(
    "--edm-root", default=_get_default_edm_root(),
    help="EDM root"
)
@click.option(
    "--edm-env", default="txwtf-dev",
    help="EDM environment to use"
)
@click.option(
    "--edm-py-version", default="3.8",
    help="Version of python to use"
)
@click.option(
    "--edm-bin", default=_get_default_edm_bin(),
    help="EDM binary to use"
)
@click.pass_context
def root(context, edm_root, edm_env, edm_py_version, edm_bin):
    """
    continuous integration tasks
    """
    class Obj:
        pass

    context.obj = obj = Obj()
    obj.edm_root = edm_root
    obj.edm_env = edm_env
    obj.edm_py_version = edm_py_version
    obj.edm_bin = edm_bin
    pass


@root.command()
@click.option(
    "--replace/--no-replace", default=False,
    help="Force replace environment?"
)
@click.pass_obj
def bootstrap(obj, replace):
    """
    create EDM environment for running sscore
    """
    if not os.path.isdir(obj.edm_root):
        os.mkdir(obj.edm_root)
    args = []
    if replace:
        args = ["--force"]
    try:
        subprocess.check_call(
            [obj.edm_bin, "-r", obj.edm_root, "envs",
             "create", obj.edm_env, "--version=%s" % obj.edm_py_version] + args)
    except subprocess.CalledProcessError:
        pass


source_dir_option = click.option(
    "--source-dir", default=join(dirname(__file__), ".."),
    help="Directory where txwtf/setup.py lives"
)


def install_deps(obj, source_dir):
    ENV_DEPS = ["pyyaml", "requests"]
    cmd_base = [obj.edm_bin, "-r", obj.edm_root]

    # install edm runtime deps
    subprocess.check_call(
        cmd_base + [
            "install", "-e", obj.edm_env, "-y"] + ENV_DEPS)

    # install other requirements via pip
    edm_run_cmd = cmd_base + ["run", "-e", obj.edm_env, "--"]
    req = join(source_dir, "requirements.txt")
    subprocess.check_call(
        edm_run_cmd + ["pip", "install", "-r", req])


def install_application(obj, source_dir, editable=False):
    cmd_base = [obj.edm_bin, "-r", obj.edm_root]
    edm_run_cmd = cmd_base + ["run", "-e", obj.edm_env, "--"]
    editable_arg = []
    if editable:
        editable_arg = ["-e"]
    subprocess.check_call(
        edm_run_cmd + ["pip", "install"] + editable_arg + [source_dir])


@root.command()
@source_dir_option
@click.pass_obj
def install_dev(obj, source_dir):
    """
    Install txwtf in the target environment in dev mode (editable)
    """
    install_deps(obj, source_dir)
    install_application(obj, source_dir, True)


@root.command()
@source_dir_option
@click.pass_obj
def install(obj, source_dir):
    """
    Install txwtf in the target environment
    """
    install_deps(obj, source_dir)
    install_application(obj, source_dir, False)


@root.command()
@click.pass_obj
def migrate(obj):
    """
    Migrate the database to HEAD
    """
    cmd_base = [obj.edm_bin, "-r", obj.edm_root]
    edm_run_cmd = cmd_base + ["run", "-e", obj.edm_env, "--"]
    # We probably want to pass options to migration here
    # but for now we just assume we want to upgrade to the HEAD
    # db revision.
    subprocess.check_call(
        edm_run_cmd + [
            "flask", "--app", "txwtf.webapp", "db", "upgrade"])


@root.command()
@click.pass_obj
def test(obj):
    """
    Run tests in txwtf EDM environment
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root, "run", "-e", obj.edm_env, "--"]
    subprocess.check_call(
        edm_run_cmd + ["txwtf", "test"], cwd=dirname(__file__))


@root.command()
@click.pass_obj
def flake8(obj):
    """
    Run flake8 in txwtf EDM environment
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root, "run", "-e", obj.edm_env, "--"]
    subprocess.check_call(
        edm_run_cmd + ["txwtf", "flake8"], cwd=join(dirname(__file__), ".."))


@root.command()
@click.argument('cmd_args', nargs=-1)
@click.pass_obj
def run(obj, cmd_args):
    """
    Run command in EDM environment
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root,
        "run", "-e", obj.edm_env, "--"] + list(cmd_args)
    subprocess.check_call(edm_run_cmd)


@root.command()
@click.option(
    "--log", envvar="TXWTF_LOG", default="-",
    help="Log file. Use '-' for stdout.")
@click.option(
    "--log-level", default="WARNING",
    help="Log output level.")
@click.argument('cmd_args', nargs=-1)
@click.pass_obj
def run_txwtf(obj, log, log_level, cmd_args):
    """
    Run txwtf in EDM environment
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root, "run", "-e", obj.edm_env, "--"]
    subprocess.check_call(
        edm_run_cmd + [
            "txwtf",
            "--log={}".format(log),
            "--log-level={}".format(log_level)] + list(cmd_args))


@root.command()
@click.pass_obj
def shell(obj):
    """
    Conveniently drop into the txwtf edm environment.
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root, "shell", "-e", obj.edm_env]
    subprocess.check_call(edm_run_cmd)


if __name__ == '__main__':
    root(prog_name="txwtf_ci")
