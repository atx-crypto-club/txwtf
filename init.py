from __future__ import print_function

from contextlib import contextmanager
import os
import subprocess
import tempfile
from os.path import abspath, dirname, expanduser, join

import click


# TODO: consider adding a command to drop into the
# boostrap environment in case a developer wants to
# run the ci module directly...


def _get_default_environment_root():
    return os.environ.get("ENV_ROOT", join(expanduser("~"), "python-runtime"))


def _get_default_edm_install_prefix(env_root=_get_default_environment_root()):
    return os.environ.get("EDM_INSTALL_PREFIX", join(env_root, "edm"))


def _get_default_edm_root(env_root=_get_default_environment_root()):
    if "EDM_VIRTUAL_ENV" in os.environ:
        root = os.path.abspath(join(os.environ["EDM_VIRTUAL_ENV"], "..", ".."))
    else:
        root = os.environ.get("EDM_ROOT", join(env_root, "edm-envs"))
    return root


def _get_default_edm_bin(env_root=_get_default_environment_root()):
    return os.environ.get(
        "EDM_BIN", join(_get_default_edm_install_prefix(env_root), "bin", "edm")
    )


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--env-root",
    default=_get_default_environment_root(),
    envvar="ENV_ROOT",
    help="Environment root where edm and project install lives",
)
@click.option(
    "--edm-root", default=None, envvar="EDM_ROOT", help="EDM root environment directory"
)
@click.option("--edm-bin", default=None, envvar="EDM_BIN", help="EDM binary to use")
@click.pass_context
def root(context, env_root, edm_root, edm_bin):
    """
    Project application environment launcher
    """
    # env_root is ignored if both edm_root and edm_bin are provided

    if edm_root is None:
        edm_root = _get_default_edm_root(env_root)
    if edm_bin is None:
        edm_bin = _get_default_edm_bin(env_root)

    class Obj:
        pass

    context.obj = obj = Obj()

    obj.edm_root = edm_root
    obj.edm_bin = edm_bin
    obj.cmd_base = [obj.edm_bin, "-r", obj.edm_root]


def bootstrap_cmds(obj, **kwargs):
    bootstrap_xtra_args = []
    project_xtra_args = []
    if kwargs["bootstrap_replace"]:
        bootstrap_xtra_args = ["--force"]
    if kwargs["project_replace"]:
        project_xtra_args = ["--replace"]
    return [
        # set up the EDM environment
        obj.cmd_base
        + [
            "envs",
            "create",
            obj.bootstrap_env,
            "--version={}".format(obj.bootstrap_py_ver),
        ]
        + bootstrap_xtra_args,
        # install bootstrap deps
        obj.cmd_base
        + ["install", "-e", obj.bootstrap_env, "-y"]
        + obj.bootstrap_env_deps,
        # bootstrap project dev env
        obj.proj_ci + ["bootstrap"] + project_xtra_args,
    ], kwargs["args"]


def install_cmds(obj, **kwargs):
    """
    install project into dev env
    """
    return [
        obj.proj_ci
        + ["install"]
        + ["--source-dir={}".format(kwargs["install_source_dir"])]
    ], kwargs["args"]


def install_dev_cmds(obj, **kwargs):
    """
    install project into dev env as an in place editable install
    """
    return [
        obj.proj_ci
        + ["install-dev"]
        + ["--source-dir={}".format(kwargs["install_source_dir"])]
    ], kwargs["args"]


def migrate_cmds(obj, **kwargs):
    """
    Project database migration
    """
    return [obj.proj_ci + ["migrate"]], kwargs["args"]


def test_cmds(obj, **kwargs):
    """
    Run project tests
    """
    return [obj.proj_ci + ["test"]], kwargs["args"]


def clean_cmds(obj, **kwargs):
    """
    Remove project and bootstrap environments
    """
    return [
        obj.cmd_base + ["envs", "remove", "--force", "-y", obj.project_env],
        obj.cmd_base + ["envs", "remove", "--force", "-y", obj.bootstrap_env],
    ], kwargs["args"]


def nuke_cmds(obj, **kwargs):
    """
    Nuke the whole edm root.
    """
    # TODO: this should probably be nuking full env root
    return [
        obj.cmd_run_base
        + ["python", "-c", "import shutil; shutil.rmtree('{}')".format(obj.edm_root)]
    ], kwargs["args"]


def default_cmds(obj, **kwargs):
    """
    Project ci command passthru
    """
    # pass thru consumes the rest of the arguments
    return [obj.proj_ci + [kwargs["cmd"]] + list(kwargs["args"])], []


def run_cmds(obj, **kwargs):
    """
    Run command in project environment
    """
    # run consumes the rest of the arguments
    return [obj.proj_ci + ["run"] + list(kwargs["args"])], []


def run_project_cmds(obj, **kwargs):
    """
    Run main project entry point
    """
    cmd = obj.proj_ci
    cmd.append("run-app")
    cmd.append("--log-file={}".format(kwargs["log_file"]))
    cmd.append("--log-level={}".format(kwargs["log_level"]))
    if kwargs["profiling"]:
        cmd.append("--profiling")
    cmd += kwargs["args"]

    # run project consumes the rest of the arguments
    return [cmd], []


def run_wsgi_cmds(obj, **kwargs):
    """
    Run wsgi along with application
    """
    cmd = obj.proj_ci
    cmd.append("run-wsgi")
    cmd.append("--log-file={}".format(kwargs["log_file"]))
    cmd.append("--log-level={}".format(kwargs["log_level"]))
    cmd.append("--bind={}".format(kwargs["bind"]))
    cmd += kwargs["args"]

    # run project consumes the rest of the arguments
    return [cmd], []


_cmd_map = {
    "bootstrap": bootstrap_cmds,
    "install": install_cmds,
    "install-dev": install_dev_cmds,
    "migrate": migrate_cmds,
    "test": test_cmds,
    "clean": clean_cmds,
    "nuke": nuke_cmds,
    "run": run_cmds,
    "run-app": run_project_cmds,
    "wsgi": run_wsgi_cmds,
}


@contextmanager
def run_ctx(obj):
    if obj.tmpdir:
        td = tempfile.mkdtemp()
        cwd = os.getcwd()
        try:
            yield td
        finally:
            os.chdir(cwd)
            os.rmdir(td)
    else:
        yield os.getcwd()


def do_run_cmds(cmds, env, cwd):
    for cmd in cmds:
        try:
            if len(cmd) > 0 and callable(cmd[0]):
                # TODO: cd to cwd for consistency with the check_call
                retval = cmd[0](*cmd[1:])
            else:
                retval = subprocess.check_call(cmd, env=env, cwd=cwd)
        except subprocess.CalledProcessError:
            # TODO: log this
            # TODO: toggle for return on error
            pass


@root.command()
@click.option(
    "--bootstrap-replace/--no-bootstrap-replace",
    default=False,
    envvar="BOOTSTRAP_REPLACE",
    help="Force replace bootstrap environment",
)
@click.option(
    "--bootstrap-env",
    default="bootstrap",
    envvar="BOOTSTRAP_ENV",
    help="bootstrap environment name",
)
@click.option(
    "--bootstrap-py-ver",
    default="3.8",
    envvar="BOOTSTRAP_PY_VER",
    help="bootstrap environment python version",
)
@click.option(
    "--project-replace/--no-project-replace",
    default=False,
    envvar="PROJECT_REPLACE",
    help="Force replace project environment",
)
@click.option(
    "--project-env",
    default="prod",
    envvar="PROJECT_ENV",
    help="project environment name",
)
@click.option(
    "--project-py-ver",
    default="3.8",
    envvar="PROJECT_PY_VER",
    help="project environment python version",
)
@click.option(
    "--tmpdir/--no-tmpdir",
    default=False,
    envvar="INIT_TMPDIR",
    help="Change cwd to a temporary directory before any operations",
)
@click.option(
    "--install-source-dir",
    default=abspath(dirname(__file__)),
    envvar="INSTALL_SOURCE_DIR",
    help="Absolute path to directory where project setup.py lives",
)
@click.option(
    "--log-file", envvar="LOG_FILE", default="-", help="Log file. Use '-' for stdout."
)
@click.option(
    "--log-level", envvar="LOG_LEVEL", default="warning", help="Log output level."
)
@click.option(
    "--profiling/--no-profiling",
    envvar="PROFILING",
    default=False,
    help="Enable profiling and print on exit.",
)
@click.option(
    "--bind", envvar="WSGI_BIND", default="127.0.0.1:8086", help="Interface to bind to"
)
@click.argument("args", nargs=-1)
@click.pass_obj
def run(
    obj,
    bootstrap_replace,
    bootstrap_env,
    bootstrap_py_ver,
    project_replace,
    project_env,
    project_py_ver,
    tmpdir,
    install_source_dir,
    log_file,
    log_level,
    profiling,
    bind,
    args,
):
    """
    Execute a sequential list of commands related to
    standing up an instance of the project services
    including bootstrapping its environment, initializing
    the database, etc.
    """
    obj.bootstrap_env = bootstrap_env
    obj.bootstrap_py_ver = bootstrap_py_ver
    obj.project_env = project_env
    obj.project_py_ver = project_py_ver
    obj.tmpdir = tmpdir
    obj.bootstrap_env_deps = ["click", "pyyaml"]
    obj.cmd_run_base = obj.cmd_base + ["run", "-e", obj.bootstrap_env, "--"]
    obj.proj_ci = obj.cmd_run_base + [
        "python",
        "-m",
        "ci",
        "--edm-bin={}".format(obj.edm_bin),
        "--edm-root={}".format(obj.edm_root),
        "--edm-env={}".format(obj.project_env),
        "--edm-py-version={}".format(obj.project_py_ver),
    ]

    env = os.environ.copy()
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] += ":" + install_source_dir
    else:
        env["PYTHONPATH"] = install_source_dir

    # default command list
    if len(args) == 0:
        args = ["bootstrap", "install-dev", "migrate", "test", "run-app", "webapp"]

    while len(args) > 0:
        cmd = args[0]
        kwargs = {
            "bootstrap_replace": bootstrap_replace,
            "project_replace": project_replace,
            "install_source_dir": install_source_dir,
            "log_file": log_file,
            "log_level": log_level,
            "profiling": profiling,
            "bind": bind,
            "cmd": cmd,
            "args": args[1:],
        }
        if cmd not in _cmd_map:
            cmds, args = default_cmds(obj, **kwargs)
        else:
            cmds, args = _cmd_map[cmd](obj, **kwargs)
        with run_ctx(obj) as cwd:
            do_run_cmds(cmds, env, cwd)


if __name__ == "__main__":
    root(prog_name="init")
