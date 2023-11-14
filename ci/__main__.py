import os
from os.path import abspath, expanduser, join, dirname
import subprocess
import sys
from threading import Thread

import click
import yaml


# TODO: add logger
# TODO: generalize ci for all group projects to use
# TODO: add tests for jobs execution


def _get_default_environment_root():
    return os.environ.get(
        "ENV_ROOT", join(
            expanduser("~"), "python-runtime"))


def _get_default_edm_install_prefix(
        env_root=_get_default_environment_root()):
    return os.environ.get(
        "EDM_INSTALL_PREFIX",
        join(env_root, "edm"))


def _get_default_edm_root(
        env_root=_get_default_environment_root()):
    if "EDM_VIRTUAL_ENV" in os.environ:
        root = abspath(
            join(os.environ["EDM_VIRTUAL_ENV"], "..", ".."))
    else:
        root = os.environ.get(
            "EDM_ROOT",
            join(env_root, "edm-envs"))
    return root


def _get_default_edm_bin():
    return os.environ.get(
        "EDM_BIN", join(_get_default_edm_install_prefix(), "bin", "edm"))


@click.group(context_settings={"help_option_names": ['-h', '--help']})
@click.option(
    "--edm-root", default=_get_default_edm_root(),
    help="EDM root")
@click.option(
    "--edm-env", default="prod",
    help="project environment to use")
@click.option(
    "--edm-py-version", default="3.8",
    help="Version of python to use")
@click.option(
    "--edm-bin", default=_get_default_edm_bin(),
    help="EDM binary to use")
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


@root.command()
@click.option(
    "--replace/--no-replace", default=False,
    help="Force replace environment?"
)
@click.pass_obj
def bootstrap(obj, replace):
    """
    create project environment for running the application
    """
    if not os.path.isdir(obj.edm_root):
        os.mkdir(obj.edm_root)
    args = []
    if replace:
        args = ["--force"]
    try:
        subprocess.check_call(
            [obj.edm_bin, "-r", obj.edm_root, "envs",
             "create", obj.edm_env,
             "--version={}".format(obj.edm_py_version)] + args)
    except subprocess.CalledProcessError as e:
        print(e)  # TODO: error logger


source_dir_option = click.option(
    "--source-dir", default=join(abspath(dirname(__file__)), ".."),
    help="Directory where setup.py lives")


def install_deps(obj, source_dir):
    ENV_DEPS = ["click", "flake8", "pyyaml", "wheel", "requests", "lxml", "sphinx"]
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
    Install application in the target environment in dev mode (editable)
    """
    install_deps(obj, source_dir)
    install_application(obj, source_dir, True)


@root.command()
@source_dir_option
@click.pass_obj
def install(obj, source_dir):
    """
    Install application in the target environment
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
            "flask", "--app", "txwtf.webapp", "db", "upgrade"],
        cwd=join(dirname(__file__), ".."))


@root.command()
@click.option(
    "--root-cmd", envvar="ROOT_CMD", default="txwtf",
    help="Application root command.")
@click.option(
    "--log-file", envvar="LOG_FILE", default="-",
    help="Log file. Use '-' for stdout.")
@click.option(
    "--log-level", envvar="LOG_LEVEL",
    default="WARNING", help="Log output level.")
@click.pass_obj
def test(obj, root_cmd, log_file, log_level):
    """
    Run application tests in project environment
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root, "run", "-e", obj.edm_env, "--"]
    subprocess.check_call(
        edm_run_cmd + [
            root_cmd,
            "--log-file={}".format(log_file),
            "--log-level={}".format(log_level)] + ["test"])


@root.command()
@click.option(
    "--root-cmd", envvar="ROOT_CMD", default="txwtf",
    help="Application root command.")
@click.pass_obj
def flake8(obj, root_cmd):
    """
    Run flake8 in application project environment
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root, "run", "-e", obj.edm_env, "--"]
    subprocess.check_call(
        edm_run_cmd + [
            root_cmd, "flake8"],
        cwd=join(dirname(__file__), ".."))


@root.command()
@click.argument('cmd_args', nargs=-1)
@click.pass_obj
def run(obj, cmd_args):
    """
    Run command in project environment
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root,
        "run", "-e", obj.edm_env, "--"] + list(cmd_args)
    subprocess.check_call(edm_run_cmd)


@root.command()
@click.option(
    "--root-cmd", envvar="ROOT_CMD", default="txwtf",
    help="Application root command.")
@click.option(
    "--log-file", envvar="LOG_FILE", default="-",
    help="Log file. Use '-' for stdout.")
@click.option(
    "--log-level", envvar="LOG_LEVEL",
    default="WARNING", help="Log output level.")
@click.option(
    "--profiling/--no-profiling", 
    envvar="PROFILING", default=False,
    help="Enable profiling and print on exit.")
@click.argument('cmd_args', nargs=-1)
@click.pass_obj
def run_app(obj, root_cmd, log_file, log_level, profiling, cmd_args):
    """
    Run application in project environment
    """
    run_cmd = [
        obj.edm_bin, "-r", obj.edm_root, "run",
        "-e", obj.edm_env, "--"]
    run_cmd.append(root_cmd)
    run_cmd.append("--log-file={}".format(log_file))
    run_cmd.append("--log-level={}".format(log_level))
    if profiling:
        run_cmd.append("--profiling")
    subprocess.check_call(run_cmd + list(cmd_args))


@root.command()
@click.option(
    "--app", envvar="WSGI_APP", default="txwtf.webapp",
    help="The webapp for gunicorn to launch")
@click.option(
    "--access-logfile", envvar="WSGI_ACCESS_LOGFILE", default="-",
    help="Log file. Use '-' for stdout.")
@click.option(
    "--access-logformat", envvar="WSGI_ACCESS_LOGFORMAT",
    default='%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"',
    help="Log format for access log")
@click.option(
    "--error-logfile", envvar="WSGI_ERROR_LOGFILE", default="-",
    help="Error log file. Use '-' for stdout.")
@click.option(
    "--log-level", envvar="WSGI_LOG_LEVEL", default="info",
    help="Error log level.")
@click.option(
    "--bind", envvar="WSGI_BIND", default="127.0.0.1:8086",
    help="Interface to bind to")
@click.option(
    "--workers", envvar="WSGI_WORKERS", default=2,
    help="Number of worker processes to handle requests.")
@click.pass_obj
def run_wsgi(
    obj, app, access_logfile, access_logformat, error_logfile,
    log_level, bind, workers):
    """
    Run gunicorn wsgi for the webapp in project environment
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root, "run", "-e", obj.edm_env, "--"]
    subprocess.check_call(
        edm_run_cmd + [
            "gunicorn",
            "--access-logfile", access_logfile,
            "--access-logformat", access_logformat,
            "--error-logfile", error_logfile,
            "--log-level", log_level,
            "--bind", bind,
            "--workers", str(workers),
            "{}:create_app()".format(app)])


@root.command()
@click.pass_obj
def shell(obj):
    """
    Conveniently drop into the project environment.
    """
    edm_run_cmd = [
        obj.edm_bin, "-r", obj.edm_root, "shell", "-e", obj.edm_env]
    subprocess.check_call(edm_run_cmd)


def fmt_arg(arg, val):
    """
    Returns an argument string with quotes for the argument
    value if it has whitespace. Or if the value is boolean,
    return an argument string as a click toggle.
    """
    if isinstance(val, bool):
        if val:
            fmt_str = "--{}".format(arg)
        else:
            fmt_str = "--no-{}".format(arg)
        return fmt_str

    fmt_str = "--{}={}"
    if " " in str(val):
        fmt_str = "--{}='{}'"
    return fmt_str.format(arg, val)


def get_job_cmds(jobs_data, job_names=[], root_cmd="txwtf"):
    """
    Given a jobs_data dict and a list of job_names,
    return a list of command line invocations for
    each job. If job_names is empty, return a list
    of command line invocations for all jobs in the
    dict.
    """
    if len(job_names) == 0:
        job_names = jobs_data.keys()

    cmds = []
    for job_name in job_names:
        if job_name not in jobs_data:
            print("Error: job {} not in jobs data".format(job_name))
            continue
        job = jobs_data[job_name]
        root_args = job["root-args"]
        command = job["command"]
        args = job["args"]
        cmd = [root_cmd]
        for arg, value in root_args.items():
            if isinstance(value, list):
                for val in value:
                    cmd.append(fmt_arg(arg, val))
            else:
                cmd.append(fmt_arg(arg, value))
        cmd.append(command)
        for arg, value in args.items():
            if isinstance(value, list):
                for val in value:
                    cmd.append(fmt_arg(arg, val))
            else:
                cmd.append(fmt_arg(arg, value))
        cmds.append(cmd)

    return cmds


@root.command()
@click.option(
    '--keepalive/--no-keepalive', '-k', default=False,
    envvar="KEEPALIVE",
    help="Rerun process if it dies")
@click.option(
    '--root-cmd', '-c', default="txwtf",
    envvar="ROOT_CMD",
    help="Application jobs root command")
@click.argument('jobs_args', nargs=-1)
@click.pass_obj
def jobs(obj, keepalive, root_cmd, jobs_args):
    """
    Execute jobs as described in a yaml file.
    """
    # if jobs_args length is zero, fail.
    # if jobs_args length is 1, interpret the argument as a jobs file
    # and execute all jobs.
    # if jobs_args length is >1, interpret the first argument as a jobs file
    # then interpret every arg after that as a job name and execute that.
    if len(jobs_args) == 0:
        print("Error: jobs command requires arguments")
        return

    jobs_file = jobs_args[0]
    with open(jobs_file, 'r') as f:
        jobs_data = yaml.safe_load(f)

    if "jobs" not in jobs_data:
        print("Error: invalid jobs file")
        return

    # TODO: reload jobs before restarting jobs for keepalive
    cmds = get_job_cmds(jobs_data["jobs"], jobs_args[1:], root_cmd)

    # job execution
    def _proc_mon(obj, cmd, keepalive):
        edm_run_cmd = [
            obj.edm_bin, "-r", obj.edm_root, "run", "-e", obj.edm_env, "--"]
        while True:
            full_cmd = edm_run_cmd + cmd
            p = subprocess.Popen(
                full_cmd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            print("Running pid {} (keepalive: {}): {}".format(
                p.pid, keepalive, full_cmd))
            while True:
                try:
                    outs, errs = p.communicate(timeout=1)
                    # TODO: output to logger / consider forwarding to redis channels
                    if outs is not None:
                        print(outs.decode(), end="")
                    if errs is not None:
                        print(errs.decode(), file=sys.stderr, end="")
                    retval = p.poll()
                    if retval is not None:
                        print("Process pid {} returned {}".format(p.pid, retval))
                        break
                except subprocess.TimeoutExpired as e:
                    pass
            if not keepalive:
                break

    # init the jobs threads
    job_threads = []
    for cmd in cmds:
        new_thread = Thread(target=_proc_mon,args=(obj, cmd, keepalive))
        job_threads.append(new_thread)

    # start 'em
    for th in job_threads:
        th.start()

    # wait till thread monitoring the job processes finish
    for th in job_threads:
        th.join()


if __name__ == '__main__':
    root(prog_name="ci")
