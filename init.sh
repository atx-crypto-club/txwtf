#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
installer_darwin="edm_cli_3.7.0_osx_x86_64.sh"
installer_linux="edm_cli_3.7.0_linux_x86_64.sh"

# default config
archive_url=https://a.tx.wtf
env_root=$HOME/python-runtime
edm_install_prefix=$env_root/edm
env_name=init
bootstrap_env_name="boot"
proj_env_name="prod"
python_version="3.8"

# parse cmd line
init_cmd=""
screen_name=""
cmd_help="[-q env name] [-b bootstrap env] [-p project env] [-r <command>] [-i] [-e <env root>] [-f <install prefix>] [-n] [-d] [-t] [-v <python version>] [-s <screen name>] [-h]"
do_run=0
test_cmd=""
install_cmd="install"
while getopts ':r:ie:f:ndtv:s:hb:p:q:' opt; do
  case "$opt" in
    q)
      env_name=$OPTARG
      ;;

    b)
      bootstrap_env_name=$OPTARG
      ;;

    p)
      proj_env_name=$OPTARG
      ;;

    r)
      init_cmd=$OPTARG
      echo "Running '$SCRIPT_DIR/init.py run $init_cmd' after initialization"
      do_run=1
      ;;

    i)
      echo "Running init shell"
      do_run=2
      ;;

    e)
      env_root=$OPTARG
      edm_install_prefix=$env_root/edm
      ;;

    f)
      edm_install_prefix=$OPTARG
      ;;

    n)
      echo "Nuking" $env_root "and instance dir"
      rm -rf $SCRIPT_DIR/instance
      rm -rf $env_root
      if [ "$do_run" = "0" ]; then
        exit 0
      fi
      ;;

    v)
      python_version=$OPTARG
      echo "Using python version $python_version"
      ;;

    s)
      screen_name=$OPTARG
      screen_cmd="screen -S $screen_name -dm"
      echo "Running in screen $screen_name"
      ;;

    t)
      test_cmd="test"
      echo "Running tests after installation"
      ;;

    d)
      install_cmd="install-dev"
      echo "Installing python package in-place for development"
      ;;

    h)
      echo "Usage: $(basename $0) $cmd_help"
      exit 0
      ;;

    :)
      echo -e "option requires an argument.\nUsage: $(basename $0) $cmd_help"
      exit 1
      ;;

    ?)
      echo -e "Invalid command option.\nUsage: $(basename $0) $cmd_help"
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

# choose edm installer based on the OS running this script
system=`uname`
installer=""
if [ "$system" = "Darwin" ]; then
    installer=$installer_darwin
elif [ "$system" = "Linux" ]; then
    installer=$installer_linux
else
    echo "Error: Unsupported OS"
    exit 1
fi
edm_install_url=$archive_url/$installer
edm_install_file=$env_root/$installer

echo "Environment root: " $env_root
echo "EDM install prefix: " $edm_install_prefix

# init
mkdir -p $env_root
edm_root=$env_root/edm-envs
mkdir -p $edm_install_prefix

# osx edm install
edm_bin=$edm_install_prefix/bin/edm
if [ -f "$edm_install_file" ]; then
    echo "Already downloaded edm installer..."
else
    curl $edm_install_url -o $edm_install_file
fi
if [ -f "$edm_bin" ]; then
    # TODO: we need a better check in case the version is different
    echo "Already installed edm..."
else
    /bin/bash $edm_install_file -b -p $edm_install_prefix -f --force-bundle-install
fi

echo "EDM environment root: " $edm_root
echo "Init environment:" $env_name
echo "Bootstrap environment:" $bootstrap_env_name
echo "Project environment:" $proj_env_name

# setup edm environment
$edm_bin -r $edm_root environments create $env_name --version=$python_version
$edm_bin -r $edm_root install -e $env_name click --yes

init_script="$edm_bin -r $edm_root run -e $env_name -- python $SCRIPT_DIR/init.py --edm-root=$edm_root --edm-bin=$edm_bin run --bootstrap-env=$bootstrap_env_name --bootstrap-py-ver=$python_version --project-env=$proj_env_name --project-py-ver=$python_version"

# install the project in the environment
$init_script bootstrap $install_cmd migrate $test_cmd

# run shell for launcher environment, or actually run the launcher
case "$do_run" in
    0)
        echo "Done."
        exit 0
        ;;

    1)
        echo "Launching command..."
        $screen_cmd $init_script $init_cmd
        exit 0
        ;;

    2)
        echo "Launching init edm shell..."
        $screen_cmd $edm_bin -r $edm_root shell -e $env_name
        exit 0
        ;;
esac
