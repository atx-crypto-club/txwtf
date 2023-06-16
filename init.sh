#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# config
archive_url=https://a.tx.wtf
env_root=$HOME/python-runtime/txwtf
env_name=txwtf-init
python_version="3.8"

# parse cmd line
init_cmd=""
screen_name=""
cmd_help="[-r <command>] [-i] [-e <env root>] [-d] [-v <python version>] [-s] [-h]"
do_run=0
while getopts ':r:ie:dv:s:h' opt; do
  case "$opt" in
    r)
      init_cmd=$OPTARG
      echo "Running 'init.py run $init_cmd' after initialization"
      do_run=1
      ;;

    i)
      echo "Running init shell"
      do_run=2
      ;;

    e)
      env_root=$OPTARG
      echo "Environment root is" $env_root
      ;;

    d)
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
    installer="edm_cli_3.5.0_osx_x86_64.sh"
elif [ "$system" = "Linux" ]; then
    installer="edm_cli_3.5.0_linux_x86_64.sh"
else
    echo "Error: Unsupported OS"
    exit 1
fi
edm_install_url=$archive_url/$installer
edm_install_file=$env_root/$installer

# init
mkdir -p $env_root
edm_install_prefix=$env_root/edm
edm_root=$env_root/edm-envs
env_prefix=$edm_root/envs/$env_name

# osx edm install
edm_bin=$edm_install_prefix/bin/edm
if [ -f "$edm_install_file" ]; then
    echo "Already downloaded edm installer..."
else
    curl $edm_install_url -o $edm_install_file
fi
if [ -f "$edm_bin" ]; then
    echo "Already installed edm..."
else
    /bin/bash $edm_install_file -b -p $edm_install_prefix -f --force-bundle-install
fi

# setup edm environment
$edm_bin -r $edm_root environments create $env_name --version $python_version
$edm_bin -r $edm_root install -e $env_name click pyyaml --yes
# TODO: add flag to toggle install-dev vs install
$edm_bin -r $edm_root run -e $env_name -- python init.py --edm-root=$edm_root --edm-bin=$edm_bin --bootstrap-py-ver=$python_version --project-py-ver=$python_version run bootstrap install-dev migrate test

# run shell for launcher environment, or actually run the launcher
case "$do_run" in
    0)
        echo "Done."
        exit 0
        ;;

    1)
        echo "Launching txwtf command..."
        $screen_cmd $edm_bin -r $edm_root run -e $env_name -- python init.py --edm-root=$edm_root --edm-bin=$edm_bin run $init_cmd
        exit 0
        ;;

    2)
        echo "Launching init edm shell..."
        $screen_cmd $edm_bin -r $edm_root shell -e $env_name
        exit 0
        ;;
esac
