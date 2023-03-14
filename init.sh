#!/bin/bash

# config
archive_url=https://tx.wtf/a
env_root=$HOME/python-runtime/txwtf
env_name=txwtf-init
python_version="3.8"

# parse cmd line
do_run=0
while getopts ':rsih' opt; do
  case "$opt" in
    r)
      echo "Running launcher.py after initialization"
      do_run=1
      ;;

    s)
      echo "Running launcher.py shell after initialization"
      do_run=2
      ;;

    i)
      echo "Running init shell"
      do_run=3
      ;;

    h)
      echo "Usage: $(basename $0) [-r] [-s] [-i]"
      exit 0
      ;;

    :)
      echo -e "option requires an argument.\nUsage: $(basename $0) [-r] [-s] [-i]"
      exit 1
      ;;

    ?)
      echo -e "Invalid command option.\nUsage: $(basename $0) [-r] [-s] [-i]"
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

# choose edm installer
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
env_prefix_src=$env_prefix/src

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
$edm_bin -r $edm_root run -e $env_name -- python launcher.py bootstrap install-dev migrate test

# run shell for launcher environment, or actually run the launcher
case "$do_run" in
    0)
        echo "Done."
        exit 0
        ;;
    1)
        echo "Launching txwtf webapp..."
        $edm_bin -r $edm_root run -e $env_name -- python launcher.py txwtf webapp
        exit 0
        ;;

    2)
        echo "Launching txwtf edm environment shell..."
        $edm_bin -r $edm_root run -e $env_name -- python launcher.py shell
        exit 0
        ;;

    3)
        echo "Launching init edm shell..."
        $edm_bin -r $edm_root shell -e $env_name
        exit 0
        ;;
esac
