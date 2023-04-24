# txwtf
This project is the atx crypto club web application **txwtf**. It provides the web interface and backend biz logic for members interacting with the system.

Use the `init.sh` script to download and install [EDM](https://www.enthought.com/edm/) for the python runtime and drop you into an initialization environment shell. For example:
> $ bash init.sh -s

If you want to skip the rest of this README and just launch the app from nothing, you can perform the entire init, install and execution of the webapp using the `-r` flag:
> $ bash init.sh -r

## Install

After running the above script, use the `launcher.py` program to actually bootstrap, install the application and associated third party dependencies and initialize the database.
> $ python launcher.py bootstrap install-dev migrate

Note that `install-dev` installs the application in such a way that you can edit the sources in situ and can rely on the entry point `txwtf` running the newest changes regardless of what your current working directory is.

## Testing
You can run the application test suite with the following command:
> $ python launcher.py test

## Running
To run the web application, run the following command to drop into a shell in the application environment:
> $ python launcher.py shell

Then at the next prompt, run the `txwtf` application like the following:
> $ txwtf webapp

This will launch the application, binding to `localhost:8086` by default. You can then load the url `http://localhost:8086` to test it.

### Launcher script
You can combine `launcher.py` commands on the command line. Sometimes it is nice to run testing and a code linter before dropping into the shell so you know what you're working with.
> $ python launcher.py bootstrap install-dev migrate test flake8 shell

Or you can go all the way and launch the webapp after initializing everything instead of dropping into a shell.
> $ python launcher.py bootstrap install-dev migrate test flake8 txwtf webapp

## Deployment

### Defaults
The default location of the installation is under `$HOME/python-runtime/txwtf`. Everything including the EDM installation in use lives under there. To uninstall the application, you can just nuke that directory. The install location is changeable. It should even be relocatable after installation but I haven't tested that. Take a look at the config environment variables in `init.sh` to get an idea how to point to a new location for installation.

The default location of application data is under the source directory in the `instance` directory. There is a sqlite file `db.sqlite` that contains all the site data. In `uploads` you will find user uploaded data. This should also be relocatable as long as you adjust the flask config variable `UPLOADED_ARCHIVE_DEST` accordingly.

### Environment Variable Configuration
The flask app is configured to use prefixed environment variable names. For instance, to change the `UPLOADED_ARCHIVE_DEST` config variable, you can export the environment variable `TXWTF_UPLOADED_ARCHIVE_DEST` before launching the application process. Likewise, `TXWTF_SECRET_KEY` will set the `SECRET_KEY` config variable, and so on.

### Setting Admin Users
To access special system information and change critical settings through the app interface, you can flag a user as an `admin`. Be extremely careful with this as an `admin` user can do anything and is effectively in god mode. But during testing you will likely need at least one admin user to test things, especially if you need to view system logs. To upgrade a user to `admin` status, you can use the following command:
> $ txwtf set-admin --admin --user t@tx.wtf

## Development

### Model Changes
When modifying or adding new models to the application, use flask-migrate commands to add each change to the database migration scripts. From the EDM environment containing the application install, run the following command to add changes to db migration version control with a message for each change.
> $ flask --app txwtf.webapp db migrate -m "change message"

After making changes to models, run the following command to actually upgrade the targed database specified by `TXWTF_SQLALCHEMY_DATABASE_URI`:
> $ flask --app txwtf.webapp db upgrade
