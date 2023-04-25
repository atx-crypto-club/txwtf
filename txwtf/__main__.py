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
    "--log-level", default="INFO",
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
@click.option(
    '--config', '-c', default=None,
    help="Flask configuration file")
@click.pass_obj
def webapp(obj, host, port, threaded, debug, config):
    """
    Run the flask app
    """
    import txwtf.webapp
    app = txwtf.webapp.create_app(config_filename=config)
    app.run(host=host, port=port, threaded=threaded, debug=debug)


@root.command()
@click.option(
    '--config', '-c', default=None,
    help="Flask configuration file")
@click.option(
    '--admin/--no-admin', default=False,
    help="admin flag setting")
@click.option(
    '--user', '-u',
    help="User to apply flag setting to")
@click.pass_obj
def set_admin(obj, config, admin, user):
    """
    Toggle admin for specified user.
    """
    from getpass import getuser
    from datetime import datetime
    import txwtf.webapp
    from txwtf.webapp import db
    from txwtf.webapp.models import User, SystemLog
    app = txwtf.webapp.create_app(config_filename=config)
    with app.app_context():
        user_obj = db.session.query(User).filter(
            User.username == user).first()
        if user_obj is None:
            logger.error("Unknown user {}".format(user))
            return
        if user_obj.is_admin == admin:
            logger.warning(
                "User {} is_admin flag already set to {}".format(
                    user, admin))
            return
        user_obj.is_admin = admin
        log_desc = "setting user {} is_admin flag to {}".format(
            user, admin)
        new_log = SystemLog(
            event_code=31337,  # default for now
            event_time=datetime.now(),
            event_desc=log_desc,
            referrer="",
            user_agent="{}'s command line".format(getuser()),
            remote_addr="localhost",
            endpoint="txwtf.set_admin")
        db.session.add(new_log)
        db.session.commit()
        logger.info(log_desc)


@root.command()
@click.option(
    '--config', '-c', default=None,
    help="Flask configuration file")
@click.pass_obj
def list_users(obj, config):
    """
    Print a list of users in the system.
    """
    from tabulate import tabulate
    import txwtf.webapp
    from txwtf.webapp import db
    from txwtf.webapp.models import User
    app = txwtf.webapp.create_app(config_filename=config)
    table = []
    with app.app_context():
        users = db.session.query(User).order_by(
            User.modified_time.desc()).all()
        for user in users:
            row = [
                user.id, user.username, user.name, user.email,
                str(user.email_verified),
                str(user.is_admin),
                user.created_time.ctime(),
                user.modified_time.ctime()]
            table.append(row)
    print("{} users".format(len(table)))
    print(tabulate(table, headers=[
        'ID', 'Username', 'Name', 'Email', 'email_verified', 'is_admin', 'Created',
        'Last Modified']))


@root.command()
@click.option(
    '--config', '-c', default=None,
    help="Flask configuration file")
@click.option(
    '--verify/--no-verify', default=False,
    help="email verification flag setting")
@click.option(
    '--user', '-u',
    help="User to apply flag setting to")
@click.pass_obj
def verify_email(obj, config, verify, user):
    """
    Toggle email verification for the specified user.
    """
    from getpass import getuser
    from datetime import datetime
    import txwtf.webapp
    from txwtf.webapp import db
    from txwtf.webapp.models import User, SystemLog
    app = txwtf.webapp.create_app(config_filename=config)
    with app.app_context():
        user_obj = db.session.query(User).filter(
            User.email == user).first()
        if user_obj is None:
            logger.error("Unknown user {}".format(user))
            return
        if user_obj.email_verified == verify:
            logger.warning(
                "User {} email_verified flag already set to {}".format(
                    user, verify))
            return
        user_obj.email_verified = verify
        log_desc = "setting user {} email_verified flag to {}".format(
            user, verify)
        new_log = SystemLog(
            event_code=31337,  # default for now
            event_time=datetime.now(),
            event_desc=log_desc,
            referrer="",
            user_agent="{}'s command line".format(getuser()),
            remote_addr="localhost",
            endpoint="txwtf.verify_email")
        db.session.add(new_log)
        db.session.commit()
        logger.info(log_desc)


@root.command()
@click.option(
    '--config', '-c', default=None,
    help="Flask configuration file")
@click.option(
    '--hashtag', '-h', default=None,
    help="Only show posts with this hashtag")
@click.pass_obj
def list_posts(obj, config, hashtag):
    """
    Print a list of posts in the system.
    """
    from tabulate import tabulate
    import txwtf.webapp
    from txwtf.webapp import db
    from txwtf.webapp.models import PostedMessage, HashTag, Tag
    app = txwtf.webapp.create_app(config_filename=config)
    table = []
    with app.app_context():
        if hashtag is not None:
            dbtag = db.session.query(Tag).filter(Tag.name == hashtag).first()
            if dbtag is None:
                logger.error("No such hashtag {}".format(hashtag))
                return
            hashtags = db.session.query(HashTag).filter(
                HashTag.tag_id == dbtag.id).all()
            posts = []
            for hashtag in hashtags:
                post = db.session.query(PostedMessage).filter(
                    PostedMessage.id == hashtag.post_id).first()
                posts.append(post)
        else:
            posts = db.session.query(PostedMessage).order_by(
                PostedMessage.post_time.desc()).all()
        for post in posts:
            row = [
                post.id, str(post.reply_to), str(post.repost_id),
                str(post.deleted), post.post_time.ctime(),
                post.post_content]
            table.append(row)
    print("{} posts".format(len(posts)))
    print(tabulate(table, headers=[
        'ID', 'reply_to', 'repost_id', 'deleted', 'post_time', 'content']))


@root.command()
@click.option(
    '--config', '-c', default=None,
    help="Flask configuration file")
@click.pass_obj
def list_tags(obj, config):
    """
    Print a list of tags known by the system.
    """
    from tabulate import tabulate
    import txwtf.webapp
    from txwtf.webapp import db
    from txwtf.webapp.models import Tag, HashTag
    app = txwtf.webapp.create_app(config_filename=config)
    table = []
    with app.app_context():
        tags = db.session.query(Tag).order_by(
            Tag.last_used_time.desc()).all()
        for tag in tags:
            num_posts = len(db.session.query(HashTag).filter(
                HashTag.tag_id == tag.id).all())
            row = [
                tag.id, tag.name, tag.created_time.ctime(),
                tag.modified_time.ctime(),
                tag.last_used_time.ctime(),
                tag.user_id, num_posts,
                tag.tag_description]
            table.append(row)
    print("{} tags".format(len(tags)))
    print(tabulate(table, headers=[
        'ID', 'name', 'created time', 'modified time',
        'last used', 'user_id', 'num posts', 'description']))


if __name__ == '__main__':
    root(prog_name="txwtf")
