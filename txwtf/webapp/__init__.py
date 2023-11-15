import logging
from hashlib import sha256
import secrets
import tempfile
from os.path import abspath, dirname, join

from flask import Flask, render_template

from flask_cors import CORS

from flask_login import LoginManager

#from flask_matomo import Matomo

from flask_migrate import Migrate

from flask_sqlalchemy import SQLAlchemy

from flask_uploads import ALL, UploadSet, configure_uploads

from markdownify import markdownify


# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()
migrate = Migrate()
upload_archive = UploadSet("archive", ALL)
logger = logging.getLogger(__name__)


def remote_addr(request):
    """
    Get the client address through the proxy if it exists.
    """
    return request.headers.get(
        'X-Forwarded-For', request.headers.get(
            'X-Real-IP', request.remote_addr))


def gen_secret():
    return sha256(
        str(secrets.SystemRandom().getrandbits(128)).encode()).hexdigest()


def create_app(config_filename=None):
    app = Flask(__name__)
    CORS(app)

    # app.config["SECRET_KEY"] = str(secrets.SystemRandom().getrandbits(128))
    app.config["SECRET_KEY"] = "clownworld"
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    instance_dir = abspath(join(dirname(__file__), "..", "..", "instance"))
    app.config["UPLOADED_ARCHIVE_DEST"] = join(instance_dir, "uploads")

    # Default 128MB max upload size
    app.config['MAX_CONTENT_LENGTH'] = 128 * 1024 * 1024

    if config_filename is not None:
        app.config.from_pyfile(config_filename)
    app.config.from_prefixed_env(prefix="TXWTF")

    logger.info("upload dir {}".format(
        app.config["UPLOADED_ARCHIVE_DEST"]))
    logger.info("database uri: {}".format(
        app.config["SQLALCHEMY_DATABASE_URI"]))

    configure_uploads(app, upload_archive)
    db.init_app(app)
    migrate.init_app(app, db)

    # set up matomo stats if available in config
    # matomo_config_keys = [
    #     "MATOMO_URL", "MATOMO_SITE_ID", "MATOMO_TOKEN_AUTH"]
    # if all([key in app.config for key in matomo_config_keys]):
    #     Matomo(
    #         app, matomo_url=app.config['MATOMO_URL'],
    #         id_site=app.config['MATOMO_SITE_ID'],
    #         token_auth=app.config['MATOMO_TOKEN_AUTH'])

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table,
        # use it in the query for the user
        return User.query.get(int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized_handler():
        return render_template('unauthorized.html'), 401

    def handle_bad_request(e):
        return render_template('error.html', error_msg="Bad request!!"), 400
    app.register_error_handler(400, handle_bad_request)

    def handle_404(e):
        return render_template('error.html', error_msg="Not found!"), 404
    app.register_error_handler(404, handle_404)

    # add useful functions to jinja2 rendering
    app.jinja_env.globals.update(markdownify=markdownify)
    from .main import (
        render_post, render_posts, render_post_message, render_user_card,
        collect_post_ids)
    app.jinja_env.globals.update(
        render_post=render_post,
        render_posts=render_posts,
        render_post_message=render_post_message,
        render_user_card=render_user_card,
        num_posts=lambda posts: len(collect_post_ids(posts)))

    return app
