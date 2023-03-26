from os.path import join
import secrets
import tempfile

from flask import Flask, render_template, send_from_directory

from flask_cors import CORS

from flask_login import LoginManager

from flask_matomo import Matomo

from flask_migrate import Migrate

from flask_sqlalchemy import SQLAlchemy

from flask_uploads import ALL, UploadSet, configure_uploads

from markdownify import markdownify


# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()
migrate = Migrate()
upload_archive = UploadSet("archive", ALL)


def create_app(config_filename=None):
    app = Flask(__name__)
    CORS(app)

    app.config["SECRET_KEY"] = str(secrets.SystemRandom().getrandbits(128))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    # TODO: by default, lets store the upload archive under the instance dir
    # next to where the db.sqlite file ends up. 
    app.config["UPLOADED_ARCHIVE_DEST"] = join(
        tempfile.gettempdir(), "txwtf", "uploads")
    app.config['MAX_CONTENT_LENGTH'] = 128 * 1024 * 1024  # 128MB max upload size

    if config_filename is not None:
        app.config.from_pyfile(config_filename)
    app.config.from_prefixed_env(prefix="TXWTF")

    configure_uploads(app, upload_archive)
    db.init_app(app)
    migrate.init_app(app, db)

    # set up matomo stats if available in config
    if "MATOMO_URL" in app.config and \
        "MATOMO_SITE_ID" in app.config and \
        "MATOMO_TOKEN_AUTH" in app.config:
        Matomo(
            app,
            matomo_url=app.config['MATOMO_URL'],
            id_site=app.config['MATOMO_SITE_ID'],
            token_auth=app.config['MATOMO_TOKEN_AUTH'])

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
    from .main import render_posts, render_post_message
    app.jinja_env.globals.update(
        render_posts=render_posts,
        render_post_message=render_post_message)

    return app
