import secrets

from flask import Flask

from flask_cors import CORS

from flask_login import LoginManager

from flask_migrate import Migrate

from flask_sqlalchemy import SQLAlchemy

from flask_uploads import IMAGES, UploadSet, configure_uploads


# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()
migrate = Migrate()
avatars = UploadSet("avatars", IMAGES)


def create_app(config_filename=None):
    app = Flask(__name__)
    CORS(app)

    app.config["SECRET_KEY"] = str(secrets.SystemRandom().getrandbits(128))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config["UPLOADED_AVATARS_DEST"] = "uploads/avatars"

    if config_filename is not None:
        app.config.from_pyfile(config_filename)
    app.config.from_prefixed_env(prefix="TXWTF")

    configure_uploads(app, avatars)
    db.init_app(app)
    migrate.init_app(app, db)

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

    return app
