class TXWTFError(Exception):
    """
    Base class for all exceptions.
    """

    def __init__(self, code: int, msg: str, *args):
        super(Exception, self).__init__(*([code, msg] + list(args)))
        self._code = code
        self._msg = msg


class PasswordError(TXWTFError):
    pass


class RegistrationError(TXWTFError):
    pass


class LoginError(TXWTFError):
    pass


class LogoutError(TXWTFError):
    pass


class SettingsError(TXWTFError):
    pass


class AuthorizedSessionError(TXWTFError):
    pass


class UserError(TXWTFError):
    pass
