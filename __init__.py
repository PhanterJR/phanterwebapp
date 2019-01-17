# -*- coding: utf-8 -*-
# author: PhanterJR<junior.conex@gmail.com>
# license: MIT

from flask import Flask, request
from flask_cors import CORS
from flask_mail import Mail
from functools import wraps
from flask_restful import Api
import os
import configparser
__author__ = "PhanterJR<junior.conex@gmail.com>"
__version__ = "0.0.1"
__project_folder__ = os.path.dirname(os.path.abspath(__file__))
__project__ = os.path.basename(__project_folder__)


app = Flask(__name__)
api = Api(app)
mail = Mail(app)

config = configparser.ConfigParser()
config.read('config.ini')

app.config['MAIL_SERVER'] = config['EMAIL']['mail_server']
app.config['MAIL_PORT'] = int(config['EMAIL']['mail_port'])
app.config['MAIL_USE_TLS'] = config['EMAIL'].getboolean('mail_use_tls')
app.config['MAIL_USE_SSL'] = config['EMAIL'].getboolean('mail_user_ssl')
app.config['MAIL_USERNAME'] = config['EMAIL']['mail_username']
app.config['MAIL_DEFAULT_SENDER'] = config['EMAIL']['mail_username']
app.config['MAIL_PASSWORD'] = config['EMAIL']['mail_password']
app.config['SECRET_KEY_USERS'] = config['APP']['app_secret_key']
app.config['DEFAULT_TIME_TOKEN_EXPIRES'] = int(config['APP']['app_default_time_token_expires'])

app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, "uploads")


class CustomReturnToInvalidToken():
    def __init__ (self, function_to_return):
        self.function_to_return=function_to_return

    def requires_valid_token(self, f):
        @wraps(f)
        def f_intern(*args, **kargs):
            from conexaodidata.models.auth_user import User
            token = request.headers.get('autorization')
            id_user = request.headers.get('autorization_user')
            try:
                id_user=int(id_user)
            except ValueError:
                id_user=0
            usuario = User(id_user=id_user)
            if usuario:
                result_check = usuario.check_token(token)
                if result_check:
                    return f(*args, **kargs)
            return self.function_to_return(*args)
        return f_intern

#controllers
from .controllers import rest
from .controllers import index
from .controllers import static_versioned

cors = CORS(app, resources={r"/api/*": {"origins": "*"}, r"/echo/*": {"origins": "*"}})