# -*- coding: utf-8 -*-
# author: PhanterJR<junior.conex@gmail.com>
# license: MIT

from flask import Flask
from flask_cors import CORS
from flask_mail import Mail
from flask_restful import Api
import os
import configparser
__author__ = "PhanterJR<junior.conex@gmail.com>"
__version__ = "0.1.1"
__project_folder__ = os.path.dirname(os.path.abspath(__file__))
__project__ = os.path.basename(__project_folder__)
__base_name__ = os.path.basename(__project_folder__)


app = Flask(__name__)
api = Api(app)
mail = Mail(app)

config = configparser.ConfigParser()
config.read(os.path.join(__project_folder__, 'config.ini'))

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

# controllers
from .controllers import rest
from .controllers import index
from .controllers import static_versioned

cors = CORS(app, resources={r"/api/*": {"origins": "*"}, r"/echo/*": {"origins": "*"}})
