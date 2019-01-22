# -*- coding: utf-8 -*-
from pydal import DAL, Field
from .. import app, mail
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from itsdangerous import TimedJSONWebSignatureSerializer as Serialize
from itsdangerous import BadSignature, SignatureExpired
from flask_mail import Message
from flask import request


database_path = os.path.join(app.root_path, 'database')
db = DAL('sqlite://storage.sqlite',
         pool_size=10,
         folder=database_path,
         migrate_enabled=True,
         check_reserved=['all'])

db.define_table(
    'auth_user',
    Field('first_name', 'string', notnull=True),
    Field('last_name', 'string', notnull=True),
    Field('email', 'string', notnull=True, unique=True),
    Field('remember_me', 'boolean', default=False),
    Field('password_hash', 'string', notnull=True),
    Field('attempts_to_login', 'integer', default=0),
    Field('datetime_next_attempt_to_login', 'datetime'),
    Field('temporary_password', 'text'),
    Field('temporary_password_hash', 'text'),
    Field('temporary_password_expire', 'datetime'),
    Field('activate_hash', 'string', unique=True),
    Field('activate_code', 'integer', default=0),
    Field('attempts_to_activate', 'integer'),
    Field('activate_date_expire', 'datetime'),
    Field('retrieve_hash', 'string', unique=True),
    Field('permit_double_login', 'boolean', default=True),
    Field('rest_key', 'string', unique=True),
    Field('rest_token', 'string', unique=True),
    Field('rest_date', 'datetime'),
    Field('rest_expire', 'integer'),
    Field('activated', 'boolean', default=False, notnull=True),
)

db.define_table(
    'auth_group',
    Field('role', 'string'),
    Field('description', 'text')
)

db.define_table(
    'auth_membership',
    Field('auth_user', 'reference auth_user'),
    Field('auth_group', 'reference auth_group')
)

db.define_table(
    'auth_activity',
    Field('auth_user', 'reference auth_user'),
    Field('request', 'text'),
    Field('activity', 'string'),
    Field('date_activity', 'datetime', default=datetime.now())
)

db.define_table(
    'csrf',
    Field('token', 'text'),
    Field('proposito', 'string'),
    Field('date_created', 'datetime')
)

db.define_table(
    'email_user_history',
    Field('auth_user', 'reference auth_user'),
    Field('email', 'string'),
    Field('data_change', 'datetime')
)

db.define_table(
    'error_log',
    Field('description', 'text'),
    Field('request', 'text'),
    Field('date_operations', 'datetime', default=datetime.now())
)
if db(db.auth_group).isempty():
    db._adapter.reconnect()
    db.auth_group.insert(role="root", description="Administrator of application (Developer)")
    db.auth_group.insert(role="administrator", description="Super user of site")
    db.commit()


class User(object):
    db = db

    def __init__(self, id_user=None, email=None, token=None):
        super(User, self).__init__()
        self.db._adapter.reconnect()
        self._field = "id"
        self._value_field = None
        self._user = None
        self._roles = []
        if id_user:
            self._value_field = id_user
        elif email:
            self._field = "email"
            self._value_field = email
        elif token:
            self._field = "rest_token"
            self._value_field = token
        self._user = db(db['auth_user'][self._field] == self._value_field).select().first()

    def commit(self):
        return self.db.commit()

    def rollback(self):
        return self.db.rollback()

    @property
    def id(self):
        self._id = None
        if self.data_user:
            self._id = self.data_user.id
        return self._id

    @property
    def first_name(self):
        self._first_name = None
        if self.data_user:
            self._first_name = self.data_user.first_name
        return self._first_name

    @first_name.setter
    def first_name(self, value):
        if self.data_user:
            self.data_user.update_record(first_name=value)
            self._first_name = value

    @property
    def last_name(self):
        self._last_name = None
        if self.data_user:
            self._last_name = self.data_user.last_name
        return self._last_name

    @last_name.setter
    def last_name(self, value):
        if self.data_user:
            self.data_user.update_record(last_name=value)
            self._last_name = value

    @property
    def email(self):
        self._email = None
        if self.data_user:
            self._email = self.data_user.email
        return self._email

    @email.setter
    def email(self, value):
        if self.data_user:
            if self.email:
                self.db.email_user_history.insert(
                    auth_user=self.id,
                    email=self.email,
                    data_change=datetime.now()
                )
                self.activated = False
            self.data_user.update_record(email=value)

            self._email = value

    @property
    def remember_me(self):
        self._remember_me = None
        if self.data_user:
            self._remember_me = self.data_user.remember_me
        return self._remember_me

    @remember_me.setter
    def remember_me(self, value):
        if self.data_user:
            self.data_user.update_record(remember_me=value)
            self._remember_me = value

    @property
    def password_hash(self):
        self._password_hash = None
        if self.data_user:
            self._password_hash = self.data_user.password_hash
        return self._password_hash

    @password_hash.setter
    def password_hash(self, value):
        if self.data_user:
            self.data_user.update_record(password_hash=value)
            self._password_hash = value

    @property
    def attempts_to_login(self):
        self._attempts_to_login = None
        if self.data_user:
            self._attempts_to_login = self.data_user.attempts_to_login
        return self._attempts_to_login

    @attempts_to_login.setter
    def attempts_to_login(self, value):
        if self.data_user:
            self.data_user.update_record(attempts_to_login=value)
            self._attempts_to_login = value

    @property
    def datetime_next_attempt_to_login(self):
        self._datetime_next_attempt_to_login = None
        if self.data_user:
            self._datetime_next_attempt_to_login = self.data_user.datetime_next_attempt_to_login
        return self._datetime_next_attempt_to_login

    @datetime_next_attempt_to_login.setter
    def datetime_next_attempt_to_login(self, value):
        if self.data_user:
            self.data_user.update_record(datetime_next_attempt_to_login=value)
            self._datetime_next_attempt_to_login = value

    @property
    def temporary_password(self):
        self._temporary_password = None
        if self.data_user:
            self._temporary_password = self.data_user.temporary_password
        return self._temporary_password

    @temporary_password.deleter
    def temporary_password(self):
        self.temporary_password = None

    @temporary_password.setter
    def temporary_password(self, value):
        t = Serialize(app.config['SECRET_KEY_USERS'], timedelta(minutes=10).total_seconds())
        token = t.dumps(
            {'id_user': self.id, 'email': self.email, 'temporary_password': value}
        )
        if self.data_user:
            self.data_user.update_record(temporary_password=token.decode("utf-8"))
            self._temporary_password = token.decode("utf-8")

    @property
    def temporary_password_hash(self):
        self._temporary_password_hash = None
        if self.data_user:
            self._temporary_password_hash = self.data_user.temporary_password_hash
        return self._temporary_password_hash

    @temporary_password_hash.deleter
    def temporary_password_hash(self):
        self.temporary_password_hash = None

    @temporary_password_hash.setter
    def temporary_password_hash(self, value):
        if self.data_user:
            self.data_user.update_record(temporary_password_hash=value)
            self._temporary_password_hash = value

    @property
    def temporary_password_expire(self):
        self._temporary_password_expire = None
        if self.data_user:
            self._temporary_password_expire = self.data_user.temporary_password_expire
        return self._temporary_password_expire

    @temporary_password_expire.deleter
    def temporary_password_expire(self):
        self.temporary_password_expire = None

    @temporary_password_expire.setter
    def temporary_password_expire(self, value):
        if self.data_user:
            self.data_user.update_record(temporary_password_expire=value)
            self._temporary_password_expire = value

    @property
    def activate_hash(self):
        self._activate_hash = None
        if self.data_user:
            self._activate_hash = self.data_user.activate_hash
        return self._activate_hash

    @activate_hash.setter
    def activate_hash(self, value):
        if self.data_user:
            self.data_user.update_record(activate_hash=value)
            self._activate_hash = value

    @property
    def activate_code(self):
        self._activate_code = None
        if self.data_user:
            self._activate_code = self.data_user.activate_code
        return self._activate_code

    @activate_code.setter
    def activate_code(self, value):
        if self.data_user:
            self.data_user.update_record(activate_code=value)
            self._activate_code = value

    @property
    def attempts_to_activate(self):
        self._attempts_to_activate = None
        if self.data_user:
            self._attempts_to_activate = self.data_user.attempts_to_activate
        return self._attempts_to_activate

    @attempts_to_activate.setter
    def attempts_to_activate(self, value):
        if self.data_user:
            self.data_user.update_record(attempts_to_activate=value)
            self._attempts_to_activate = value

    @property
    def activate_date_expire(self):
        self._activate_date_expire = None
        if self.data_user:
            self._activate_date_expire = self.data_user.activate_date_expire
        return self._activate_date_expire

    @activate_date_expire.setter
    def activate_date_expire(self, value):
        if self.data_user:
            self.data_user.update_record(activate_date_expire=value)
            self._activate_date_expire = value

    @property
    def retrieve_hash(self):
        self._retrieve_hash = None
        if self.data_user:
            self._retrieve_hash = self.data_user.retrieve_hash
        return self._retrieve_hash

    @retrieve_hash.setter
    def retrieve_hash(self, value):
        if self.data_user:
            self.data_user.update_record(retrieve_hash=value)
            self._retrieve_hash = value

    @property
    def activated(self):
        self._activated = None
        if self.data_user:
            self._activated = self.data_user.activated
        return self._activated

    @activated.setter
    def activated(self, value):
        if self.data_user:
            self.data_user.update_record(activated=value)
            self._activated = value

    @property
    def rest_key(self):
        self._rest_key = None
        if self.data_user:
            self._rest_key = self.data_user.rest_key
        return self._rest_key

    @rest_key.setter
    def rest_key(self, value):
        if self.data_user:
            self.data_user.update_record(rest_key=value)
            self._rest_key = value

    @property
    def rest_token(self):
        self._rest_token = None
        if self.data_user:
            self._rest_token = self.data_user.rest_token
        return self._rest_token

    @rest_token.setter
    def rest_token(self, value):
        if self.data_user:
            self.data_user.update_record(rest_token=value)
            self._rest_token = value

    @property
    def rest_date(self):
        self._rest_date = None
        if self.data_user:
            self._rest_date = self.data_user.rest_date
        return self._rest_date

    @rest_date.setter
    def rest_date(self, value):
        if self.data_user:
            self.data_user.update_record(rest_date=value)
            self._rest_date = value

    @property
    def rest_expire(self):
        self._rest_expire = None
        if self.data_user:
            self._rest_expire = self.data_user.rest_expire
        return self._rest_expire

    @rest_expire.setter
    def rest_expire(self, value):
        if self.data_user:
            self.data_user.update_record(rest_expire=value)
            self._rest_expire = value

    @property
    def permit_double_login(self):
        self._permit_double_login = None
        if self.data_user:
            self._permit_double_login = self.data_user.permit_double_login
        return self._permit_double_login

    @permit_double_login.setter
    def permit_double_login(self, value):
        if self.data_user:
            self.data_user.update_record(permit_double_login=value)
            self._permit_double_login = value

    @property
    def token(self):
        if self.remember_me:
            time = int(timedelta(365).total_seconds())
            self.rest_date = datetime.now() + timedelta(days=365)
        else:
            time = app.config['DEFAULT_TIME_TOKEN_EXPIRES']
            self.rest_date = datetime.now() + timedelta(seconds=time)
        t = Serialize(app.config['SECRET_KEY_USERS'], time)
        token = t.dumps(
            {'id_user': self.id, 'email': self.email}
        )
        self.rest_token = token
        self.commit()
        return token

    @property
    def data_user(self):
        if self._value_field is None:
            self._user = None
        else:
            db = self.db
            self._user = db(db['auth_user'][self._field] == self._value_field).select().first()
        return self._user

    @staticmethod
    def create_activation_ajax_code():
        import random
        numbers = []
        while len(numbers) < 5:
            number = random.randint(0, 9)
            if number not in numbers:
                if not ((len(numbers) == 0) and (number == 0)):
                    numbers.append(str(number))
        final_number = int("".join(numbers))
        return final_number

    @staticmethod
    def create_temporary_password():
        import random
        matrix = 'abcdefghijlmnopqrstuvxzwykABCDEFGHIJLMNOPQRSTUVXZWYK0123456789'
        password = []
        while len(password) < 8:
            number = random.randint(0, len(matrix) - 1)
            char = matrix[number]
            if char not in password:
                password.append(char)
        final_password = "".join(password)
        return final_password

    def send_temporary_password(self):
        if self.data_user:
            new_password = self.create_temporary_password()
            self.temporary_password = new_password
            pass_hash = generate_password_hash("password%s%s" % (new_password, app.config['SECRET_KEY_USERS']))
            self.data_user.update_record(
                temporary_password_hash=pass_hash,
                temporary_password_expire=datetime.now() + timedelta(minutes=10),
            )
            self.commit()
            self._send_email(app.config['MAIL_DEFAULT_SENDER'], model="temporary_password")

    def send_new_ajax_activation_code(self):
        if self.data_user:
            if not self.activated:
                new_code = self.create_activation_ajax_code()
                self.data_user.update_record(
                    activate_code=new_code,
                    activate_date_expire=datetime.now() + timedelta(hours=12),
                    attempts_to_activate=0
                )
                self.commit()
                self._send_email(app.config['MAIL_DEFAULT_SENDER'], model="activation_ajax")

    def increment_attempts_to_activate(self):
        if self.data_user:
            if self.attempts_to_activate:
                self.attempts_to_activate += 1
            else:
                self.attempts_to_activate = 1
            self.commit()

    def new_password(self, password, reset_temporary_password=False):
        if reset_temporary_password:
            del self.temporary_password
            del self.temporary_password_hash
            del self.temporary_password_expire
        pass_hash = generate_password_hash("password%s%s" % (password, app.config['SECRET_KEY_USERS']))
        self.password_hash = pass_hash
        self.commit()

    def register_ajax(self, first_name, last_name, email, password):
        db = self.db
        q_email = db(db.auth_user.email == email).select().first()
        if not q_email:
            final_number = self.create_activation_ajax_code()
            pass_hash = generate_password_hash("password%s%s" % (password, app.config['SECRET_KEY_USERS']))
            id_user = db.auth_user.validate_and_insert(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password_hash=pass_hash,
                activate_code=final_number,
                attempts_to_activate=0,
                activate_date_expire=datetime.now() + timedelta(hours=12),
            )
            if id_user:
                self.commit()
                self._field = "id"
                self._value_field = id_user
                self._send_email(app.config['MAIL_DEFAULT_SENDER'], model="activation_ajax")
            else:
                self.rollback()

    def _send_email(self, email_origem, nome_origem="no-reply", model="welcome"):
        email_ok = False
        user = self.data_user
        email = user.email
        first_name = user.first_name
        last_name = user.last_name
        activate_code = user.activate_code
        titulo = "Bem vindo!"
        text_email = "Bem vindo %s %s, Estamos felizes de tê-lo conosco." % (first_name, last_name)
        html_email = "<h3>Bem vindo %s %s</h3><br /><p>Estamos felizes de tê-lo conosco.</p>" % (first_name, last_name)
        activity_text = ""

        if model == "activation_ajax":
            titulo = "Ativação de Conta"
            code = activate_code
            text_email = '\tOlá %s %s, sua conta foi criada, falta apenas confirmação do email, para ativar utilize o seguinte código: %s.\nO código expira em 12 horas.' % (first_name, last_name, code)
            html_email = '<h3>Olá %s %s,</h3><br /><p>sua conta foi criada, falta apenas confirmação do email, para ativar utilize o seguinte código: <b>%s</b></p><p>O código expira em 12 horas.</p>' % (first_name, last_name, code)
            activity_text ='Tentativa de envio de email com código ativação.\nStatus do envio: %s'
            email_ok = True
        elif model == "temporary_password":
            t = Serialize(app.config['SECRET_KEY_USERS'], timedelta(minutes=10).total_seconds())
            password = None
            try:
                password = t.loads(self.temporary_password)['temporary_password']
            except BadSignature:
                self.activity("A senha temporária não pode ser decifrada")
            except SignatureExpired:
                self.activity("A senha temporária expirou, o email não poderá ser enviado!")
            except KeyError:
                self.activity("A senha temporária tem um token cujo key apresentou erro!")
            if password:
                if app.debug:
                    app.logger.debug(password)
                titulo = "Senha temporária de recuperação"
                text_email = '\tOlá %s %s, foi solicitado uma alteração de senha de uma conta vinculada a este email, utilize a seguinte senha para prosseguir com a alteração: %s.\nBasta acessar o site e logar com esta senha que foi enviada, ela estará ativa apenas 10 minutos.' % (first_name, last_name, password)
                html_email = '<h3>Olá %s %s,</h3><br /><p>foi solicitado uma alteração de senha de uma conta vinculada a este email, utilize a seguinte senha para prosseguir com a alteração: <b>%s</b></p><p>Basta acessar o site e logar com esta senha que foi enviada, ela estará ativa apenas 10 minutos.</p>' % (first_name, last_name, password)
                activity_text = 'Tentativa de envio de email com senha temporária.\nStatus do envio: %s'
                email_ok = True
        if email_ok:
            msg = Message(titulo, sender=email_origem)
            msg.recipients = [email]
            msg.body = text_email
            msg.html = html_email
            result = None
            try:
                result = mail.send(msg)
            except Exception as e:
                result = "Email from '%s' to '%s' don't send! -> Error: %s" % (email_origem, email, e)
            if result and activity_text:
                self.activity(activity_text % result)

    def activity(self, activity):

        text_request = "Path: %(Path)s\n" +\
            "HTTP Method: %(Method)s\n" +\
            "Client IP Address: %(Address)s\n" +\
            "User Agent: %(Agent)s\n" +\
            "User Platform: %(Platform)s\n" +\
            "User Browser: %(Browser)s\n" +\
            "User Browser Version: %(Version)s\n" +\
            "GET args: %(args)s\n" +\
            "view args: %(view)s\n" +\
            "URL: %(URL)s\n"
        text_request = text_request % {
            "Path": request.path,
            "Method": request.method,
            "Address": request.remote_addr,
            "Agent": request.user_agent.string,
            "Platform": request.user_agent.platform,
            "Browser": request.user_agent.browser,
            "Version": request.user_agent.version,
            "args": dict(request.args),
            "view": request.view_args,
            "URL": request.url
        }

        db.auth_activity.insert(auth_user=self.id, activity=activity, request=text_request)
        self.commit()

    def verify_password(self, password):
        result = False
        user = self.data_user
        if self.password_hash:
            if check_password_hash(
                self.password_hash,
               "password%s%s" % (
                    password,
                    app.config['SECRET_KEY_USERS'])):
                result = True
            elif (self.temporary_password_hash) and (self.temporary_password_expire):
                now = datetime.now()
                if now > user.temporary_password_expire:
                    self.temporary_password_expire = None
                    self.temporary_password_hash = None
                else:
                    if check_password_hash(
                        self.temporary_password_hash,
                        "password%s%s" % (password, app.config['SECRET_KEY_USERS'])
                    ):
                        result = True
        return result

    def check_token(self, token):
        usuario = self
        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            t.loads(token)
            token = t.dumps({'id': usuario.id, 'email': usuario.email})
            return token.decode("utf-8")
        except BadSignature:
            return None
        except SignatureExpired:
            return None
        return None

    @property
    def roles(self):
        db = self.db
        q_roles = db(db.auth_membership.auth_user == self.id).select()
        if q_roles:
            roles = []
            for x in q_roles:
                roles.append(x.auth_group.role)
            self._roles = roles
        else:
            self._roles = []
        return self._roles

    def __bool__(self):
        if self.data_user:
            return True
        else:
            return False

    def __str__(self):
        return self.data_user.as_json()


class CSRF(object):
    db = db

    def __init__(self, time=app.config['DEFAULT_TIME_TOKEN_EXPIRES']):
        super(CSRF, self).__init__()
        self.db._adapter.reconnect()
        self.time = time

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()

    def token(self, proposito="publico", conteudo=None):
        t = Serialize(app.config['SECRET_KEY_USERS'], self.time)
        id_csrf = self.db.csrf.insert(proposito=proposito, date_created=datetime.now())
        if conteudo:
            conteudo['proposito'] = proposito
        else:
            conteudo = {'proposito': proposito}

        if id_csrf:
            self._token = t.dumps({'id_csrf': id_csrf, **conteudo})
            self.db.csrf[id_csrf].update_record(token=self._token.decode("utf-8"))
            self.commit()

            return self._token.decode("utf-8")

    def valid_response_token(self, token):
        t = Serialize(app.config['SECRET_KEY_USERS'])
        try:
            conteudo = t.loads(token)
        except BadSignature:
            return None
        except SignatureExpired:
            return None

        if conteudo:
            db = self.db
            q_token = db(db.csrf.id == conteudo['id_csrf']).select().first()
            if q_token:
                v_token = q_token.token
                v_proposito = q_token.proposito
                q_token.delete_record()
                self.commit()
                if (token == v_token) and (conteudo['proposito'], v_proposito):
                    return conteudo
        else:
            db = self.db
            q_token = db(db.csrf.token == token).select().first()
            if q_token:
                q_token.delete_record()
                self.commit()

        return None


class ErrorLog(object):
    db = db

    def __init__(self):
        super(ErrorLog, self).__init__()
        self.db._adapter.reconnect()

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()

    def error(self, description):

        text_request = "Authorization: %(Authorization)s\n" +\
            "Path: %(Path)s\n" +\
            "HTTP Method: %(Method)s\n" +\
            "Client IP Address: %(Address)s\n" +\
            "User Agent: %(Agent)s\n" +\
            "User Platform: %(Platform)s\n" +\
            "User Browser: %(Browser)s\n" +\
            "User Browser Version: %(Version)s\n" +\
            "GET args: %(args)s\n" +\
            "view args: %(view)s\n" +\
            "URL: %(URL)s\n"
        Authorization = request.headers.get('Authorization')
        text_request = text_request % {
            "Authorization": Authorization,
            "Path": request.path,
            "Method": request.method,
            "Address": request.remote_addr,
            "Agent": request.user_agent.string,
            "Platform": request.user_agent.platform,
            "Browser": request.user_agent.browser,
            "Version": request.user_agent.version,
            "args": dict(request.args),
            "view": request.view_args,
            "URL": request.url
        }

        id_error = self.db.error_log.insert(description=description, request=text_request)
        if id_error:
            self.commit()
