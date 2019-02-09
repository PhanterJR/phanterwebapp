# -*- coding: utf-8 -*-
from .. import (
    app,
    api,
    __version__ as app_version,
    __project__ as app_name,
)

from inspect import currentframe, getframeinfo
from ..models import User, CSRF, ErrorLog, db
from ..models.phantergallery import UserImage
from phanterweb.validators import ValidateReqArgs
from phanterweb.phantergallery import PhanterGalleryCutter
from phanterweb.captcha import Captcha
from phanterweb.db_date_datetime import conv_datetime, conv_date
from flask import request, url_for, Markup, send_from_directory
from flask_restful import Resource, reqparse
from functools import wraps
from werkzeug.utils import secure_filename
from itsdangerous import (
    TimedJSONWebSignatureSerializer as Serialize, BadSignature, SignatureExpired
)
from datetime import datetime, timedelta
import os

parser = reqparse.RequestParser()
time = app.config['DEFAULT_TIME_TOKEN_EXPIRES']
processError = ErrorLog()


def requires_login(
    authorized_roles=None,
    check_csrf=False,
    intention_csrf=None,
    defid="requires_login"):
    def real_decorator(f):
        @wraps(f)
        def f_intern(*args, **kargs):
            parser.add_argument('Authorization', location='headers')
            parser.add_argument('csrf_token', location='form')
            args = parser.parse_args()
            token = args['Authorization']
            t = Serialize(
                app.config['SECRET_KEY_USERS'],
                app.config['DEFAULT_TIME_TOKEN_EXPIRES']
            )
            new_csrf_token = None
            try:
                id_user = t.loads(token)['id_user']
            except Exception as e:
                id_user = 0
            authorization_error = ErrorLog()
            if id_user:
                usuario = User(id_user=id_user)
                if usuario:
                    if isinstance(authorized_roles, (tuple, list)):
                        has_autorization = False
                        for x in usuario.roles:
                            if x in authorized_roles:
                                has_autorization = True
                        if has_autorization is False:
                            return {
                                'status': "ERROR",
                                'authenticated': False,
                                'auth_user': None,
                                'roles': ['Anônimo'],
                                'message': "Não tem autoriação",
                            }, 401
                    proposito = "publico"
                    csrf = CSRF()
                    if intention_csrf:
                        proposito = intention_csrf
                    csrf_token = csrf.token(proposito=intention_csrf)
                    new_csrf_token = csrf_token
                    if check_csrf:
                        is_valid = csrf.valid_response_token(args['csrf_token'])
                        if not is_valid:
                            frameinfo = getframeinfo(currentframe())
                            authorization_error.error(
                                "".join([
                                    "file: %s" % frameinfo.filename,
                                    "\nline: %s" % frameinfo.lineno,
                                    "\ndef: %s" % defid,
                                    "\nmessage: O token csrf não foi validado"
                                ])
                            )
                            return {
                                'status': "ERROR",
                                'authenticated': False,
                                'auth_user': None,
                                'roles': ['Anônimo'],
                                'message': "Erro no envio dos dados, tente novamente!",
                                'csrf': csrf_token,
                            }
                        else:
                            proposito = is_valid['proposito']
                            if proposito != intention_csrf:
                                frameinfo = getframeinfo(currentframe())
                                authorization_error.error(
                                    "".join([
                                        "file: %s" % frameinfo.filename,
                                        "\nline: %s" % frameinfo.lineno,
                                        "\ndef: %s" % defid,
                                        "\nmessage: token csrf válido sendo usado para ",
                                        intention_csrf,
                                        " porém gerado com propósito diferente: ",
                                        proposito
                                    ])
                                )
                                return {
                                    'status': "ERROR",
                                    'authenticated': False,
                                    'auth_user': None,
                                    'roles': ['Anônimo'],
                                    'message': "Token csrf inválido!",
                                }
                    kargs['token'] = token
                    kargs['usuario'] = usuario
                    kargs['new_csrf_token'] = new_csrf_token
                    return f(*args, **kargs)
                else:
                    id_user = str(id_user)
                    frameinfo = getframeinfo(currentframe())
                    message_error = "".join([
                        "file: %s" % frameinfo.filename,
                        "\nline: %s" % frameinfo.lineno,
                        "\ndef: %s" % defid,
                        "\nmessage: O usuário com id %s" % id_user,
                        " não foi localizado"
                    ])
                    authorization_error.error(
                        message_error
                    )
                    return {
                        'status': 'ERROR',
                        'authenticated': False,
                        'auth_user': None,
                        'roles': ['Anônimo'],
                        'message': 'Usuário não localizado'
                    }
            else:
                usuario = User(token=token)
                if usuario:
                    ultima_data = usuario.rest_date
                    periodo = datetime.now() - ultima_data
                    if (periodo.seconds > 0) and (periodo.seconds < app.config['DEFAULT_TIME_TOKEN_EXPIRES']):
                        new_token = usuario.token
                        usuario = User(token=new_token)
                        if usuario.activated:
                            activated = True
                        else:
                            activated = False
                        email = Markup.escape(usuario.email)
                        is_to_remember = True if usuario.remember_me else False
                        user_roles = ["user"]
                        if usuario.roles:
                            user_roles = usuario.roles
                            if "user" not in user_roles:
                                user_roles.append("user")
                        user_image = UserImage(usuario.id)
                        url_image_user = user_image.url_image
                        first_name = Markup.escape(usuario.first_name)
                        last_name = Markup.escape(usuario.last_name)
                        user_name = "%s %s" % (first_name, last_name)
                        if usuario.roles:
                            if "administrator" in usuario.roles:
                                user_role = "Administrador"
                            if "root" in usuario.roles:
                                user_role = "Super Administrador"
                        return {
                            'status': 'OK',
                            'authenticated': True,
                            'retoken': True,
                            'token': new_token.decode('utf-8'),
                            'auth_user': {
                                'id': usuario.id,
                                'user_name': user_name,
                                'first_name': first_name,
                                'last_name': last_name,
                                'url_image_user': url_image_user,
                                'remember_me': is_to_remember,
                                'role': user_role,
                                'roles': user_roles,
                                'email': email,
                            },
                            'activated': activated
                        }
                    else:
                        frameinfo = getframeinfo(currentframe())
                        authorization_error.error(
                            "".join([
                                "file: %s" % frameinfo.filename,
                                "\nline: %s" % frameinfo.lineno,
                                "\ndef: %s" % defid,
                                "\nmessage: O token %s" % token,
                                " é inválido mesmo depois de um retoken."
                            ])
                        )
                        return {
                            'status': 'ERROR',
                            'authenticated': False,
                            'auth_user': None,
                            'roles': ['Anônimo'],
                            'message': 'Token inválido ou expirado, faça login novamente!'
                        }

                frameinfo = getframeinfo(currentframe())
                authorization_error.error(
                    "".join([
                        "file: %s" % frameinfo.filename,
                        "\nline: %s" % frameinfo.lineno,
                        "\ndef: %s" % defid,
                        "\nmessage: O token %s" % token,
                        " é inválido."
                    ])
                )
                return {
                    'status': 'ERROR',
                    'authenticated': False,
                    'auth_user': None,
                    'roles': ['Anônimo'],
                    'message': 'Token inválido ou expirado, faça login novamente!'
                }
        return f_intern
    return real_decorator


def requires_csrf(
    intention_csrf=None,
    defid="requires_csrf"):
    def real_decorator(f):
        @wraps(f)
        def f_intern(*args, **kargs):
            authorization_error = ErrorLog()
            parser.add_argument('csrf_token', location='form')
            args = parser.parse_args()
            csrf = CSRF()
            is_valid = csrf.valid_response_token(args['csrf_token'])
            proposito = "publico"
            if intention_csrf:
                proposito = intention_csrf
            csrf_token = csrf.token(proposito=intention_csrf)
            if not is_valid:
                frameinfo = getframeinfo(currentframe())
                authorization_error.error(
                    "".join([
                        "file: %s" % frameinfo.filename,
                        "\nline: %s" % frameinfo.lineno,
                        "\ndef: %s" % defid,
                        "\nmessage: O token csrf não foi validado"
                    ])
                )
                return {
                    'status': "ERROR",
                    'message': "Erro no envio dos dados, tente novamente!",
                    'csrf_token': csrf_token,
                }
            else:
                proposito = is_valid['proposito']
                if proposito != intention_csrf:
                    frameinfo = getframeinfo(currentframe())
                    authorization_error.error(
                        "".join([
                            "file: %s" % frameinfo.filename,
                            "\nline: %s" % frameinfo.lineno,
                            "\ndef: %s" % defid,
                            "\nmessage: token  válido sendo usado para ",
                            intention_csrf,
                            " porém gerado com propósito diferente: ",
                            proposito
                        ])
                    )
                    return {
                        'status': "ERROR",
                        'message': "Token csrf inválido!",
                    }

            kargs['new_csrf_token'] = csrf_token
            return f(*args, **kargs)
        return f_intern
    return real_decorator


def data_auth_user(query_auth_user):
    q_membership = db(db.auth_membership.auth_user == query_auth_user.id).select()
    groups = ""
    cont = 0
    g_proc = []
    for x in q_membership:
        if x.auth_group not in g_proc:
            g_proc.append(x.auth_group)
            if cont == 0:
                groups = "%s" % x.auth_group
            else:
                groups += "|%s" % x.auth_group
            cont += 1
    datetime_next_attempt_to_login = conv_datetime(
        query_auth_user.datetime_next_attempt_to_login, "%d/%m/%Y %H:%M:%S")
    temporary_password_expire = conv_datetime(
        query_auth_user.temporary_password_expire, "%d/%m/%Y %H:%M:%S")
    activate_date_expire = conv_datetime(
        query_auth_user.activate_date_expire, "%d/%m/%Y %H:%M:%S")
    rest_date = conv_datetime(
        query_auth_user.rest_date, "%d/%m/%Y %H:%M:%S")

    user_image = UserImage(query_auth_user.id)
    url_image_user = user_image.url_image

    data = {
        'id': query_auth_user.id,
        'user_image': url_image_user,
        'first_name': query_auth_user.first_name,
        'last_name': query_auth_user.last_name,
        'email': query_auth_user.email,
        'remember_me': query_auth_user.remember_me,
        'password_hash': query_auth_user.password_hash,
        'attempts_to_login': query_auth_user.attempts_to_login,
        'datetime_next_attempt_to_login': datetime_next_attempt_to_login,
        'temporary_password': query_auth_user.temporary_password,
        'temporary_password_hash': query_auth_user.temporary_password_hash,
        'temporary_password_expire': temporary_password_expire,
        # 'activate_hash': query_auth_user.activate_hash,
        'activate_code': query_auth_user.activate_code,
        'attempts_to_activate': query_auth_user.attempts_to_activate,
        'activate_date_expire': activate_date_expire,
        'retrieve_hash': query_auth_user.retrieve_hash,
        'permit_double_login': query_auth_user.permit_double_login,
        'rest_key': query_auth_user.rest_key,
        'rest_token': query_auth_user.rest_token,
        'rest_date': rest_date,
        # 'rest_expire': query_auth_user.rest_expire,
        'activated': query_auth_user.activated,
        'groups': groups
    }
    return data


def process_list_string(value):
    new_value = []
    if value:
        for x in value.split("|"):
            if x:
                try:
                    x = int(x)
                    new_value.append(x)
                except Exception as e:
                    frameinfo = getframeinfo(currentframe())
                    processError.error(
                        "".join([
                            "file: %s" % frameinfo.filename,
                            "\nline: %s" % frameinfo.lineno,
                            "\ndef: process_list_string",
                            "\nvalue: %s" % value,
                            "\nerror: %s" % e,
                            "\nmessage: O valor da lista não é um número inteiro"
                        ])
                    )
    return new_value


def process_checkbox(value):
    if value == "on":
        return True
    else:
        return False


def process_intenger(value):
    try:
        value = int(value)
        return value
    except Exception as e:
        frameinfo = getframeinfo(currentframe())
        processError.error(
            "".join([
                "file: %s" % frameinfo.filename,
                "\nline: %s" % frameinfo.lineno,
                "\ndef: process_intenger",
                "\nvalue: %s" % value,
                "\nerror: %s" % e,
                "\nmessage: O valor não pode ser convertido para inteiro"
            ])
        )
        return 0


def process_date(value):
    import time

    try:
        tempo = datetime(*(time.strptime(str(value), '%d/%m/%Y')[0:6]))
        return tempo
    except Exception as e:
        frameinfo = getframeinfo(currentframe())
        processError.error(
            "".join([
                "file: %s" % frameinfo.filename,
                "\nline: %s" % frameinfo.lineno,
                "\ndef: process_intenger",
                "\nvalue: %s" % value,
                "\nerror: %s" % e,
                "\nmessage: A data não pode ser convertida"
            ])
        )
        return None


def process_datetime(value):
    import time

    try:
        tempo = datetime(*(time.strptime(str(value), '%d/%m/%Y %H:%M:%S')[0:6]))
        return tempo
    except Exception as e:
        frameinfo = getframeinfo(currentframe())
        processError.error(
            "".join([
                "file: %s" % frameinfo.filename,
                "\nline: %s" % frameinfo.lineno,
                "\ndef: process_intenger",
                "\nvalue: %s" % value,
                "\nerror: %s" % e,
                "\nmessage: A datahora não pode ser convertida"
            ])
        )
        return None


def process_generic_data(value, datastr="%d/%m/%Y"):
    if value is None:
        return None
    elif isinstance(value, (bool, list, dict, int, tuple, float)):
        return value
    elif isinstance(value, str):
        return Markup(value)
    elif isinstance(value, datetime):
        conv_date(value, datastr)
    else:
        value = str(value)
        return Markup(str(value))


class RestApi(Resource):
    """
        url: /api
    """

    def get(self):
        return {'status': 'OK',
            'message': 'Hello World'}


class RestCSRF(Resource):
    def get(self):
        parser.add_argument('proposito')
        args = parser.parse_args()
        proposito = args['proposito']
        prop = "publico"
        if proposito:
            prop = proposito
        csrf = CSRF()
        token = csrf.token(proposito=prop)
        return {"status": "OK", "token_captcha": token, "csrf": token}


class RestCaptcha(Resource):
    """
        url: /api/captcha
    """

    def get(self):
        parser.add_argument('group')
        args = parser.parse_args()
        group = args['group']
        captcha = Captcha(group)
        choice = captcha.choice
        csrf = CSRF()
        token = csrf.token(proposito="captcha", conteudo={"choice": choice})
        captcha.token = token
        return {"status": "OK", "token_captcha": token, "html": captcha.html.xml()}

    def post(self):
        parser.add_argument('cmd_option')
        parser.add_argument('token_captcha')
        parser.add_argument('group')
        args = parser.parse_args()
        cmd_option = args['cmd_option']
        token_captcha = args['token_captcha']
        group = args['group']
        csrf = CSRF()
        response_token = csrf.valid_response_token(token_captcha)
        captcha = Captcha(group)
        if response_token:
            if captcha.check(response_token['choice'], cmd_option):
                csrf = CSRF()
                csrf_token = csrf.token(proposito=group)

                return {"status": "OK", "html": captcha.html_ok.xml(), "csrf": csrf_token}
            else:
                return {"status": "ERROR", "message": "Captcha Falhou! Tente Novamente.", "group": group}
        else:
            return {"status": "ERROR", "message": "Captcha Falhou! Tente Novamente.", "group": group}


class RestActive(Resource):

    @requires_login(defid="RestActive.get")
    def get(self, *args, **kargs):
        if 'usuario' in kargs:
            usuario = kargs['usuario']
            if usuario:
                if usuario.activate_date_expire:
                    data_code = (
                        usuario.activate_date_expire + timedelta(minutes=5)
                    ) - timedelta(hours=12)
                    now = datetime.now()
                    minutes = data_code - now
                    minutes = int(minutes.seconds / 60) + 1
                    if now < data_code:
                        return {
                            'status': 'ERROR',
                            'message': 'Aguarde %s minuto(s) para nova tentativa!' % minutes
                        }
                    else:
                        usuario.send_new_ajax_activation_code()
                        return {
                            'status': 'OK',
                            'message': 'Código Enviado!'
                        }
                else:
                    usuario.send_new_ajax_activation_code()
                    return {'status': 'OK', 'message': 'Código Enviado!'}

    @requires_login(defid="RestActive.post")
    def post(self, *args, **kargs):
        parser.add_argument('code')
        args = parser.parse_args()
        code = args['code']
        try:
            code = int(code)
        except Exception as e:
            return {'status': 'ERROR', 'message': 'Código Inválido!'}
        usuario = kargs['usuario']
        if not usuario.activated:
            usuario.increment_attempts_to_activate()
            attempts_to_activate = usuario.attempts_to_activate
            if attempts_to_activate < 4:
                now = datetime.now()
                if usuario.activate_code and (usuario.activate_code == code):
                    if usuario.activate_date_expire:
                        activate_date_expire = usuario.activate_date_expire
                        if now > activate_date_expire:
                            return {'status': 'ERROR', 'message': 'Código Expirado!'}
                        else:
                            usuario.activate_code = None
                            usuario.attempts_to_activate = None
                            usuario.activate_date_expire = None
                            usuario.activated = True
                            usuario.commit()
                            return {
                                'status': 'OK',
                                'message': 'Código Aceito! Conta ativada.'}
                    else:
                        return {'status': 'ERROR', 'message': 'Código Expirado!'}
                else:
                    return {'status': 'ERROR', 'message': 'Código Inválido!'}
            else:
                return {'status': 'ERROR', 'message': 'É permitido apenas 3 tentativas!'}
        else:
            return {'status': 'ERROR', 'message': 'Sua conta já está ativada!'}


class RestRequestPassword(Resource):

    @requires_csrf(intention_csrf="request-password", defid="RestRequestPassword.post")
    def post(self, *args, **kargs):
        parser.add_argument('email-request-password')
        args = parser.parse_args()
        validate = ValidateReqArgs(args)
        email = args['email-request-password']
        validate.isEmail('email-request-password', "O email é inválido.")
        csrf_token = kargs['new_csrf_token']

        if validate.anyError:
            return {
                'status': 'ERROR',
                'message': 'Erros nos dados enviados!',
                'csrf': csrf_token,
                'validators': validate.validators
            }
        else:
            usuario = User(email=email)
            if usuario:
                if usuario.temporary_password_expire:
                    now = datetime.now()
                    if now > usuario.temporary_password_expire:
                        usuario.temporary_password_expire = None
                        usuario.temporary_password_hash = None
                        usuario.send_temporary_password()
                        return {
                            'status': 'OK',
                            'message': 'senha enviada para o email'
                        }
                    else:
                        return {
                            'status': 'ERROR',
                            'message': 'Aguarde alguns minutos para uma nova solicitação!'
                        }
                else:
                    usuario.send_temporary_password()
                    return {
                        'status': 'OK',
                        'message': 'senha enviada para o email'
                    }
            else:
                return {
                    'status': 'ERROR',
                    'message': 'Não há conta com este email!'
                }


class RestChangePassword(Resource):

    @requires_login(intention_csrf="change_password", defid="RestChangePassword.get")
    def get(self, *args, **kargs):
        if ('usuario' in kargs) and ('new_csrf_token' in kargs):
            usuario = kargs["usuario"]
            if usuario:
                csrf_token = kargs['new_csrf_token']
                temporary_password = False
                if (usuario.temporary_password_hash) and (usuario.temporary_password_expire):
                    if datetime.now() < usuario.temporary_password_expire:
                        temporary_password = True
                return {
                    'status': 'OK',
                    'csrf': csrf_token,
                    'temporary_password': temporary_password
                }
            else:
                return {'status': 'ERROR', 'message': 'Usuário ou/e token Inválido(s)!'}
        else:
            return {'status': 'ERROR', 'message': 'Usuário ou/e token Inválido(s)!'}

    @requires_login(check_csrf=True, intention_csrf="change_password", defid="RestChangePassword.post")
    def post(self, *args, **kargs):
        usuario = kargs["usuario"]
        csrf_token = kargs['new_csrf_token']
        parser.add_argument('old_password')
        parser.add_argument('password')
        parser.add_argument('password_repeat')
        args = parser.parse_args()
        old_password = args['old_password']
        password = args['password']
        password_repeat = args['password_repeat']
        validate = ValidateReqArgs(args)
        validate.isNotEmpty('old_password')
        validate.isNotEmpty('password')
        validate.isNotEmpty('password_repeat')
        validate.isEquals('password', password_repeat, "As senhas não coincidem.")
        validate.isEquals('password_repeat', password, "As senhas não coincidem.")
        if validate.anyError:
            return {
                'status': 'ERROR',
                'message': 'Erros nos dados enviados!',
                'csrf': csrf_token,
                'validators': validate.validators
            }
        else:
            if usuario.verify_password(old_password):
                usuario.new_password(password, True)
                return {
                    'status': "OK",
                    'message': "Senha alterada com sucesso!"
                }
            else:
                usuario.activity("RestChangePassword: A senha antiga é inválida")
                return {
                    'status': 'ERROR',
                    'message': 'Senha antiga inválida!',
                    'csrf': csrf_token
                }


class RestImageUser(Resource):
    """
        url:/api/user/image/<int:id_image>/<autorization>
    """

    def get(self, id_image, autorization):
        reader_autorization = Serialize(app.config['SECRET_KEY_USERS'])
        has_autorization = False
        try:
            message = reader_autorization.loads(autorization)
            token = message['token']
            has_autorization = True
        except BadSignature:
            has_autorization = False
        except SignatureExpired:
            has_autorization = False

        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            id_user = t.loads(token)['id_user']
        except Exception as e:
            id_user = 0

        if has_autorization:
            usuario = User(id_user=id_user)
            if usuario:
                user_image = UserImage(usuario.id).image
                if user_image:
                    filename = "%s.%s" % (user_image.id, user_image.extensao)
                    folder = os.path.join(app.root_path, user_image.folder)
                    return send_from_directory(folder, filename)
                else:
                    return send_from_directory(
                        os.path.join(app.root_path, "static", "images"),
                        "user.png"
                    )
            else:
                return send_from_directory(
                    os.path.join(app.root_path, "static", "images"),
                    "user.png"
                )
        else:
            return send_from_directory(
                os.path.join(app.root_path, "static", "images"),
                "user.png"
            )

class RestUsers(Resource):

    @requires_login()
    def get(self, *args, **kargs):
        usuario = kargs['usuario']
        token = kargs['token']
        if usuario:
            user_name = Markup.escape("%s %s" % (usuario.first_name, usuario.last_name))
            if usuario.activated:
                activated = True
            else:
                activated = False
            email = Markup.escape(usuario.email)
            is_to_remember = True if usuario.remember_me else False
            user_roles = ["user"]
            if usuario.roles:
                user_roles = usuario.roles
                if "user" not in user_roles:
                    user_roles.append("user")
            user_image = UserImage(usuario.id)
            url_image_user = user_image.url_image
            first_name = Markup.escape(usuario.first_name)
            last_name = Markup.escape(usuario.last_name)
            user_role = "Usuário"
            if usuario.roles:
                if "administrator" in usuario.roles:
                    user_role = "Administrador"
                if "root" in usuario.roles:
                    user_role = "Super Administrador"
            return {
                'status': 'OK',
                'authenticated': True,
                'auth_user': {
                    'id': usuario.id,
                    'user_name': user_name,
                    'first_name': first_name,
                    'last_name': last_name,
                    'url_image_user': url_image_user,
                    'remember_me': is_to_remember,
                    'role': user_role,
                    'roles': user_roles,
                    'email': email,
                },
                'activated': activated
            }

    @requires_csrf(intention_csrf="register", defid="RestUsers.post")
    def post(self, *args, **kargs):
        parser.add_argument('first_name')
        parser.add_argument('last_name')
        parser.add_argument('email')
        parser.add_argument('password')
        parser.add_argument('password_repeat')
        args = parser.parse_args()
        first_name = args['first_name']
        last_name = args['last_name']
        email = args['email']
        password = args['password']
        password_repeat = args['password_repeat']
        validate = ValidateReqArgs(args)
        validate.isNotEmpty('first_name', "O nome não pode ser vazio.")
        validate.isNotEmpty('last_name', "O sobrenome não pode ser vazio.")
        validate.isNotEmpty('email', "O email não pode ser vazio.")
        validate.isEmail('email', "O email é inválido.")
        validate.isNotEmpty('password', "A senha não pode ser vazia.")
        validate.isNotEmpty('password_repeat', "Repita a senha.")
        validate.isEquals('password', password_repeat, "As senhas não coincidem.")
        validate.isEquals('password_repeat', password, "As senhas não coincidem.")
        csrf_token = kargs['new_csrf_token']
        if validate.anyError:
            return {
                'status': 'ERROR',
                'message': 'Erros nos dados enviados!',
                'csrf': csrf_token,
                'validators': validate.validators
            }
        else:
            usuario_existe = User(email=email)
            if usuario_existe:
                return {
                    'status': 'ERROR',
                    'message': 'Já existe uma conta com este email.',
                }
            else:
                new_user = User()
                new_user.register_ajax(first_name, last_name, email, password)
                new_user.commit()
                url_image_user = url_for('static', filename="images/user.png")
                user_role = "Usuário"
                if new_user.roles:
                    if "administrator" in new_user.roles:
                        user_role = "Administrador"
                    if "root" in new_user.roles:
                        user_role = "Super Administrador"
                new_user.roles
                user_roles = ["user"]
                if new_user.roles:
                    user_roles = new_user.roles
                    if "user" not in user_roles:
                        user_roles.append("user")
                is_to_remember = new_user.remember_me
                if new_user:
                    return {
                        'status': 'OK',
                        'id_user': '%s' % (new_user.id),
                        'token': '%s' % (new_user.token.decode('utf-8')),
                        'message': 'Usuário criado com sucesso!',
                        'auth_user': {
                            'id': new_user.id,
                            'user_name': Markup.escape("%s %s" % (first_name, last_name)),
                            'first_name': Markup.escape(first_name),
                            'last_name': Markup.escape(last_name),
                            'url_image_user': url_image_user,
                            'remember_me': is_to_remember,
                            'role': user_role,
                            'roles': user_roles,
                            'email': Markup.escape(email),
                        }
                    }
                else:
                    return {
                        'status': 'ERROR',
                        'message': 'Já existe uma conta com este email.',
                    }

    @requires_login(check_csrf=True, intention_csrf="profile", defid="RestUsers.put")
    def put(self, *args, **kargs):
        usuario = kargs['usuario']
        csrf_token = kargs['new_csrf_token']
        parser.add_argument('email')
        parser.add_argument('first_name')
        parser.add_argument('last_name')
        parser.add_argument('phantergallery_upload-input-file-profile')
        parser.add_argument('phantergallery-input-name-cutterSizeX-profile')
        parser.add_argument('phantergallery-input-name-cutterSizeY-profile')
        parser.add_argument('phantergallery-input-name-positionX-profile')
        parser.add_argument('phantergallery-input-name-positionY-profile')
        parser.add_argument('phantergallery-input-name-newSizeX-profile')
        parser.add_argument('phantergallery-input-name-newSizeY-profile')
        args = parser.parse_args()
        first_name = args['first_name']
        last_name = args['last_name']
        new_email = args['email']
        validate = ValidateReqArgs(args)
        validate.isNotEmpty("first_name", "O nome não pode ser vazio.")
        validate.isNotEmpty("last_name", "O sobrenome não pode ser vazio.")
        validate.isEmail("email", "O email é inválido.")
        if validate.anyError:
            return {
                'status': 'ERROR',
                'message': 'Erros nos dados enviados!',
                'csrf': csrf_token,
                'validators': validate.validators
            }
        else:
            email_now = usuario.email
            email_alterado = False
            usuario_alterado = False
            sobrenome_alterado = False
            imagem_alterada = False
            if new_email != email_now:
                check_email = User(email=new_email)
                if check_email:
                    usuario.activity(
                        "".join(
                            [
                                "RestUsers: O usuário tentou mudar o email de ",
                                email_now, " para ", new_email,
                                " sem sucesso, o email já está cadastrado"
                            ]
                        )
                    )
                    return {
                        'status': 'ERROR',
                        'csrf': csrf_token,
                        'message': 'O novo email digitado já existe!',
                        'validators': {
                            'first_name': "OK",
                            'last_name': "OK",
                            'email': "O email já existe",
                        }
                    }
                else:
                    usuario.email = new_email
                    email_alterado = True

            if(first_name != usuario.first_name):
                usuario.first_name = first_name
                usuario_alterado = True
            if(last_name != usuario.last_name):
                usuario.last_name = last_name
                sobrenome_alterado = True

            if 'phantergallery_upload-input-file-profile' in request.files:
                imagem_alterada = True
                arquivo = request.files['phantergallery_upload-input-file-profile']
                cutterSizeX = args['phantergallery-input-name-cutterSizeX-profile']
                cutterSizeY = args['phantergallery-input-name-cutterSizeY-profile']
                positionX = args['phantergallery-input-name-positionX-profile']
                positionY = args['phantergallery-input-name-positionY-profile']
                newSizeX = args['phantergallery-input-name-newSizeX-profile']
                newSizeY = args['phantergallery-input-name-newSizeY-profile']
                if arquivo.filename != '':
                    imageName = secure_filename(arquivo.filename)
                    imageBytes = arquivo
                    cut_file = PhanterGalleryCutter(
                        imageName=imageName,
                        imageBytes=imageBytes,
                        cutterSizeX=cutterSizeX,
                        cutterSizeY=cutterSizeY,
                        positionX=positionX,
                        positionY=positionY,
                        newSizeX=newSizeX,
                        newSizeY=newSizeY
                    )
                    novo_arquivo = cut_file.getImage()
                    user_image = UserImage(
                        usuario.id, app.config['UPLOAD_FOLDER']
                    )
                    user_image.set_image(
                        novo_arquivo,
                        cut_file.nome_da_imagem,
                        cut_file.extensao
                    )

            if any([email_alterado,
                    usuario_alterado,
                    sobrenome_alterado,
                    imagem_alterada]):
                usuario.send_new_ajax_activation_code()
                usuario.activity(
                    "".join(
                        ["RestUsers: Perfil Atualizado com Sucesso"]
                    )
                )
                usuario.commit()
                usuario = User(id_user=usuario.id)
                user_image = UserImage(usuario.id)
                url_image_user = user_image.url_image
                user_role = "Usuário"
                if usuario.roles:
                    if "administrator" in usuario.roles:
                        user_role = "Administrador"
                    if "root" in usuario.roles:
                        user_role = "Super Administrador"
                user_roles = ["user"]
                if usuario.roles:
                    user_roles = usuario.roles
                    if "user" not in user_roles:
                        user_roles.append("user")
                is_to_remember = usuario.remember_me
                email = Markup.escape(usuario.email)
                first_name = Markup.escape(usuario.first_name)
                last_name = Markup.escape(usuario.last_name)
                username = "%s %s" % (first_name, last_name)
                return {
                    "status": "OK",
                    "message": "Perfil atualizado com sucesso",
                    'change_email': email_alterado,
                    'auth_user': {
                        'id': usuario.id,
                        'user_name': username,
                        'first_name': first_name,
                        'last_name': last_name,
                        'url_image_user': url_image_user,
                        'remember_me': is_to_remember,
                        'role': user_role,
                        'roles': user_roles,
                        'email': email,
                    },
                }
            else:
                return {
                    "status": "ATTENTION",
                    'csrf': csrf_token,
                    "message": "Nada foi alterado!"
                }


class RestAdminGroups(Resource):
    @requires_login(authorized_roles=['root'], defid="RestAdminGroups.get")
    def get(self, *args, **kargs):
        db._adapter.reconnect()
        q_groups = db(db.auth_group.id > 0).select()
        t_groups = db(db.auth_group.id > 0).count()
        fields = {x: db.auth_group[x].label for x in db.auth_group.fields}
        return {
            'status': 'OK',
            'fields': fields,
            'table_length': t_groups,
            'auth_group': [{
                'id': x.id,
                'role': x.role,
                'description': x.description
            } for x in q_groups]
        }

    @requires_login(
        authorized_roles=['root'],
        check_csrf=True,
        intention_csrf="auth_group",
        defid="RestAdminGroups.post")
    def post(self, *args, **kargs):
        csrf_token = kargs['new_csrf_token']
        parser.add_argument('role')
        parser.add_argument('description')
        args = parser.parse_args()
        role = args['role']
        description = args['description']
        validate = ValidateReqArgs(args)
        validate.isNotEmpty("role", "O nome não pode ser vazio.")
        if validate.anyError:
            return {
                'status': 'ERROR',
                'message': 'Erros nos dados enviados!',
                'csrf': csrf_token,
                'validators': validate.validators
            }
        id_auth_group = db.auth_group.insert(role=role,
            description=description)
        if id_auth_group:
            db.commit()
            return {'status': 'OK',
                'message': 'Auth group created',
                'auth_group': {
                    'id': id_auth_group,
                    'role': role,
                    'description': description}}
        else:
            return {'status': 'ERROR',
                'message': 'Erro in edit auth group'}

    @requires_login(
        authorized_roles=['root'],
        check_csrf=True,
        intention_csrf="auth_group",
        defid="RestAdminGroups.put")
    def put(self, *args, **kargs):
        id_auth_group = kargs["id_auth_group"]
        csrf_token = kargs['new_csrf_token']
        parser.add_argument('role')
        parser.add_argument('description')
        args = parser.parse_args()
        role = args['role']
        description = args['description']
        validate = ValidateReqArgs(args)
        validate.isNotEmpty("role", "O nome não pode ser vazio.")
        if validate.anyError:
            return {
                'status': 'ERROR',
                'message': 'Erros nos dados enviados!',
                'csrf': csrf_token,
                'validators': validate.validators
            }
        q_group = db(db.auth_group.id == id_auth_group).select().first()
        if q_group:
            q_group.update_record(role=role,
                description=description)
            db.commit()
            return {'status': 'OK',
                'message': 'Auth group created',
                'auth_group': {'id': id_auth_group,
                    'role': role,
                    'description': description}}
        else:
            return {'status': 'ERROR',
                'message': 'Erro in create auth group'}


class RestAdminImageUser(Resource):
    def get(self, autorization):
        reader_autorization = Serialize(app.config['SECRET_KEY_USERS'])
        has_autorization = False
        try:
            message = reader_autorization.loads(autorization)
            id_user = message['id_user']
            has_autorization = True
        except BadSignature:
            has_autorization = False
        except SignatureExpired:
            has_autorization = False
        if has_autorization:
            usuario = User(id_user=id_user)
            if usuario:
                user_image = UserImage(usuario.id).image
                if user_image:
                    filename = "%s.%s" % (user_image.id, user_image.extensao)
                    folder = os.path.join(app.root_path, user_image.folder)
                    return send_from_directory(folder, filename)
                else:
                    return send_from_directory(
                        os.path.join(app.root_path, "static", "images"),
                        "user.png"
                    )
            else:
                return send_from_directory(
                    os.path.join(app.root_path, "static", "images"),
                    "user.png"
                )
        else:
            return send_from_directory(
                os.path.join(app.root_path, "static", "images"),
                "user.png"
            )


class RestAdminUsers(Resource):
    @requires_login(authorized_roles=['root'], defid="RestAdminUsers.get")
    def get(self, *args, **kargs):
        db._adapter.reconnect()
        if "id_auth_user" in kargs:
            q_user = db(db.auth_user.id == kargs["id_auth_user"]).select().first()
            if q_user:
                pass
        q_auth_group = db(db.auth_group.id > 0).select()
        q_users = db(db.auth_user.id > 0).select()
        t_users = db(db.auth_user.id > 0).count()
        fields = {x: db.auth_user[x].label for x in db.auth_user.fields}
        return {
            'status': 'OK',
            'fields': fields,
            'table_length': t_users,
            'auth_user': [data_auth_user(x) for x in q_users],
            'auth_group': [{
                'id': x.id,
                'role': x.role,
                'description': x.description} for x in q_auth_group]
        }

    @requires_login(
        authorized_roles=['root'],
        check_csrf=True,
        intention_csrf="auth_user",
        defid="RestAdminUsers.put")
    def put(self, *args, **kargs):
        id_auth_user = kargs["id_auth_user"]
        csrf_token = kargs['new_csrf_token']
        parser.add_argument('first_name')
        parser.add_argument('last_name')
        parser.add_argument('email')
        parser.add_argument('remember_me')
        parser.add_argument('attempts_to_login')
        parser.add_argument('datetime_next_attempt_to_login')
        parser.add_argument('temporary_password_expire')
        parser.add_argument('activate_code')
        parser.add_argument('attempts_to_activate')
        parser.add_argument('activate_date_expire')
        parser.add_argument('permit_double_login')
        parser.add_argument('rest_date')
        parser.add_argument('activated')
        parser.add_argument('phantergallery_upload-input-file-auth_user')
        parser.add_argument('phantergallery-input-name-cutterSizeX-auth_user')
        parser.add_argument('phantergallery-input-name-cutterSizeY-auth_user')
        parser.add_argument('phantergallery-input-name-positionX-auth_user')
        parser.add_argument('phantergallery-input-name-positionY-auth_user')
        parser.add_argument('phantergallery-input-name-newSizeX-auth_user')
        parser.add_argument('phantergallery-input-name-newSizeY-auth_user')
        parser.add_argument('chips-groups-auth_user')
        args = parser.parse_args()
        first_name = args['first_name']
        last_name = args['last_name']
        email = args['email']
        remember_me = process_checkbox(args['remember_me'])
        permit_double_login = process_checkbox(args['permit_double_login'])
        attempts_to_login = process_intenger(args['attempts_to_login'])
        activate_code = process_intenger(args['activate_code'])
        attempts_to_activate = process_intenger(args['attempts_to_activate'])
        activated = process_checkbox(args['activated'])
        datetime_next_attempt_to_login = process_datetime(args['datetime_next_attempt_to_login'])
        temporary_password_expire = process_datetime(args['temporary_password_expire'])
        activate_date_expire = process_datetime(args['activate_date_expire'])
        rest_date = process_datetime(args['rest_date'])
        list_groups = [x.id for x in db(db.auth_group).select()]
        chips_groups_auth_user = process_list_string(args['chips-groups-auth_user'])
        validate = ValidateReqArgs(args)
        validate.updateOrInsertArg('chips-groups-auth_user', chips_groups_auth_user)
        validate.isNotEmpty("first_name", "O nome não pode ser vazio.")
        validate.isNotEmpty("last_name", "O sobrenome não pode ser vazio.")
        validate.isEmail("email", "O email é inválido.")
        validate.canIsEmpty("datetime_next_attempt_to_login", empty_values=["__/__/____ __:__:__"])
        validate.canIsEmpty("temporary_password_expire", empty_values=["__/__/____ __:__:__"])
        validate.canIsEmpty("activate_date_expire", empty_values=["__/__/____ __:__:__"])
        validate.canIsEmpty("rest_date", empty_values=["__/__/____ __:__:__"])
        validate.canIsEmpty("chips-groups-auth_user")
        validate.canIsEmpty("attempts_to_login")
        validate.canIsEmpty("attempts_to_activate")
        validate.match('attempts_to_activate', "Intenger", r"^[0-9]{0,2}$", "O valor tem que ser um inteiro")
        validate.match('attempts_to_login', "Intenger1", r"^[0-9]{0,2}$", "O valor tem que ser um inteiro")
        validate.isInSet('chips-groups-auth_user', list_groups, "Não é um grupo válido")
        if validate.anyError:
            return {
                'status': 'ERROR',
                'message': 'Erros nos dados enviados!',
                'csrf': csrf_token,
                'validators': validate.validators
            }
        else:
            q_user = db(db.auth_user.id == id_auth_user).select().first()
            q_user.update_record(
                first_name=first_name,
                last_name=last_name,
                email=email,
                remember_me=remember_me,
                attempts_to_login=attempts_to_login,
                datetime_next_attempt_to_login=datetime_next_attempt_to_login,
                temporary_password_expire=temporary_password_expire,
                activate_code=activate_code,
                attempts_to_activate=attempts_to_activate,
                activate_date_expire=activate_date_expire,
                permit_double_login=permit_double_login,
                rest_date=rest_date,
                activated=activated)
            q_group = db(db.auth_membership.auth_user == id_auth_user).select()
            for x in q_group:
                if x.auth_group in chips_groups_auth_user:
                    pass
                else:
                    x.delete_record()

            for y in chips_groups_auth_user:
                q_group = db(
                    (db.auth_membership.auth_user == id_auth_user) &
                    (db.auth_membership.auth_group == y)).select().first()
                if not q_group:
                    db.auth_membership.insert(auth_user=id_auth_user,
                        auth_group=y)

            if 'phantergallery_upload-input-file-auth_user' in request.files:
                arquivo = request.files['phantergallery_upload-input-file-auth_user']
                cutterSizeX = args['phantergallery-input-name-cutterSizeX-auth_user']
                cutterSizeY = args['phantergallery-input-name-cutterSizeY-auth_user']
                positionX = args['phantergallery-input-name-positionX-auth_user']
                positionY = args['phantergallery-input-name-positionY-auth_user']
                newSizeX = args['phantergallery-input-name-newSizeX-auth_user']
                newSizeY = args['phantergallery-input-name-newSizeY-auth_user']
                if arquivo.filename != '':
                    imageName = secure_filename(arquivo.filename)
                    imageBytes = arquivo
                    cut_file = PhanterGalleryCutter(
                        imageName=imageName,
                        imageBytes=imageBytes,
                        cutterSizeX=cutterSizeX,
                        cutterSizeY=cutterSizeY,
                        positionX=positionX,
                        positionY=positionY,
                        newSizeX=newSizeX,
                        newSizeY=newSizeY
                    )
                    novo_arquivo = cut_file.getImage()
                    user_image = UserImage(
                        id_auth_user, app.config['UPLOAD_FOLDER']
                    )
                    user_image.set_image(
                        novo_arquivo,
                        cut_file.nome_da_imagem,
                        cut_file.extensao
                    )
            db.commit()
            q_user = db(db.auth_user.id == id_auth_user).select().first()
            return {
                'status': 'OK',
                'message': 'Usuário editado com sucesso',
                'auth_user': data_auth_user(q_user)
            }


class RestServerInfo(Resource):

    def get(self):

        nova_data = datetime.now()
        dia = str(nova_data.day).zfill(2)
        mes = str(nova_data.month).zfill(2)
        ano = nova_data.year
        hora = str(nova_data.hour).zfill(2)
        minuto = str(nova_data.minute).zfill(2)
        return {
            'status': 'OK',
            'hora_servidor': "%s/%s/%s %s:%s:00" %
            (dia, mes, ano, hora, minuto),
            'application': {
                'debug': app.debug,
                'application_version': app_version,
                'application_name': app_name
            }
        }


class RestAuthenticater(Resource):
    """
        url: /api/authenticator

    """
    @requires_csrf(intention_csrf="login", defid="RestAuthenticater.post")
    def post(self, *args, **kargs):
        import base64
        parser.add_argument('basic_authorization', location='form')
        parser.add_argument('remember_me', location='form')
        args = parser.parse_args()
        validate = ValidateReqArgs(args)
        basic_authorization = base64.b64decode(args['basic_authorization'])
        basic_authorization_splitted = basic_authorization.decode('utf-8').split(":")
        email = basic_authorization_splitted.pop(0)
        password = ":".join(basic_authorization_splitted)
        remember_me = args['remember_me']
        validate.delArg('basic_authorization')
        validate.updateOrInsertArg("email", email)
        validate.updateOrInsertArg("password", password)
        validate.isNotEmpty("email", "O email não pode ser vazio.")
        validate.isEmail("email", "O email é inválido.")
        validate.isNotEmpty("password", "A senha não pode ser vazia.")
        csrf_token = kargs['new_csrf_token']

        if validate.anyError:
            return {
                'status': 'ERROR',
                'message': 'Erros nos dados enviados!',
                'csrf': csrf_token,
                'validators': validate.validators
            }
        else:
            login_error = ErrorLog()
            if remember_me == "on":
                is_to_remember = True
            else:
                is_to_remember = False
            can_login = False
            usuario = User(email=email)
            tempo_que_falta = timedelta(seconds=0)
            tentativa_login = usuario.attempts_to_login
            data_next_login = usuario.datetime_next_attempt_to_login
            if data_next_login is not None:
                tempo_que_falta = data_next_login - datetime.now()
            if tentativa_login is None:
                usuario.attempts_to_login = 0
                usuario.commit()
                tentativa_login = 0
                can_login = True
            elif tentativa_login > 3 and data_next_login:
                if data_next_login < datetime.now():
                    can_login = True
                else:

                    if tempo_que_falta.seconds < 60:
                        str_tempo = "%s segundos" % (tempo_que_falta.seconds)
                    else:
                        str_tempo = '%s minutos' % (tempo_que_falta.seconds // 60)
                    frameinfo = getframeinfo(currentframe())
                    login_error.error(
                        "".join([
                            "file: %s" % frameinfo.filename,
                            "\nline: %s" % frameinfo.lineno,
                            "\ndef: RestAuthenticater.post",
                            "\nmessage: Tentativa de login sem sucesso (Senha incorreta)",
                            " Aguardando %s para próxima tentativa" % str_tempo
                        ])
                    )
                    return {
                        'status': 'ERROR',
                        'csrf': csrf_token,
                        'message': 'Aguarde %s para próxima tentativa' % (str_tempo),
                    }
            else:
                can_login = True
            mult_temp = tentativa_login - 3
            if can_login:
                try:
                    usuario.attempts_to_login += 1
                except TypeError as e:
                    usuario.attempts_to_login = 0
                usuario.commit()
                tentativa_login += 1
                if usuario.verify_password(password):
                    if (usuario.temporary_password_hash) and (usuario.temporary_password_expire):
                        temporary_password = True
                    else:
                        temporary_password = False
                    usuario.remember_me = is_to_remember
                    if usuario.activated:
                        activated = True
                    else:
                        activated = False
                    token = usuario.token
                    email = usuario.email
                    first_name = usuario.first_name
                    last_name = usuario.last_name
                    user_name = "%s %s" % (first_name, last_name)
                    user_role = "Usuário"
                    if usuario.roles:
                        if "administrator" in usuario.roles:
                            user_role = "Administrador"
                        if "root" in usuario.roles:
                            user_role = "Super Administrador"
                    user_roles = ["user"]
                    if usuario.roles:
                        user_roles = usuario.roles
                        if "user" not in user_roles:
                            user_roles.append("user")
                    user_image = UserImage(usuario.id)
                    url_image_user = user_image.url_image
                    usuario.attempts_to_login = 0
                    usuario.commit()
                    frameinfo = getframeinfo(currentframe())
                    return {
                        'status': 'OK',
                        'token': '%s' % (token.decode('utf-8')),
                        'activated': activated,
                        'temporary_password': temporary_password,
                        'auth_user': {
                            'id': (usuario.id),
                            'email': Markup.escape(email),
                            'user_name': Markup.escape(user_name),
                            'first_name': Markup.escape(first_name),
                            'last_name': Markup.escape(last_name),
                            'url_image_user': url_image_user,
                            'remember_me': is_to_remember,
                            'role': user_role,
                            'roles': user_roles,
                        },
                    }
                else:
                    mult_temp = tentativa_login - 3
                    if tentativa_login > 3:
                        data_next_login = datetime.now() + timedelta(minutes=5 * mult_temp)
                        usuario.datetime_next_attempt_to_login = data_next_login
                        usuario.commit()
                        tempo_que_falta = data_next_login - datetime.now()
                        if tempo_que_falta.seconds < 60:
                            str_tempo = "%s segundos" % (tempo_que_falta.seconds)
                        else:
                            str_tempo = '%s minutos' % (tempo_que_falta.seconds // 60)
                        frameinfo = getframeinfo(currentframe())
                        login_error.error(
                            "".join([
                                "file: %s" % frameinfo.filename,
                                "\nline: %s" % frameinfo.lineno,
                                "\ndef: RestAuthenticater.post",
                                "\nmessage: Tentativa de login sem sucesso (Senha incorreta)",
                                " Aguardando %s para próxima tentativa" % str_tempo
                            ])
                        )
                        return {
                            'status': 'ERROR',
                            'csrf': csrf_token,
                            'message': 'Senha inválida! próxima tentativa em %s' % (str_tempo),
                        }
                    else:
                        if tentativa_login == 3:
                            usuario.datetime_next_attempt_to_login = datetime.now()
                            usuario.commit()
                        frameinfo = getframeinfo(currentframe())
                        login_error.error(
                            "".join([
                                "file: %s" % frameinfo.filename,
                                "\nline: %s" % frameinfo.lineno,
                                "\ndef: RestAuthenticater.post",
                                "\nmessage: Tentativa %s de 3 " % (tentativa_login),
                                "de login sem sucesso (Senha incorreta)"
                            ])
                        )
                        return {
                            'status': 'ERROR',
                            'csrf': csrf_token,
                            'message': 'Senha inválida! Tentativa %s de 3' % tentativa_login
                        }
            else:
                frameinfo = getframeinfo(currentframe())
                login_error.error(
                    "".join([
                        "file: %s" % frameinfo.filename,
                        "\nline: %s" % frameinfo.lineno,
                        "\ndef: RestAuthenticater.post",
                        "\nmessage: Erro inesperado!"
                    ])
                )
                return {'status': 'ERROR', 'message': 'Erro inesperado!'}


api.add_resource(RestApi, '/api')
api.add_resource(RestImageUser, '/api/user/image/<int:id_image>/<autorization>')
api.add_resource(RestActive, '/api/user/active-code')
api.add_resource(RestRequestPassword, '/api/user/request-password')
api.add_resource(RestChangePassword, '/api/user/change-password')
api.add_resource(RestCSRF, '/api/csrf')
api.add_resource(RestCaptcha, '/api/captcha')
api.add_resource(RestUsers, '/api/users')
api.add_resource(RestServerInfo, '/api/server')
api.add_resource(RestAuthenticater, '/api/authenticater')
api.add_resource(RestAdminImageUser, '/api/auth_user/image/<autorization>')
api.add_resource(RestAdminUsers, '/api/admin/users', '/api/admin/users/<id_auth_user>')
api.add_resource(RestAdminGroups, '/api/admin/groups', '/api/admin/groups/<id_auth_group>')
