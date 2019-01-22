# -*- coding: utf-8 -*-
from .. import (
    app,
    api,
    __version__ as app_version,
    __project__ as app_name,
)

from inspect import currentframe, getframeinfo
from ..models import User, CSRF, ErrorLog
from ..models.phantergallery import UserImage
from phanterweb.validators import Validator, ValidateReqArgs
from phanterweb.phantergallery import PhanterGalleryCutter
from phanterweb.captcha import Captcha
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

def requires_login(
    authorized_roles=None,
    check_csrf=False,
    intention_csrf=None,
    defid="requires_login",
    permit_retoken=False
    ):
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
                                'data': None,
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
                                'data': None,
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
                                        "\nmessage: token  válido sendo usado para ",
                                        intention_csrf,
                                        " porém gerado com propósito diferente: ",
                                        proposito
                                    ])
                                )
                                return {
                                    'status': "ERROR",
                                    'authenticated': False,
                                    'data': None,
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
                        'data': None,
                        'roles': ['Anônimo'],
                        'message': 'Usuário não localizado'
                    }
            else:
                if permit_retoken:
                    usuario = User(token=token)
                    if usuario:
                        ultima_data = usuario.rest_date
                        periodo = datetime.now() - ultima_data
                        app.logger.debug(periodo.seconds)
                        if (periodo.seconds > 0) and (periodo.seconds < app.config['DEFAULT_TIME_TOKEN_EXPIRES']):
                            app.logger.debug("veio aqui")
                            new_token = usuario.token
                            usuario = User(token=new_token)
                            if usuario.activated:
                                activated = True
                            else:
                                activated = False
                            user_image = UserImage(usuario.id).image
                            email = Markup.escape(usuario.email)
                            is_to_remember = True if usuario.remember_me else False
                            user_roles = ["user"]
                            if usuario.roles:
                                user_roles = usuario.roles
                                if "user" not in user_roles:
                                    user_roles.append("user")
                            if user_image:
                                reader = Serialize(
                                    app.config['SECRET_KEY_USERS'],
                                    int(timedelta(365).total_seconds())
                                )
                                autorization = reader.dumps(
                                    {'token': new_token.decode('utf-8')}
                                )
                                url_image_user = api.url_for(
                                    RestImageUser,
                                    id_image=user_image.id,
                                    autorization=autorization,
                                    _external=True
                                )
                            else:
                                url_image_user = url_for('static', filename="images/user.png")
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
                                'token': new_token.decode('utf-8'),
                                'data': {
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
                                'data': None,
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
                    'data': None,
                    'roles': ['Anônimo'],
                    'message': 'Token inválido ou expirado, faça login novamente!'
                }

        return f_intern
    return real_decorator

def requires_csrf(
    intention_csrf=None,
    defid="requires_csrf"
    ):
    def real_decorator(f):
        @wraps(f)
        def f_intern(*args, **kargs):
            authorization_error = ErrorLog()
            parser.add_argument('csrf_token', location='form')
            args = parser.parse_args()
            app.logger.debug(args['csrf_token'])
            csrf = CSRF()
            is_valid = csrf.valid_response_token(args['csrf_token'])
            app.logger.debug(is_valid)
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
                app.logger.debug("proposito eh igual a intenção?")
                app.logger.debug(proposito != intention_csrf)
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


class HelloWorld(Resource):
    """
        url: /api
    """
    def get(self):
        parser.add_argument('old_password')
        parser.add_argument('password')
        parser.add_argument('password_repeat')
        parser.add_argument('csrf_token')
        args = parser.parse_args()

        return {'hello': str(dict(args))}


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


class RestLogin(Resource):
    """
        url: /api/login
    """

    def post(self):
        import base64
        parser.add_argument('basic_authorization')
        parser.add_argument('remember_me')
        parser.add_argument('csrf_token')
        args = parser.parse_args()
        basic_authorization = base64.b64decode(args['basic_authorization'])
        basic_authorization_splitted = basic_authorization.decode('utf-8').split(":")
        email = basic_authorization_splitted.pop(0)
        password = ":".join(basic_authorization_splitted)
        csrf_token = args['csrf_token']
        remember_me = args['remember_me']
        app.logger.debug(email)
        app.logger.debug(password)
        valid_email = Validator(email)
        valid_email.isNotEmpty("O email não pode ser vazio.")
        valid_email.isEmail("O email é inválido.")
        valid_password = Validator(password)
        valid_password.isNotEmpty("A senha não pode ser vazia.")
        valid_csrf_token = Validator(csrf_token)
        valid_csrf_token.isNotEmpty("CSRF token inválido.")

        if any([
                valid_email.has_error,
                valid_password.has_error,
                valid_csrf_token.has_error,
        ]):
            return {
                'status': 'ERROR',
                'message': 'Erros nos dados enviados!',
                'validators': {
                    'email': valid_email.error if valid_email.has_error else "OK",
                    'password': valid_password.error if valid_password.has_error else "OK",
                    'csrf_token': valid_csrf_token.error if valid_csrf_token.has_error else "OK",
                }
            }
        else:
            if remember_me == "on":
                is_to_remember = True
            else:
                is_to_remember = False
            csrf = CSRF()
            response_token = csrf.valid_response_token(csrf_token)
            if response_token:
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
                        csrf = CSRF()
                        csrf_token = csrf.token(proposito="Tentativa apos senha errada")
                        if tempo_que_falta.seconds < 60:
                            str_tempo = "%s segundos" % (tempo_que_falta.seconds)
                        else:
                            str_tempo = '%s minutos' % (tempo_que_falta.seconds // 60)
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
                        user_name = "%s %s" % (usuario.first_name, usuario.last_name)
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
                        user_image = UserImage(usuario.id).image
                        if user_image:
                            reader = Serialize(
                                app.config['SECRET_KEY_USERS'], int(timedelta(365).total_seconds())
                            )
                            autorization = reader.dumps(
                                {'token': token.decode('utf-8')}
                            )
                            url_image_user = api.url_for(
                                RestImageUser,
                                id_image=user_image.id,
                                autorization=autorization,
                                _external=True
                            )
                        else:
                            url_image_user = url_for('static', filename="images/user.png")
                        usuario.attempts_to_login = 0
                        usuario.commit()
                        return {
                            'status': 'OK',
                            'id_user': '%s' % (usuario.id),
                            'token': '%s' % (token.decode('utf-8')),
                            'activated': activated,
                            'temporary_password': temporary_password,
                            'csrf': csrf_token,
                            'data_user': {
                                'url_image_user': url_image_user,
                                'user_name': Markup.escape(user_name),
                                'remember_me': is_to_remember,
                                'user_role': user_role,
                                'email': Markup.escape(email),
                            },
                            'info': {
                                'name': Markup.escape(user_name),
                                'first_name': Markup.escape(usuario.first_name),
                                'last_name': Markup.escape(usuario.last_name),
                                'url_image_user': url_image_user,
                                'user_name': Markup.escape(user_name),
                                'remember_me': is_to_remember,
                                'role': user_role,
                                'roles': user_roles,
                                'email': Markup.escape(email),
                            },
                        }
                    else:
                        csrf = CSRF()
                        csrf_token = csrf.token(proposito="Senha Errada")
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
                            return {
                                'status': 'ERROR',
                                'csrf': csrf_token,
                                'message': 'Senha inválida! próxima tentativa em %s' % (str_tempo),
                            }
                        else:
                            if tentativa_login == 3:
                                usuario.datetime_next_attempt_to_login = datetime.now()
                                usuario.commit()
                            return {
                                'status': 'ERROR',
                                'csrf': csrf_token,
                                'message': 'Senha inválida! Tentativa %s de 3' % tentativa_login
                            }
            else:
                return {'status': 'ERROR', 'message': 'Erro no envio!', 'codigo': 'login01'}


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
        if 'usuario' in kargs:
            usuario = kargs['usuario']
            if usuario:
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
            else:
                return {'status': 'ERROR', 'message': 'Usuário ou/e token Inválido(s)!'}
        else:
            return {'status': 'ERROR', 'message': 'Usuário ou/e token Inválido(s)!'}


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


class RestProfile(Resource):
    def get(self):
        token = request.headers.get('Authorization')
        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            id_user = t.loads(token)['id_user']
        except Exception as e:
            id_user = 0

        if id_user:
            usuario = User(id_user=id_user)
            if usuario:
                user_image = UserImage(usuario.id).image
                if user_image:
                    id_image = user_image.id
                else:
                    id_image = None
                return {
                    'status': 'OK',
                    'data_user': {
                        'first_name': Markup.escape(usuario.first_name),
                        'last_name': Markup.escape(usuario.last_name),
                        'email': Markup.escape(usuario.email),
                        'id_image': id_image,
                    }
                }
            else:
                return {'status': 'ERROR', 'message': 'Usuário ou/e token Inválido(s)!'}


class RestPhanterGallery(Resource):
    def get(self, section):
        if section == "profile":
            token = request.headers.get('Autorization')
            id_user = request.headers.get('Autorization-User')
            usuario = User(id_user=id_user)
            user_image = UserImage(usuario.id).image
            if user_image:
                reader = Serialize(
                    app.config['SECRET_KEY_USERS'], int(timedelta(365).total_seconds())
                )
                autorization = reader.dumps({'token': token})
                url_image_user = api.url_for(
                    RestImageUser,
                    id_image=user_image.id,
                    autorization=autorization,
                    _external=True
                )
            else:
                url_image_user = url_for('static', filename="images/user.png")
            return {
                'status': 'OK',
                'data_user': {'url_image_user': url_image_user},
            }


class RestLock(Resource):
    def get(self):
        token = request.headers.get('Authorization')
        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            id_user = t.loads(token)['id_user']
        except Exception as e:
            id_user = 0
        if id_user:
            usuario = User(id_user=id_user)
            if usuario:
                user_name = "%s %s" % (usuario.first_name, usuario.last_name)
                user_role = "Usuário"
                is_to_remember = usuario.remember_me
                csrf = CSRF()
                csrf_token = csrf.token(proposito="lock")
                email = usuario.email
                user_image = UserImage(usuario.id).image
                if user_image:
                    reader = Serialize(
                        app.config['SECRET_KEY_USERS'], int(timedelta(365).total_seconds())
                    )
                    autorization = reader.dumps({'token': token})
                    url_image_user = api.url_for(
                        RestImageUser,
                        id_image=user_image.id,
                        autorization=autorization,
                        _external=True
                    )
                else:
                    url_image_user = url_for('static', filename="images/user.png")
                return {
                    'status': 'OK',
                    'csrf': csrf_token,
                    'data_user': {
                        'url_image_user': url_image_user,
                        'user_name': Markup.escape(user_name),
                        'remember_me': is_to_remember,
                        'user_role': user_role,
                        'email': Markup.escape(email),
                    }
                }
            else:
                return {
                    'status': 'ERROR',
                    'message': 'Conta Expirada!'
                }
        return {
            'status': 'ERROR',
            'message': 'Conta Expirada!'
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

    @requires_login(permit_retoken=True)
    def get(self, *args, **kargs):
        if ('usuario' in kargs) and ('token' in kargs):
            usuario = kargs['usuario']
            token = kargs['token']
            if usuario:
                user_name = Markup.escape("%s %s" % (usuario.first_name, usuario.last_name))
                if usuario.activated:
                    activated = True
                else:
                    activated = False
                user_image = UserImage(usuario.id).image
                email = Markup.escape(usuario.email)
                is_to_remember = True if usuario.remember_me else False
                user_roles = ["user"]
                if usuario.roles:
                    user_roles = usuario.roles
                    if "user" not in user_roles:
                        user_roles.append("user")
                if user_image:
                    reader = Serialize(
                        app.config['SECRET_KEY_USERS'],
                        int(timedelta(365).total_seconds())
                    )
                    autorization = reader.dumps(
                        {'token': token}
                    )
                    url_image_user = api.url_for(
                        RestImageUser,
                        id_image=user_image.id,
                        autorization=autorization,
                        _external=True
                    )
                else:
                    url_image_user = url_for('static', filename="images/user.png")
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
                    'data': {
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
                        'data': {
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
        token = kargs['token']
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
                                "RestProfile: O usuário tentou mudar o email de ",
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
                            'first_name': valid_first_name.error if valid_first_name.has_error else "OK",
                            'last_name': valid_last_name.error if valid_last_name.has_error else "OK",
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
                        ["RestProfile: Perfil Atualizado com Sucesso"]
                    )
                )
                usuario.commit()
                usuario = User(id_user=usuario.id)
                user_image = UserImage(usuario.id).image
                if user_image:
                    reader = Serialize(
                        app.config['SECRET_KEY_USERS'],
                        int(timedelta(365).total_seconds())
                    )
                    autorization = reader.dumps({'token': token})
                    url_image_user = api.url_for(
                        RestImageUser,
                        id_image=user_image.id,
                        autorization=autorization,
                        _external=True
                    )
                else:
                    url_image_user = url_for('static', filename="images/user.png")
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
                    'data': {
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
        app.logger.debug(validate.anyError)
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
                    user_image = UserImage(usuario.id).image
                    if user_image:
                        reader = Serialize(
                            app.config['SECRET_KEY_USERS'], int(timedelta(365).total_seconds())
                        )
                        autorization = reader.dumps(
                            {'token': token.decode('utf-8')}
                        )
                        url_image_user = api.url_for(
                            RestImageUser,
                            id_image=user_image.id,
                            autorization=autorization,
                            _external=True
                        )
                    else:
                        url_image_user = url_for('static', filename="images/user.png")
                    usuario.attempts_to_login = 0
                    usuario.commit()
                    frameinfo = getframeinfo(currentframe())
                    return {
                        'status': 'OK',
                        'token': '%s' % (token.decode('utf-8')),
                        'activated': activated,
                        'temporary_password': temporary_password,
                        'data': {
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


api.add_resource(HelloWorld, '/api')
api.add_resource(RestLogin, '/api/user/login')
api.add_resource(RestProfile, '/api/user/profile')
api.add_resource(RestLock, '/api/user/lock')
api.add_resource(RestImageUser, '/api/user/image/<int:id_image>/<autorization>')
api.add_resource(RestActive, '/api/user/active-code')
api.add_resource(RestRequestPassword, '/api/user/request-password')
api.add_resource(RestChangePassword, '/api/user/change-password')
api.add_resource(RestCSRF, '/api/csrf')
api.add_resource(RestCaptcha, '/api/captcha')
api.add_resource(RestPhanterGallery, '/api/phantergallery/<section>')
api.add_resource(RestUsers, '/api/users')
api.add_resource(RestServerInfo, '/api/server')
api.add_resource(RestAuthenticater, '/api/authenticater')
