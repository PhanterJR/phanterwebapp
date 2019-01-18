# -*- coding: utf-8 -*-
from .. import (
    app,
    api,
    __version__ as app_version,
    __project__ as app_name,
    )
from ..models import User, CSRF
from ..models.phantergallery import UserImage
from phanterweb.validators import Validator
from phanterweb.phantergallery import PhanterGalleryCutter
from phanterweb.captcha import Captcha
from flask import request, url_for, Markup, send_from_directory
from flask_restful import Resource, reqparse
from werkzeug.security import generate_password_hash
from functools import wraps
from werkzeug.utils import secure_filename
from itsdangerous import TimedJSONWebSignatureSerializer as Serialize, BadSignature, SignatureExpired
from datetime import datetime, timedelta
import os

#api = Api(app)
parser = reqparse.RequestParser()
time = app.config['DEFAULT_TIME_TOKEN_EXPIRES']

def check_login_in_rest(f):
    @wraps(f)
    def f_intern(*args, **kargs):
        token = request.headers.get('Autorization')
        id_user = request.headers.get('Autorization-User')
        try:
            id_user=int(id_user)
        except ValueError:
            id_user=0
        except TypeError:
            id_user=0
        usuario = User(id_user=id_user)
        if usuario:
            result_check = usuario.check_token(token)
            app.logger.debug(result_check)
            if result_check:
                return f(*args, **kargs)
            else:
                return {'status':'ERROR', 'message':'Token inválido ou expirado, faça login novamente!'}
        else:
            return {'status':'ERROR', 'message':'Token inválido ou expirado, faça login novamente!'}

    return f_intern

class HelloWorld(Resource):
    def get(self):
        return {'hello': 'world'}

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
            return {'status': 'ERROR',
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
                            str_tempo = "%s segundos" %(tempo_que_falta.seconds)
                        else:
                            str_tempo = '%s minutos' % (tempo_que_falta.seconds//60)
                        return {'status': 'ERROR',
                                'csrf': csrf_token,
                                'message': 'Aguarde %s para próxima tentativa ' % (str_tempo),
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
                            if not "user" in user_roles:
                                user_roles.append("user")
                        user_image = UserImage(usuario.id).image
                        if user_image:
                            reader = Serialize(app.config['SECRET_KEY_USERS'], int(timedelta(365).total_seconds()))
                            autorization = reader.dumps({'token':token.decode('utf-8')})
                            url_image_user = api.url_for(RestImageUser,
                                id_image=user_image.id,
                                autorization=autorization,
                                _external=True)
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
                                'url_image_user' : url_image_user,
                                'user_name': Markup.escape(user_name),
                                'remember_me': is_to_remember,
                                'user_role': user_role,
                                'email': Markup.escape(email),
                            },
                            'info':{
                                'name':Markup.escape(user_name),
                                'first_name':Markup.escape(usuario.first_name),
                                'last_name':Markup.escape(usuario.last_name),
                                'url_image_user': url_image_user,
                                'user_name': Markup.escape(user_name),
                                'remember_me': is_to_remember,
                                'roles': user_roles,
                                'email': Markup.escape(email),
                            },
                        }
                    else:
                        csrf = CSRF()
                        csrf_token = csrf.token(proposito="Senha Errada")
                        mult_temp = tentativa_login - 3
                        if tentativa_login > 3:
                            data_next_login = datetime.now() + timedelta(minutes=5*mult_temp)
                            usuario.datetime_next_attempt_to_login = data_next_login 
                            usuario.commit()
                            tempo_que_falta = data_next_login - datetime.now()  
                            if tempo_que_falta.seconds < 60:
                                str_tempo = "%s segundos" %(tempo_que_falta.seconds)
                            else:
                                str_tempo = '%s minutos' % (tempo_que_falta.seconds//60)
                            return {'status': 'ERROR',
                                'csrf': csrf_token,
                                'message': 'Senha inválida! próxima tentativa em %s' % (str_tempo),
                            }
                        else:
                            if tentativa_login == 3:
                                usuario.datetime_next_attempt_to_login = datetime.now()
                                usuario.commit()
                            return {'status': 'ERROR',
                                    'csrf': csrf_token,
                                    'message': 'Senha inválida! Tentativa %s de 3' %tentativa_login}
            else:
                return {'status': 'ERROR', 'message': 'Erro no envio!', 'codigo':'login01'}

    @check_login_in_rest
    def get(self):
        token = request.headers.get('Autorization')
        id_user = request.headers.get('Autorization-User')
        usuario = User(id_user=id_user)
        user_name = Markup.escape("%s %s" %(usuario.first_name, usuario.last_name))
        if usuario.activated:
            activated = True
        else:
            activated = False
        user_image = UserImage(usuario.id).image
        email = Markup.escape(usuario.email)
        is_to_remember = True if usuario.remember_me else False
        user_role = "Usuário"
        if user_image:
            reader = Serialize(app.config['SECRET_KEY_USERS'], int(timedelta(365).total_seconds()))
            autorization = reader.dumps({'token':token})
            url_image_user = api.url_for(RestImageUser,
                id_image=user_image.id,
                autorization=autorization,
                _external=True)
        else:
            url_image_user = url_for('static', filename="images/user.png")

        return {'status':'OK',
                        #'html':html,
                        'data_user':{
                            'name':user_name,
                            'url_image_user': url_image_user,
                            'user_name': user_name,
                            'remember_me': is_to_remember,
                            'user_role': user_role,
                            'email': email,
                        },
                        'activated':activated}
        #     else:
        #         return {'status':'ERROR', 'message':'Token inválido ou expirado, faça login novamente!'}
        # else:
        #     {'status':'ERROR', 'message':'Token inválido ou expirado, faça login novamente!'}


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


class RestRegister(Resource):
    def post(self):
        parser.add_argument('first_name')
        parser.add_argument('last_name')
        parser.add_argument('email')
        parser.add_argument('password')
        parser.add_argument('password_repeat')
        parser.add_argument('csrf_token')
        args = parser.parse_args()
        first_name = args['first_name']
        last_name = args['last_name']
        email = args['email']
        password = args['password']
        password_repeat = args['password_repeat']
        csrf_token = args['csrf_token']
        valid_first_name = Validator(first_name)
        valid_last_name = Validator(last_name)
        valid_email = Validator(email)
        valid_password = Validator(password)
        valid_csrf_token = Validator(csrf_token)
        valid_password_repeat = Validator(password_repeat)
        valid_first_name.isNotEmpty("O nome não pode ser vazio.")
        valid_last_name.isNotEmpty("O sobrenome não pode ser vazio.")
        valid_email.isEmail("O email é inválido.")
        valid_password.isEquals(password_repeat, "As senhas não coincidem.")
        valid_password.isNotEmpty("A senha não pode ser vazia.")
        valid_password_repeat.isEquals(password, "As senhas não coincidem.")
        valid_password_repeat.isNotEmpty("O campo não pode ser vazio.")
        valid_csrf_token.isNotEmpty("CSRF token inválido.")
        if any([
            valid_first_name.has_error,
            valid_last_name.has_error,
            valid_email.has_error,
            valid_password.has_error,
            valid_password_repeat.has_error,
            valid_csrf_token.has_error
        ]):
            return {'status': 'ERROR',
                    'message': 'Erros nos dados enviados!',
                    'validators': {
                        'first_name': valid_first_name.error if valid_first_name.has_error else "OK",
                        'last_name': valid_last_name.error if valid_last_name.has_error else "OK",
                        'email': valid_email.error if valid_email.has_error else "OK",
                        'password': valid_password.error if valid_password.has_error else "OK",
                        'password_repeat': valid_password_repeat.error if valid_password_repeat.has_error else "OK",
                        'csrf_token': valid_csrf_token.error if valid_csrf_token.has_error else "OK",
                    }
                }
        else:
            csrf = CSRF()
            response_token = csrf.valid_response_token(csrf_token)
            if response_token:
                usuario_existe = User(email=email)
                if usuario_existe:
                    return {
                        'status': 'ERROR',
                        'message': 'Já existe uma conta com este email.',
                    }
                else:
                    new_user = User()
                    new_user.register_ajax(first_name, last_name, email, password)
                    url_image_user = url_for('static', filename="images/user.png")
                    if new_user:
                        return {
                            'status': 'OK',
                            'id_user': '%s' % (new_user.id),
                            'token': '%s' % (new_user.token.decode('utf-8')),
                            'message': 'Conta criada com sucesso!',
                            'data_user': {
                                'url_image_user' : url_image_user,
                                'user_name': Markup.escape("%s %s" %(first_name, last_name)),
                                'remember_me': False,
                                'user_role': "Usuário",
                                'email': Markup.escape(email),
                            }
                        }
                    else:
                        return {
                            'status': 'ERROR',
                            'message': 'Já existe uma conta com este email.',
                        }
            else:
                return {'status': 'ERROR', 'message': 'Erro no envio!'}


class RestActive(Resource):
    def post(self):
        token = request.headers.get('Authorization')
        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            id_user = t.loads(token)['id_user']
        except:
            id_user = 0

        parser.add_argument('code')
        args = parser.parse_args()
        code = args['code']
        try:
            code = int(code)
        except Exception as e:
            return {'status': 'ERROR', 'message': 'Código Inválido!'}
        if id_user:
            usuario = User(id_user=id_user)
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


class RestGetNewActiveCode(Resource):
    def get(self):
        token = request.headers.get('Autorization')
        id_user = request.headers.get('Autorization-User')
        try:
            id_user = int(id_user)
        except ValueError:
            id_user = 0
        usuario = User(id_user=id_user)
        if usuario:
            if usuario.check_token(token):
                if usuario.activate_date_expire:
                    data_code = (usuario.activate_date_expire + timedelta(minutes=5)) - timedelta(hours=12)
                    now = datetime.now()
                    if now < data_code:
                        return {'status': 'ERROR', 'message': 'Aguarde alguns minutos para nova tentativa!'}
                    else:
                        usuario.send_new_ajax_activation_code()
                        return {'status': 'OK', 'message': 'Código Enviado!'}
                else:
                    usuario.send_new_ajax_activation_code()
                    return {'status': 'OK', 'message': 'Código Enviado!'}


class RestRequestPassword(Resource):
    def post(self):
        parser.add_argument('csrf_token')
        parser.add_argument('email')
        args = parser.parse_args()
        email = args['email']
        csrf_token = args['csrf_token']
        valid_email = Validator(email)
        valid_csrf_token = Validator(csrf_token)
        valid_email.isEmail("O email é inválido.")
        valid_csrf_token.isNotEmpty("CSRF token inválido.")
        if any([
            valid_email.has_error,
            valid_csrf_token.has_error
        ]):
            return {'status': 'ERROR',
                    'message': 'Erros nos dados enviados!',
                    'validators': {
                        'email': valid_email.error if valid_email.has_error else "OK",
                        'csrf_token': valid_csrf_token.error if valid_csrf_token.has_error else "OK",
                    }
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
                        return {'status': 'OK', 'message': 'senha enviada para o email'}
                    else:
                        return {'status': 'ERROR', 'message': 'Aguarde alguns minutos para uma nova solicitação!'}
                else:
                    usuario.send_temporary_password()
                    return {'status': 'OK', 'message': 'senha enviada para o email'}
            else:
                return {'status': 'ERROR', 'message': 'Não há conta com este email!'}


class RestProfile(Resource):
    def get(self):
        token = request.headers.get('Authorization')
        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            id_user = t.loads(token)['id_user']
        except:
            id_user = 0

        if id_user:
            usuario = User(id_user=id_user)
            if usuario:
                user_image = UserImage(usuario.id).image
                if user_image:
                    id_image = user_image.id
                else:
                    id_image = 'null'
                return {
                    'status': 'OK',
                    'data_user': {
                        'first_name': Markup.escape(usuario.first_name),
                        'last_name': Markup.escape(usuario.last_name),
                        'email': Markup.escape(usuario.email),
                        'id_image': id_image,
                    },
                }
            else:
                return {'status': 'ERROR', 'message': 'Usuário ou/e token Inválido(s)!'}

    def post(self):
        token = request.headers.get('Authorization')
        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            id_user = t.loads(token)['id_user']
        except:
            id_user = 0
        if id_user:
            usuario = User(id_user=id_user)
            if usuario:
                parser.add_argument('csrf_token')
                parser.add_argument('email')
                parser.add_argument('first_name')
                parser.add_argument('last_name')
                parser.add_argument('email')
                parser.add_argument('phantergallery_upload-input-file-profile')
                parser.add_argument('phantergallery-input-name-cutterSizeX-profile')
                parser.add_argument('phantergallery-input-name-cutterSizeY-profile')
                parser.add_argument('phantergallery-input-name-positionX-profile')
                parser.add_argument('phantergallery-input-name-positionY-profile')
                parser.add_argument('phantergallery-input-name-newSizeX-profile')
                parser.add_argument('phantergallery-input-name-newSizeY-profile')
                args = parser.parse_args()

                csrf_token = args['csrf_token']
                first_name = args['first_name']
                last_name = args['last_name']
                new_email = args['email']
                valid_first_name = Validator(first_name)
                valid_last_name = Validator(last_name)
                valid_email = Validator(new_email)
                valid_csrf_token = Validator(csrf_token)
                valid_first_name.isNotEmpty("O nome não pode ser vazio.")
                valid_last_name.isNotEmpty("O sobrenome não pode ser vazio.")
                valid_csrf_token.isNotEmpty("O csrf_token não pode ser vazio.")
                valid_email.isEmail("O email é inválido.")
                if any([
                    valid_first_name.has_error,
                    valid_last_name.has_error,
                    valid_email.has_error,
                    valid_csrf_token.has_error
                    ]):
                    return {'status': 'ERROR',
                            'message': 'Erros nos dados enviados!',
                            'validators': {
                                'first_name': valid_first_name.error if valid_first_name.has_error else "OK",
                                'last_name': valid_last_name.error if valid_last_name.has_error else "OK",
                                'email': valid_email.error if valid_email.has_error else "OK",
                                'csrf_token': valid_csrf_token.has_error if valid_csrf_token.has_error else "OK",
                                }
                            }
                else:
                    csrf = CSRF()
                    response_token = csrf.valid_response_token(csrf_token)
                    if response_token:
                        email_now = usuario.email
                        email_alterado = False
                        usuario_alterado = False
                        sobrenome_alterado = False
                        imagem_alterada = False
                        if new_email!=email_now:
                            check_email = User(email=new_email)
                            if check_email:
                                csrf = CSRF()
                                csrf_token = csrf.token(proposito="mudar profile apos email existir")
                                usuario.activity("".join(["RestProfile: O usuário tentou mudar o email de ",
                                    email_now, " para ", new_email," sem sucesso, o email já está cadastrado"]))
                                return {'status': 'ERROR',
                                        'csrf':csrf_token,
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
                                
                        if(first_name!=usuario.first_name):
                            usuario.first_name = first_name
                            usuario_alterado = True
                        if(last_name!=usuario.last_name):
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
                                cut_file = PhanterGalleryCutter(imageName=imageName,
                                    imageBytes=imageBytes,
                                    cutterSizeX=cutterSizeX,
                                    cutterSizeY=cutterSizeY,
                                    positionX=positionX,
                                    positionY=positionY,
                                    newSizeX=newSizeX,
                                    newSizeY=newSizeY)
                                novo_arquivo = cut_file.getImage()
                                user_image = UserImage(usuario.id, app.config['UPLOAD_FOLDER'])
                                user_image.set_image(novo_arquivo,
                                                            cut_file.nome_da_imagem,
                                                            cut_file.extensao)

                        if any([email_alterado,
                                usuario_alterado,
                                sobrenome_alterado,
                                imagem_alterada]):
                            usuario.send_new_ajax_activation_code()
                            usuario.activity("".join(["RestProfile: Perfil Atualizado com Sucesso"]))
                            usuario.commit()
                            return {"status": "OK", "message": "Perfil atualizado com sucesso", 'change_email': email_alterado}
                        else:
                            csrf = CSRF()
                            csrf_token = csrf.token(proposito="mudar profile sel alteracao")
                            return {"status": "ATTENTION", 'csrf':csrf_token, "message": "Nada foi alterado!"}
                    else:
                        csrf = CSRF()
                        csrf_token = csrf.token(proposito="mudar profile apos Token CSFR Inválido")
                        usuario.activity("".join(["RestProfile: Token CSFR Inválido"]))
                        return {'status': 'ERROR', 'csrf': csrf_token, 'message': 'Token CSFR Inválido ou Expirado!'} 
            else:
                return {'status': 'ERROR', 'message': 'Usuário Inválido!'} 
        else:
            return {'status': 'ERROR', 'message': 'Problemas ao alterar o perfil!'}


class RestPhanterGallery(Resource):
    def get(self, section):
        if section == "profile":
            token = request.headers.get('Autorization')
            id_user = request.headers.get('Autorization-User')
            usuario = User(id_user=id_user)
            user_image = UserImage(usuario.id).image
            if user_image:
                reader = Serialize(app.config['SECRET_KEY_USERS'], int(timedelta(365).total_seconds()))
                autorization = reader.dumps({'token':token})
                url_image_user = api.url_for(RestImageUser,
                    id_image=user_image.id,
                    autorization=autorization,
                    _external=True)
            else:
                url_image_user = url_for('static', filename="images/user.png")
            return {
                'status':'OK', 
                'data_user': {'url_image_user': url_image_user},
                }


class RestLock(Resource):
    def get(self):
        token = request.headers.get('Authorization')
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
                reader = Serialize(app.config['SECRET_KEY_USERS'], int(timedelta(365).total_seconds()))
                autorization = reader.dumps({'token':token})
                url_image_user = api.url_for(RestImageUser,
                    id_image=user_image.id,
                    autorization=autorization,
                    _external=True)
            else:
                url_image_user = url_for('static', filename="images/user.png")
            return {'status':'OK', 
                    'csrf': csrf_token,
                    'data_user': {
                        'url_image_user' : url_image_user,
                        'user_name': Markup.escape(user_name),
                        'remember_me': is_to_remember,
                        'user_role': user_role,
                        'email': Markup.escape(email),
                    }
                }
        else:
            return {'status': 'ERROR', 'message':'Conta Expirada!'}


class RestChangePassword(Resource):
    def get(self):
        token = request.headers.get('Authorization')
        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            id_user = t.loads(token)['id_user']
        except:
            id_user = 0

        if id_user:
            usuario = User(id_user=id_user)
            if usuario:
                csrf = CSRF()
                csrf_token = csrf.token(proposito="change_password")
                temporary_password = False
                if (usuario.temporary_password_hash) and (usuario.temporary_password_expire):
                    if datetime.now()<usuario.temporary_password_expire:
                        temporary_password = True
                return {
                    'status': 'OK',
                    'csrf': csrf_token,
                    'temporary_password':temporary_password
                }
            else:
                return {'status': 'ERROR', 'message': 'Usuário ou/e token Inválido(s)!'}
        else:
            return {'status': 'ERROR', 'message': 'Usuário ou/e token Inválido(s)!'}

    def post(self):
        parser.add_argument('old_password')
        parser.add_argument('password')
        parser.add_argument('password_repeat')
        parser.add_argument('csrf_token')
        args = parser.parse_args()
        old_password = args['old_password']
        password = args['password']
        password_repeat = args['password_repeat']
        csrf_token = args['csrf_token']
        token = request.headers.get('Authorization')
        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            id_user = t.loads(token)['id_user']
        except:
            id_user = 0
        app.logger.debug(id_user)
        if id_user:
            usuario = User(id_user=id_user)
            if usuario:
                valid_old_password = Validator(old_password)
                valid_password = Validator(password)
                valid_password_repeat = Validator(password_repeat)
                valid_csrf_token = Validator(csrf_token)
                valid_old_password.isNotEmpty("A senha não pode ser vazia.")
                valid_password.isEquals(password_repeat, "As senhas não coincidem.")
                valid_password.isNotEmpty("A senha não pode ser vazia.")
                valid_password_repeat.isEquals(password, "As senhas não coincidem.")
                valid_password_repeat.isNotEmpty("O campo não pode ser vazio.")
                valid_csrf_token.isNotEmpty("CSRF token inválido.")
                if any([
                        valid_old_password.has_error,
                        valid_password.has_error,
                        valid_password_repeat.has_error,
                        valid_csrf_token.has_error
                    ]):
                    csrf = CSRF()
                    csrf_token = csrf.token(proposito="tentativa após erro")
                    return {'status': 'ERROR',
                            'message': 'Erros nos dados enviados!',
                            'csrf':csrf_token,
                            'validators': {
                                'old_password': valid_old_password.error if valid_old_password.has_error else "OK",
                                'password': valid_password.error if valid_password.has_error else "OK",
                                'valid_password_repeat': valid_password_repeat.error if valid_password_repeat.has_error else "OK",
                                'csrf_token': valid_csrf_token.error if valid_csrf_token.has_error else "OK",
                            }
                        }
                else:
                    csrf = CSRF()
                    response_token = csrf.valid_response_token(csrf_token)
                    if response_token:
                        if usuario.verify_password(old_password):
                            usuario.new_password(password)
                            return{'status':"OK", 'message':"Senha alterada com sucesso!"}
                        else:
                            csrf_token = csrf.token(proposito="tentativa após erro: token inválido")
                            usuario.activity("RestChangePassword: A senha antiga é inválida")
                            return {'status': 'ERROR', 'message': 'Senha antiga inválida!', 'csrf':csrf_token}
                    else:
                        csrf_token = csrf.token(proposito="tentativa após erro: token inválido")
                        usuario.activity("RestChangePassword: 'csrf_token' inválido")
                        return {'status': 'ERROR', 'message': 'Erro no envio!', 'csrf':csrf_token}

            else:
                csrf = CSRF()
                csrf_token = csrf.token(proposito="tentativa após erro: usuário inválido")
                usuario.activity("RestChangePassword: usuário inválido")
                return {'status': 'ERROR', 'message': 'Usuário Inválido',
                            'csrf':csrf_token}
        else:
            return {'status':'ERROR', 'message':"Problemas ao tentar modificar senha!"}
                        

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
        except:
            id_user = 0

        if has_autorization:
            usuario = User(id_user=id_user)
            if usuario:
                user_image = UserImage(usuario.id).image
                if user_image:
                    filename = "%s.%s" %(user_image.id, user_image.extensao)
                    folder = os.path.join(app.root_path, user_image.folder)
                    return send_from_directory(folder, filename)
                    # return send_from_directory(folder,
                    #                    filename, as_attachment=True, attachment_filename=user_image.filename)
                else:
                    return send_from_directory(os.path.join(app.root_path, "static", "images"),
                                       "user.png")                 
            else:
                return send_from_directory(os.path.join(app.root_path, "static", "images"),
                                   "user.png")
        else:
            return send_from_directory(os.path.join(app.root_path, "static", "images"),
                           "user.png")


class RestUserInfo(Resource):
    def get(self):
        token = request.headers.get('Authorization')
        t = Serialize(app.config['SECRET_KEY_USERS'], app.config['DEFAULT_TIME_TOKEN_EXPIRES'])
        try:
            id_user = t.loads(token)['id_user']
        except:
            id_user = 0

        if id_user:
            usuario = User(id_user=id_user)
            if usuario:
                user_name = Markup.escape("%s %s" %(usuario.first_name, usuario.last_name))
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
                    if not "user" in user_roles:
                        user_roles.append("user")
                if user_image:
                    reader = Serialize(app.config['SECRET_KEY_USERS'], int(timedelta(365).total_seconds()))
                    autorization = reader.dumps({'token':token})
                    url_image_user = api.url_for(RestImageUser,
                        id_image=user_image.id,
                        autorization=autorization,
                        _external=True)
                else:
                    url_image_user = url_for('static', filename="images/user.png")

                return {'status':'OK',
                        'authenticated':True,
                        'info':{
                            'name':user_name,
                            'first_name':usuario.first_name,
                            'last_name':usuario.last_name,
                            'url_image_user': url_image_user,
                            'user_name': user_name,
                            'remember_me': is_to_remember,
                            'roles': user_roles,
                            'email': email,
                        },
                        'activated':activated}
        return {'status':'OK',
                'authenticated':False,
                'info':None,
                'roles':['Anônimo']}



class RestServerInfo(Resource):

    def get(self):

        nova_data = datetime.now()
        dia = str(nova_data.day).zfill(2)
        mes = str(nova_data.month).zfill(2)
        ano = nova_data.year
        hora = str(nova_data.hour).zfill(2)
        minuto = str(nova_data.minute).zfill(2)
        return {'status':'OK',
                'hora_servidor':"%s/%s/%s %s:%s:00" %(dia, mes, ano, hora, minuto),
                'application':{'debug':app.debug,
                                'application_version': app_version,
                                'application_name': app_name
                                }
                }

api.add_resource(HelloWorld, '/api')
api.add_resource(RestLogin, '/api/user/login')
api.add_resource(RestRegister, '/api/user/register')
api.add_resource(RestProfile, '/api/user/profile')
api.add_resource(RestLock, '/api/user/lock')
api.add_resource(RestImageUser, '/api/user/image/<int:id_image>/<autorization>')
api.add_resource(RestActive, '/api/user/active-code')
api.add_resource(RestGetNewActiveCode, '/api/user/get-active-code')
api.add_resource(RestRequestPassword, '/api/user/request-password')
api.add_resource(RestChangePassword, '/api/user/change-password')
api.add_resource(RestCSRF, '/api/csrf')
api.add_resource(RestCaptcha, '/api/captcha')
api.add_resource(RestPhanterGallery, '/api/phantergallery/<section>')
api.add_resource(RestUserInfo, '/api/user/info')
api.add_resource(RestServerInfo, '/api/server')
