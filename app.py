from flask import Flask, request, jsonify, make_response, render_template, Response
import jwt
from functools import wraps
from datetime import datetime, timedelta
import cryptocode

from json import loads, dumps

from flask_sqlalchemy import SQLAlchemy
from flask_user import UserManager
from flask_login import UserMixin

import secrets

SUPERMEGASECRET = "DJASDNJasJHDASHJIFH2j4h3J$HJ@NCHJKW" # Secret
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 5
REF_EXP_DELTA_SECONDS = 9900

app = Flask(__name__, static_folder='')
app.config['SQLALCHEMY_DATABASE_URI'] = ''
app.config['USER_EMAIL_SENDER_EMAIL'] = 'test@test.com'
app.config['SECRET_KEY'] = 'a'
db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), nullable=False, unique=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

    active = db.Column(db.Boolean()),
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)

    resfresh_token = db.Column(db.String(255), nullable=True)

    def match_password(self, password):
        if password == self.password:
            return True
        return False

class JWT(db.Model):
    __tablename__ = 'keys'

    kid = db.Column(db.String(255), nullable=False, primary_key=True)
    secret = db.Column(db.String(255), nullable=False)
    jwt = db.Column(db.String(255), nullable=True)


user_manager = UserManager(app, db, User)
db.create_all()

def auth_middleware():
    def middleware(f):
        @wraps(f)
        def _middleware(*args, **kwargs):
            request.user = None
            jwt_token = request.cookies.get('token')

            if not(jwt_token):
                return jsonify({'message': 'Login first!'})

            try:
                jwt_token = cryptocode.decrypt(jwt_token, SUPERMEGASECRET)
            except:
                return jsonify({'message': 'Invalid token!'})

            kid = jwt.get_unverified_header(jwt_token)['kid']
            print('KID', kid)

            try:
                secret = JWT.query.filter_by(kid=kid).first().secret
            except Exception as e:
                print('1', e)
                return jsonify({'message': 'Kid is invalid'})

            if jwt_token:
                try:
                    payload = jwt.decode(jwt_token, secret,
                                        algorithms=[JWT_ALGORITHM])

                except jwt.ExpiredSignatureError:
                    refresh_token = request.cookies.get('ref_token')

                    try:
                        refresh_token = cryptocode.decrypt(refresh_token, SUPERMEGASECRET)
                    except:
                        return jsonify({'message': 'Invalid refresh token!'})


                    try:
                        ref_kid = jwt.get_unverified_header(refresh_token)['kid']

                        try:
                            secret = JWT.query.filter_by(kid=ref_kid).first().secret
                        except Exception as e:
                            print('2', e)
                            return jsonify({'message': 'Ref kid is invalid'})

                        payload = jwt.decode(refresh_token, secret, algorithms=[JWT_ALGORITHM])

                    except jwt.ExpiredSignatureError:
                        return jsonify({'message': 'Token is invalid'})

                    request.user = User.query.filter_by(id=payload['user_id']).first()

                    token = create_access_token(request.user)
                    refresh = create_access_token(request.user, refresh=True)

                    r = f(*args, **kwargs)
                    r.set_cookie('token', cryptocode.encrypt(token.decode('utf-8'), SUPERMEGASECRET))

                    expire_date = datetime.now()
                    expire_date = expire_date + timedelta(seconds=REF_EXP_DELTA_SECONDS)

                    r.set_cookie('ref_token', cryptocode.encrypt(refresh.decode('utf-8'), SUPERMEGASECRET), expires=expire_date)

                    return r

                except Exception as e:
                    print(e)
                    return jsonify({'message': 'Token is invalid'})

                request.user = User.query.filter_by(id=payload['user_id']).first()
                print(request.user.email)

                return f(*args, **kwargs)

        return _middleware

    return middleware

@app.route('/')
def login_page():
    return app.send_static_file('template.html')

@app.route('/api/login', methods=["POST"])
def login():
    print(request.data)
    post_data = loads(request.data.decode('utf-8'))

    try:
        user = User.query.filter_by(email=post_data['email']).first()
        if not(user.match_password(post_data['password'])):
            return jsonify({'message': 'Wrong credentials'})

    except Exception as e:
        print(e)
        return jsonify({'message': 'Wrong credentials'})

    jwt_token = create_access_token(user)
    refresh = create_access_token(user, True, jwt_token)

    r = jsonify({'status': 1})
    r.set_cookie('token', cryptocode.encrypt(jwt_token.decode('utf-8'), SUPERMEGASECRET))

    expire_date = datetime.now()
    expire_date = expire_date + timedelta(seconds=REF_EXP_DELTA_SECONDS)

    r.set_cookie('ref_token', cryptocode.encrypt(refresh.decode('utf-8'), SUPERMEGASECRET), expires=expire_date)

    return r

def get_user():
    return request.user.id

@app.route('/api/resfresh_token')
@auth_middleware()
def refresh_token():
    user = get_user()
    jwt_token = create_access_token(user)

def create_access_token(user, refresh=False, token=None):
    if refresh:
        payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(seconds=REF_EXP_DELTA_SECONDS)
    }

    else:
        payload = {
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS),
        }

    JWT_SECRET = secrets.token_urlsafe(32)
    KID = secrets.token_urlsafe(16)

    jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM, headers={'kid': KID})
    db.session.add(JWT(kid=KID, secret=JWT_SECRET, jwt=jwt_token if jwt_token else None))
    db.session.commit()

    print(jwt_token, JWT_SECRET)
    return jwt_token

def delete_auth_token():
    token = request.cookies.get('token')

    try:
        token = cryptocode.decrypt(token, SUPERMEGASECRET)
    except:
        return jsonify({'message': 'Invalid token!'})

    tkid = jwt.get_unverified_header(token)['kid']

    ref_token = request.cookies.get('ref_token')

    try:
        ref_token = cryptocode.decrypt(ref_token, SUPERMEGASECRET)
    except:
        return jsonify({'message': 'Invalid ref token!'})

    rkid = jwt.get_unverified_header(ref_token)['kid']

    JWT.query.filter_by(kid=tkid).delete()
    JWT.query.filter_by(kid=rkid).delete()

    db.session.commit()

@app.route('/api/logout', methods=["POST"])
@auth_middleware()
def logout():
    delete_auth_token()

    r = jsonify({'status': 1})
    r.delete_cookie('token')
    r.delete_cookie('ref_token')

    return r

@app.route('/supersecret', methods=["GET", "POST"])
@auth_middleware()
def supersecret():

    return jsonify({'status': 1, 'message': f'<div class="app-content"><div class="app-conent-label"> Здравствуйте, {request.user.username}</br>Вы авторизовались, поэтому посмотрите на эти фотографии лаванды</div><div class="app-conent-images"><img src="static/AAAcy1fE6Ru2V-VpCWIeedbgKKOg0VFPSmn7GR4bkGWCA0zyMdVHk0ZtAaxip2zmTBJsuR2QWxYDrBvIIgOlQDt4Q4k.jpg"/><img src="static/FLFeJM7Tz5aWsF67GCCHAYMrA7gOWpvBukdabbxT.webp"/></div></div><input type="button" class="btn-logout app-login-btn" value="Выйти" ng-click="logout()" />',})
