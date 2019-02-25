import os
from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = '1550857495'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL','sqlite:////home/sam/setBooks/setbooks.db')


db = SQLAlchemy(app)

#region models

class User(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Langauge(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    langauge = db.Column(db.String(50))
    user_id = db.Column(db.Integer)

class setBook(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    bkname = db.Column(db.String(50))
    author = db.Column(db.String(50))
    user_id = db.Column(db.Integer)
    lang_id = db.Column(db.Integer)

#end region models

#begin decorator region

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token,app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user,*args, **kwargs)

    return decorated

#end region decorator

#begin user region
#method gets all user.action limted to admin users
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})
    
    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

#method gets one user whose public id is supplied. action limted to admin users
@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user Found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

#method createds new users.action limted to admin users
@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New User created successfully!'})

#method used to promote a user to an admin level.action limted to admin users
@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user Found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

#method used to delete a user, whose public id is passed.action limted to admin users
@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user Found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

# end user region

#region languages
#method used to get all languages.can be performed by any user
@app.route('/language', methods=['GET'])
@token_required
def get_all_langauges(self):
    langs = Langauge.query.all()

    output = []

    for lang in langs:
        lang_data = {}
        lang_data['id'] = lang.id
        lang_data['langauge'] = lang.langauge
        output.append(lang_data)

    return jsonify({'Langauges' : output})

#method used to get one language when language id is passed.can be performed by any user
@app.route('/language/<lang_id>', methods=['GET'])
@token_required
def get_one_language(self,lang_id):


    language = Langauge.query.filter_by(id=lang_id).first()

    if not language:
        return jsonify({'message' : 'No language Found!'})

    language_data = {}
    language_data['id'] = language.id
    language_data['langauge'] = language.langauge


    return jsonify({'language' : language_data})

#methods used to create languages.action limted to admin users
@app.route('/language', methods=['POST'])
@token_required
def create_language(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()


    new_language = Langauge(langauge=data['langauge'], user_id=current_user.id)
    db.session.add(new_language)
    db.session.commit()

    return jsonify({'message' : 'New Langauge created successfully!'})

#method used to delete a language.action limted to admin users
@app.route('/language/<lang_id>',methods=['DELETE'])
@token_required
def delete_language(current_user, lang_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    language = Langauge.query.filter_by(id=lang_id).first()

    if not language:
        return jsonify({'message' : 'No language Found!'})

    db.session.delete(language)
    db.session.commit()

    return jsonify({'message' : 'The language has been deleted!'})

#end region

#region setbooks

#this method gets all  set books beloging to a language, language id is passed
@app.route('/setbook/<lang_id>', methods=['GET'])
@token_required
def get_all_setbook(self, lang_id):
    books = setBook.query.filter_by(lang_id=lang_id)


    output = []

    for book in books:
        book_data = {}
        book_data['id'] = book.id
        book_data['lang_id'] = book.lang_id
        book_data['bkname'] = book.bkname
        book_data['author'] = book.author
        output.append(book_data)

    return jsonify({'setBooks' : output})

#this method gets one set book when set book id is passed
@app.route('/getsetbook/<bk_id>',methods=['GET'])
@token_required
def get_one_setbook(self, bk_id):

    book = setBook.query.filter_by(id=bk_id).first()

    if not book:
        return jsonify({'message' : 'No setBook Found!'})

    book_data = {}
    book_data['id'] = book.id
    book_data['lang_id'] = book.lang_id
    book_data['bkname'] = book.bkname
    book_data['author'] = book.author

    return jsonify({'setbook' : book_data})


#method used to create new setbook.action limted to admin users
@app.route('/setbook', methods=['POST'])
@token_required
def create_setbook(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()


    new_setbook = setBook(bkname=data['bkname'],lang_id=data['lang_id'],author=data['author'], user_id=current_user.id)
    db.session.add(new_setbook)
    db.session.commit()

    return jsonify({'message' : 'New setbook created successfully!'})

#method used to delete a setbook.action limted to admin users
@app.route('/setbook/<bk_id>',methods=['DELETE'])
@token_required
def delete_setBook(current_user, bk_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    book = setBook.query.filter_by(id=bk_id).first()

    if not book:
        return jsonify({'message' : 'No setbook Found!'})

    db.session.delete(book)
    db.session.commit()

    return jsonify({'message' : 'The setbook has been deleted!'})
#end region setbooks


# region login
#method used to generate an author token.user passes in user name and thier password.ones authenticated, an access token is generated
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password,auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

# end region login

if __name__ == '__main__':
    app.run(debug=True)