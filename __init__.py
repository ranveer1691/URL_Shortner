from flask import Flask, render_template, url_for, redirect, request, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired,Length
from wtforms import StringField,PasswordField,SubmitField
import random

app = Flask(__name__)
app.config['MONGO_DBNAME'] = 'url_shortner'
app.config['MONGO_URI'] = 'mongodb://ranveer1691:ranufootball1234567@ds125423.mlab.com:25423/url_shortner'
app.config['SECRET_KEY'] = 'super_secret_key'
mongo = PyMongo(app)

class RegForm(FlaskForm):
    username=StringField('Username:', validators=[DataRequired(),Length(min=5,max=9,message='Username must be between 5 to 9 characters long!')])
    password=PasswordField('Password:', validators=[DataRequired(),Length(min=8,message='Password should be atleast 8 characters long!')])
    submit=SubmitField('Sign up')

class LoginForm(FlaskForm):
    username=StringField('Username:', validators=[DataRequired(),Length(min=5,max=9)])
    password=PasswordField('Password:', validators=[DataRequired(),Length(min=8)])
    submit=SubmitField('Login')

class UrlForm(FlaskForm):
    urls=StringField('url',validators=[DataRequired()])
    submit=SubmitField('Short url')

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def reg_user():
    form=RegForm()
    users = mongo.db.users
    mssg=''

    active='active'

    if request.method=='POST':
        if form.validate_on_submit():
            existing_user=users.find_one({'username': form.username.data})

            if existing_user is None:
                bcrypt=Bcrypt()
                hashed_pass=bcrypt.generate_password_hash(form.password.data)
                users.insert({'username': form.username.data, 'password': hashed_pass})
                return redirect(url_for('login'))
            else:
                mssg='Username already exists!'

    return render_template('register.html',form=form,mssg=mssg, active= active)

@app.route('/login', methods=['GET', 'POST'])
def login():

    form=LoginForm()
    users = mongo.db.users
    session['username']=None
    mssg='Invalid Username or Password'
    active1 = 'active'

    if request.method=='POST':
        existing_user=users.find_one({'username': form.username.data})

        if existing_user is None:
            return render_template('login.html',form=form,mssg=mssg, active1=active1)

        bcrypt=Bcrypt()
        db_uname=existing_user['username']
        db_pass=existing_user['password']

        if db_uname==form.username.data and bcrypt.check_password_hash(db_pass, form.password.data):
            session['username'] = form.username.data
            return redirect(url_for('url', name=db_uname))

        return render_template('login.html', mssg=mssg, form=form, active1=active1)

    return render_template('login.html',form=form, active1=active1)

@app.route('/<name>', methods=['POST','GET'])
def url(name):

    form = UrlForm()
    urls = mongo.db[name]
    mssg=''
    if session['username']:
        if request.method == 'POST':
            existing_url = urls.find_one({'original':form.urls.data})

            if existing_url:
                mssg = 'URL is already shortned.Try new one!!!'
                url_find = urls.find()
                return render_template('shortner.html', form=form, name=name, url_find=url_find, mssg=mssg)

            else:
                if form.validate_on_submit():
                    rand = random.randint(0, pow(10, 5))
                    temp = "http://0.0.0.0:8800/"+name+"/"+ str(rand)
                    urls.insert({'original':form.urls.data,'short':temp})
                    return redirect(url_for('url', name=name))

        else:
            url_find = urls.find()
            return render_template('shortner.html', form=form, name=name, url_find=url_find,mssg=mssg)

    return redirect(url_for('login'))

@app.route('/<name>/<trunc>', methods=['POST','GET'])
def link(name,trunc):
    urls = mongo.db[name]
    search = urls.find_one({'short':'http://0.0.0.0:8800/'+name+'/'+trunc})
    if search:
        return redirect(search['original'])
    return redirect(url_for('url', name=name))

@app.route('/logout')
def logout():
    session['username'] = None
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
    app.secret_key = 'super_secret_key'
    # app.run(host = '0.0.0.0', port = 8800)
