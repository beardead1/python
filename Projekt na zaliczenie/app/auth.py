from flask import Blueprint, render_template, redirect, url_for, request, flash
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from flask_login import login_user, logout_user, login_required, current_user
from .models import User, Post
import sqlite3

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

	
@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
	
	
@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first() # Jeśli zwróci użytkownika to znaczy, że email istnieje już

    if user: # Jeśli użytkownik znaleziony to przekieruj go z powrotem do logowania
        return redirect(url_for('auth.signup'))

    # create new user with the form data. Hash the password so plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))
	
    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email już istnieje w bazie')
        return redirect(url_for('auth.signup'))
		
		
		
@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password):
        flash('Sprawdź swoje dane i spróbuj ponownie')
        return redirect(url_for('auth.login')) # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))
	
#proba postów
@auth.route('/index', methods=['POST'])
def posty():
	conn = sqlite3.connect('app.db')
	tytul = request.form.get('tytul')
	post = request.form.get('post')
	post_1 = Post(title=tytul, body=post, osoba=current_user.email)
	db.session.add(post_1)
	db.session.commit()
	return redirect(url_for('main.index'))

@auth.route('/')
def list():
	rekordy = Post.query.all()
	print(rekordy)
	return render_template("index.html", rekordy = rekordy, test="test", naglowek="POSTY UŻYTKOWNIKÓW")
	
@auth.route('/profile')
def list_1():
	szukaj = current_user.email
	rekordy = Post.query.filter_by(osoba=current_user.email).all()
	return render_template("profile.html", name=current_user.name, rekordy = rekordy, test="test", naglowek="TWOJE POSTY")
	
#proba postów
@auth.route('/profile', methods=['POST'])
def usun_post():
	ident = request.form.get('id')
	rekordy = Post.query.filter_by(id=ident).delete()
	db.session.commit()
	return redirect(url_for('main.index'))