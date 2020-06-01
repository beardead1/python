from flask_login import UserMixin, current_user
from . import db
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) #Klucz główny
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


class Post(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(80), nullable=False)
	body = db.Column(db.Text, nullable=False)
	pub_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	osoba = db.Column(db.String(80))
