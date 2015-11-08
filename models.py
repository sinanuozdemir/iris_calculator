from sqlalchemy.orm import relationship, sessionmaker, backref
from controller import db
from werkzeug.security import generate_password_hash, check_password_hash



class App(db.Model):
	__tablename__ = "app"
	id = db.Column(db.Integer, primary_key=True)
	appid = db.Column(db.String(64), index=True, unique=True)
	website_id = db.Column(db.Integer, db.ForeignKey("website.id"), nullable=False)
	website = relationship("Website", uselist=False, backref="app")
	user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
	user = relationship("User", uselist=False, backref="app")
	emails = relationship('Email', backref='app')
	def __repr__(self):
		return '<App %r>' % (self.appid)



class User(db.Model):
	__tablename__ = "user"
	id = db.Column(db.Integer, primary_key=True)
	apps_allowed = db.Column(db.Integer, default = 0)
	nickname = db.Column(db.String(64), index=True, unique=True)
	first_name = db.Column(db.String(64), index=True, unique=True)
	pw_hash = db.Column(db.String(512), index=True, unique=True)
	email = db.Column(db.String(120), index=True, unique=True)
	is_authenticated = db.Column(db.Boolean, index=False, unique=False)
	is_active = db.Column(db.Boolean, index=False, unique=False)
	is_anonymous = db.Column(db.Boolean, index=False, unique=False)
	def __repr__(self):
		return '<User %r>' % (self.nickname)
	def get_id(self):
		return str(self.id)
	def set_password(self, password):
		self.pw_hash = generate_password_hash(password)
	def check_password(self, password):
		return check_password_hash(self.pw_hash, password)

class Website(db.Model):
	__tablename__ = "website"
	id = db.Column(db.Integer, primary_key=True)
	base = db.Column(db.String(1024), index=True, unique=True)
	visits = relationship('Visit', backref='visit')

class Email(db.Model):
	__tablename__ = "email"
	id = db.Column(db.Integer, primary_key=True)
	emailid = db.Column(db.String(64), index=True, unique=True)
	opens = relationship('Visit', backref='email')
	app_id = db.Column(db.Integer, db.ForeignKey("app.id"), nullable=True)


class Visit(db.Model):
	__tablename__ = "visit"
	id = db.Column(db.Integer, primary_key=True)
	private_ip = db.Column(db.String(64), index=False, unique=False)
	public_ip = db.Column(db.String(64), index=False, unique=False)
	lat = db.Column(db.String(64), index=False, unique=False)
	lng = db.Column(db.String(64), index=False, unique=False)
	is_mobile = db.Column(db.Boolean, index=False, unique=False)
	is_tablet = db.Column(db.Boolean, index=False, unique=False)
	is_pc = db.Column(db.Boolean, index=False, unique=False)
	is_bot = db.Column(db.Boolean, index=False, unique=False)
	secure = db.Column(db.Boolean, index=False, unique=False)
	city = db.Column(db.String(64), index=False, unique=False)
	country = db.Column(db.String(64), index=False, unique=False)
	state = db.Column(db.String(64), index=False, unique=False)
	browser = db.Column(db.String(1024), index=False, unique=True)
	user_agent = db.Column(db.String(1024), index=False, unique=False)
	full_url = db.Column(db.String(1024), index=False, unique=False, nullable = True)
	website_id = db.Column(db.Integer, db.ForeignKey("website.id"), nullable=True)
	email_id = db.Column(db.Integer, db.ForeignKey("email.id"), nullable=True)
	after = db.Column(db.String(1024), index=False, unique=False)
	gets = db.Column(db.String(1024), index=False, unique=False)
	date = db.Column(db.DateTime())
	def __repr__(self):
		return '<Visit %r>' % (self.public_ip)