from sqlalchemy.orm import relationship, sessionmaker, backref
from controller import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class App(db.Model):
	__tablename__ = "app"
	id = db.Column(db.Integer, primary_key=True)
	appid = db.Column(db.String(64), index=True, unique=True)
	website_id = db.Column(db.Integer, db.ForeignKey("website.id"), nullable=False)
	website = relationship("Website", uselist=False, backref="app")
	google_email = db.Column(db.String(128), index=True, unique=True)
	google_access_token = db.Column(db.Text(), index=True)
	google_refresh_token = db.Column(db.Text(), index=True)
	user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
	user = relationship("User", uselist=False, backref="app")
	emails = relationship('Email', backref='app')
	threads = relationship('Thread', backref='app')
	def __repr__(self):
		return '<App %r>' % (self.appid)

class User(db.Model):
	__tablename__ = "user"
	id = db.Column(db.Integer, primary_key=True)
	apps_allowed = db.Column(db.Integer, default = 0)
	nickname = db.Column(db.String(64), index=True, unique=True)
	first_name = db.Column(db.String(64), index=True, unique=True)
	google_email = db.Column(db.String(128), index=True, unique=True)
	google_access_token = db.Column(db.Text(), index=True)
	google_refresh_token = db.Column(db.Text(), index=True)
	login_check = db.Column(db.String(64), index=True, unique=True)
	is_verified = db.Column(db.Boolean, index=False, unique=False)
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

class Thread(db.Model):
	__tablename__ = "thread"
	id = db.Column(db.Integer, primary_key=True)
	emails = relationship('Email', backref='thread')
	origin = db.Column(db.String(128), index=True)
	unique_thread_id = db.Column(db.String(128), index=True)
	last_checked = db.Column(db.DateTime())
	first_made = db.Column(db.DateTime())
	app_id = db.Column(db.Integer, db.ForeignKey("app.id"), nullable=True)
	

class Email(db.Model):
	__tablename__ = "email"
	id = db.Column(db.Integer, primary_key=True)
	emailid = db.Column(db.String(64), index=True, unique=True)
	google_message_id = db.Column(db.String(128), index=True, unique=True)
	google_thread_id = db.Column(db.String(128), index=True)
	textblob_sentiment = db.Column(db.Float)
	makeshift_sentiment = db.Column(db.Float)
	text = db.Column(db.Text(), index=True)
	html = db.Column(db.Text(), index=True)
	to_address = db.Column(db.Text(), index=True)
	bounce = db.Column(db.Boolean, index=False, default=False)
	bounced_email = db.Column(db.String(256), index=True, unique=True)
	from_address = db.Column(db.Text(), index=True)
	cc_address = db.Column(db.Text(), index=True)
	bcc_address = db.Column(db.Text(), index=True)
	subject = db.Column(db.Text(), index=True)
	opens = relationship('Visit', backref='email')
	date_sent = db.Column(db.DateTime())
	links = relationship('Link', backref='email')
	app_id = db.Column(db.Integer, db.ForeignKey("app.id"), nullable=True)
	thread_id = db.Column(db.Integer, db.ForeignKey("thread.id"), nullable=True)

class Link(db.Model):
	__tablename__ = "link"
	id = db.Column(db.Integer, primary_key=True)
	linkid = db.Column(db.String(64), index=True, unique=True)
	url = db.Column(db.String(1024), index=True)
	text = db.Column(db.String(1024), index=True)
	opens = relationship('Visit', backref='link')

	app_id = db.Column(db.Integer, db.ForeignKey("app.id"), nullable=True)
	email_id = db.Column(db.Integer, db.ForeignKey("email.id"), nullable=True)


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
	link_id = db.Column(db.Integer, db.ForeignKey("link.id"), nullable=True)
	after = db.Column(db.String(1024), index=False, unique=False)
	gets = db.Column(db.String(1024), index=False, unique=False)
	events = relationship('Event', backref='event')
	notified = db.Column(db.Boolean, index=False, unique=False, default = False)
	date = db.Column(db.DateTime())
	def __repr__(self):
		return '<Visit %r>' % (self.public_ip)


class Event(db.Model):
	__tablename__ = "event"
	id = db.Column(db.Integer, primary_key=True)
	visit_id = db.Column(db.Integer, db.ForeignKey("visit.id"), nullable=True)
	element_id = db.Column(db.String(1024), index=False, unique=False)
	element_type = db.Column(db.String(1024), index=False, unique=False)
	element_tag = db.Column(db.String(1024), index=False, unique=False)
	event_type = db.Column(db.String(1024), index=False, unique=False)
	date = db.Column(db.DateTime())
	def __repr__(self):
		return '%s on %s' % (self.event_type, self.element_id)

