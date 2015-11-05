from controller import db


class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	nickname = db.Column(db.String(64), index=True, unique=True)
	first_name = db.Column(db.String(64), index=True, unique=True)
	email = db.Column(db.String(120), index=True, unique=True)

	def __repr__(self):
		return '<User %r>' % (self.nickname)



class Visit(db.Model):
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
	full_url = db.Column(db.String(1024), index=False, unique=False)
	date = db.Column(db.DateTime())
	def __repr__(self):
		return '<Visit %r>' % (self.public_ip)