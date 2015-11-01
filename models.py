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
	ip = db.Column(db.String(64), index=True, unique=True)
	lat = db.Column(db.String(64), index=True, unique=True)
	lng = db.Column(db.String(64), index=True, unique=True)
	city = db.Column(db.String(64), index=True, unique=True)
	country = db.Column(db.String(64), index=True, unique=True)
	browser = db.Column(db.String(128), index=True, unique=True)
	full_url = db.Column(db.String(1024), index=True, unique=True)
	date = db.Column(db.DateTime())
	def __repr__(self):
		return '<Visit %r>' % (self.ip)