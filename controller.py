import pytz
from pytz import timezone
import string, random
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response, redirect, abort, flash
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.cors import CORS
from flask.ext.login import LoginManager, login_user, current_user, logout_user, login_required
login_manager = LoginManager()
application = Flask(__name__)
application.config.from_object('config')
CORS(application)
login_manager.init_app(application)
from user_agents import parse
db = SQLAlchemy(application)
import models
import geocoder
from random import randint
import json
from datetime import datetime
from collections import Counter

website_re = re.compile("(https?://)?(www.)?([^\.]+)(.\w+)/?((\w+/?)*(\?[\w=]+)?)", re.IGNORECASE)


utc = timezone('UTC')
time_zone = timezone('US/Eastern')

login_manager.login_view = "login"
login_manager.login_message = "Please log in"


@application.route("/", methods=["GET"])
def home():
	return render_template('splash.html')

@login_manager.user_loader
def load_user(user_id):
    return getUser(id = user_id)

@application.route("/get_my_ip", methods=["GET"])
def get_my_ip():
	fwd = request.environ.get('HTTP_X_FORWARDED_FOR', None)
	if fwd is None:
		fwd = request.environ.get('REMOTE_ADDR')
	ip = fwd.split(',')[0]
	if request.args.get('format') == 'json':
		return jsonify(**{'ip': ip})
	else:
		return ip


@application.route("/logout")
@login_required
def logout():
	logout_user()
	return redirect('/login')

@application.route("/data/<path:appid>")
def chart_data(appid):
	app = db.session.query(models.App).filter_by(appid = appid).first()
	data_set = db.session.query(models.Visit).filter_by(website_id=app.website.id).values('date', 'browser')
	browsers = []
	dates = []
	for d in data_set:
		browsers.append(d[1])
		dates.append(datetime.strftime(utc.localize(d[0]).astimezone(time_zone), '%m-%d-%Y'))
	data = {
		'host':app.website.base,
		'browsers': [{'label':k, 'y':v} for k, v in Counter(browsers).iteritems()],
		'visits': sorted([{'label':k, 'y':v} for k, v in Counter(dates).iteritems()], key = lambda x:x['label'])
	}
	js = json.dumps(data)
	resp = Response(js, status=200, mimetype='application/json')
	return resp


@application.route('/insert', methods=['GET', 'POST'])
def insert():
	error = 'tracked visit. Nothing more to see here'
	status = 'success'
	try:
		d = {}
		print request.__dict__
		if request.args.get('emailid'):
			d['email_id'] = db.session.query(models.Email).filter_by(emailid=request.args.get('emailid')).first()
			if d['email_id']:
				d['email_id'] = d['email_id'].id
				error = 'successfully tracked email'
			else:
				error = 'no such email found'
				return jsonify(**{'status':'failure', 'description':error})
		elif 'appid' in request.form and 'HTTP_REFERER' in request.environ:
			d['full_url'] = request.environ.get('HTTP_REFERER', '').strip().lower()
			app = getModel(models.App, appid = request.form['appid'])
			if not app:
				return jsonify(**{'status':'failure', 'description':'no app found with that id'})
			print app.website.base, d['full_url']
			if app.website.base not in d['full_url']:
				return jsonify(**{'status':'failure', 'description':'app is for a different website'})
			ur = d['full_url'].replace('https://','').replace('http://','').replace('www.','').lower().strip()
			if '/' not in ur: ur += '/'
			base, d['after'] = ur[:ur.index('/')], ur[ur.index('/')+1:]
			d['website_id'] = app.website.id
			if len(d['after']) <= 1:
				d['after'] = None
			elif d['after'][-1] == '/':
				d['after'] = d['after'][:-1]
			if '?' in ur:
				if d['after']:
					d['after'] = d['after'].split('?')[0]
				d['gets'] = ur.split('?')[1]
				if len(d['gets']) <= 1:
					d['gets'] = None
			d['secure'] = 'https://' in d['full_url']
		else: return jsonify(**{'status':'failure', 'description':'no recognized action taken'})
		d['private_ip'] = request.environ.get('REMOTE_ADDR')
		d['public_ip'] = request.environ.get('HTTP_X_FORWARDED_FOR', None)
		if d['public_ip']:
			g = geocoder.ip(d['public_ip'])
			d['lat'], d['lng'] = g.latlng
			d['city'] = g.city
			d['country'] = g.country
			d['state'] = g.state
		d['user_agent'] = request.environ.get('HTTP_USER_AGENT')
		if d['user_agent']:
			user_agent = parse(d['user_agent'])
			d['browser'] = user_agent.browser.family
			d['is_bot'], d['is_mobile'], d['is_tablet'], d['is_pc'] = user_agent.is_bot, user_agent.is_mobile, user_agent.is_tablet, user_agent.is_pc
		
		print d
		p = models.Visit(**d)
		p.date = datetime.now()
		db.session.add(p)
		db.session.commit()
	except Exception as e:
		print e
		error = repr(e)
		status = 'failure'
	return jsonify(**{'status':status, 'description':error})

def get_or_create(model, **kwargs):
	instance = db.session.query(model).filter_by(**kwargs).first()
	if instance:
		return instance
	else:
		instance = model(**kwargs)
		db.session.add(instance)
		db.session.commit()
		return instance

def getModel(model, **kwargs):
	return db.session.query(model).filter_by(**kwargs).first()

def getUser(**kwargs):
	return db.session.query(models.User).filter_by(**kwargs).first()

def getWebsite(base_):
	return db.session.query(models.Website).filter(models.Website.base.like(base_)).first()



@application.route('/login',methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		email = request.form['email']
		password = request.form['password']
		password2 = request.form.get('password2')
		if password2 and password2 == password:
			u = models.User(email=email, pw_hash = generate_password_hash(password), is_active = True, is_authenticated = True)
			db.session.add(u)
			db.session.commit()
			login_user(u, remember=True, force=True, fresh=False)
			return redirect('/test')
		else:
			u = getUser(email=email.lower().strip())
			if u and u.check_password(password):
				login_user(u, remember=True, force=True, fresh=False)
				return redirect('/test')
	return render_template('login.html')


@application.route('/check',methods=['GET'])
def check():
	pass



@application.route('/test',methods=['GET', 'POST'])
@login_required
def test():
	if request.method == 'POST':
		if 'site_to_track' in request.form:
			base = request.form['site_to_track'].replace('https://','').replace('http://','').replace('www.','').replace('/','').lower().strip()
			a = models.App(appid = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20)), user = current_user, website = get_or_create(models.Website, base=base))
			db.session.add(a)
			db.session.commit()
	print current_user
	apps = db.session.query(models.App).filter_by(user_id = current_user.id).all()
	return render_template('test.html', apps = apps)

#Handle Bad Requests
@application.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404


application.secret_key = 'A0Zr9slfjybdskfs8j/3yX R~XHH!jmN] sdfjhbsdfjhvbskcgvbdf394574LWX/,?RT'

if __name__ == '__main__':
    application.run(debug=True)




