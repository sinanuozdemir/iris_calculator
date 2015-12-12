import itertools
import operator
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

website_re = re.compile("(https?://)?(www.)?([^\.]+)([\.\w]+)/?((\w+/?)*(\?[\w=]+)?)", re.IGNORECASE)


utc = timezone('UTC')
time_zone = timezone('US/Eastern')

login_manager.login_view = "login"


@application.route("/", methods=["GET"])
def home(): return render_template('splash.html')

@login_manager.user_loader
def load_user(user_id): return getUser(id = user_id)

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
	data_set = db.session.query(models.Visit).filter_by(website_id=app.website.id).values('date', 'browser', 'public_ip', 'after', 'id')
	data_set = [list(d) for d in data_set]
	events = db.session.query(models.Event).filter(models.Event.visit_id.in_([d[4] for d in data_set])).order_by('date').all()
	for d in data_set:
		visit_events = [{'event':e, 'pretty_event':str(e)} for e in events if e.visit_id==d[4]]
		# if visit_events:
		# 	print visit_events
		d[0] = datetime.strftime(d[0], '%m-%d-%Y')
	afters = [d[3] for d in data_set]
	afters = [a if a else app.website.base for a in afters]
	browsers = [d[1] for d in data_set]
	dates =  [d[0] for d in data_set]
	for unique_date in set(dates):
		visits_on_this_day = [d for d in data_set if d[0] == unique_date]
		unique_ips_on_day = list(set([v[2] for v in visits_on_this_day]))
	ips = [d[2] for d in data_set]
	sessions = {k: list(v) for k, v in itertools.groupby(data_set, key=lambda x:x[2])}
	session_lens = [len(a) for a in sessions.values()]
	print sessions
	last_pages = [a[-1][3] if a[-1][3] else app.website.base for a in sessions.values()]
	data = {
		'host':       app.website.base,
		'browsers':   [{'label':k, 'y':v} for k, v in Counter(browsers).iteritems()],
		'visits':     sorted([{'label':k, 'y':v} for k, v in Counter(dates).iteritems()], key = lambda x:x['label']),
		'unique_ips': len(set(ips)),
		'afters':     sorted([{'label':k, 'y':v} for k, v in Counter(afters).iteritems()], key = lambda x:x['y'])[-10:],
		'pages_per_sess': float(sum(session_lens)) / len(session_lens),
		'last_pages': sorted([{'label':k, 'y':v} for k, v in Counter(last_pages).iteritems()], key = lambda x:x['y'])[-10:],
	}
	
	js = json.dumps(data)
	resp = Response(js, status=200, mimetype='application/json')
	return resp

@application.route('/createLink', methods=['GET', 'POST'])
def createLink():
	if 'appid' in request.form:
		return jsonify(**_makeDBLink(request.form['url'], request.form['appid']))
	return jsonify(**{})

def _makeDBLink(url, appid):
	r = re.match(website_re, url)
	print r.groups()
	if '.' not in r.group(4):
		return jsonify( status='failure', reason='not a valid url')
	if not r.group(1):
		u = 'http://'
	else:
		u = r.group(1)
	u+=r.group(3)+r.group(4)
	if r.group(5): u += '/'+r.group(5)
	app = getModel(models.App, appid=appid)
	if app:
		created = False
		while not created:
			random_link = 'll'+.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(14))
			l, created = get_or_create(models.Link, app_id=appid, linkid=random_link, url=u)
		return {'success':True, 'email_id':random_link, 'url':u}
	return {'success':False}

@application.route('/createEmail', methods=['GET', 'POST'])
def createEmail():
	if 'appid' in request.form:
		return jsonify(**_makeDBEmail(request.form))
	return jsonify(**{})

def _makeDBEmail(form_dict):
	print form_dict
	app = getModel(models.App, appid=form_dict['appid'])
	if app:
		d = {}
		created = False
		d['app_id'] = form_dict['appid']
		while not created:
			random_email = 'ee'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(14))
			d['emailid'] = random_email
			for i in ['text', 'html', 'cc_address', 'bcc_address', 'to_address', 'from_address']:
				if i in form_dict: d[i] = form_dict[i]
			e, created = get_or_create(models.Email, **d)
		return {'success':True, 'email_id':random_email}
	return {'success':False}

@application.route("/r/<path:l>", methods=['GET'])
def _redirect(l):
	d = {}
	d['private_ip'] = request.environ.get('REMOTE_ADDR')
	d['public_ip'] = request.environ.get('HTTP_X_FORWARDED_FOR')
	d['full_url'] = request.environ.get('HTTP_REFERER', '').strip().lower()
	link = db.session.query(models.Link).filter_by(linkid=l).first()
	if link:
		red_url = link.url
		d['link_id'] = link.id
		error = 'successfully tracked link'
	else:
		return jsonify(**{'status':'failure', 'description':'no such link found'})
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
	p = models.Visit(**d)
	p.date = datetime.now()
	db.session.add(p)
	db.session.commit()
	return redirect(red_url, code=302)

@application.route("/e/<path:e>", methods=['GET'])
def emailOpen(e):
	d = {}
	d['private_ip'] = request.environ.get('REMOTE_ADDR')
	d['public_ip'] = request.environ.get('HTTP_X_FORWARDED_FOR')
	d['full_url'] = request.environ.get('HTTP_REFERER', '').strip().lower()
	email = db.session.query(models.Email).filter_by(emailid=e).first()
	if email:
		d['email_id'] = email.id
	else:
		return jsonify(**{'status':'failure', 'description':'no such email found'})
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
	return jsonify(success=True, description='successfully tracked email')



@application.route('/insert', methods=['GET', 'POST'])
def insert():
	error = 'tracked visit. Nothing more to see here'
	status = 'success'
	try:
		if 'appid' in request.form and 'HTTP_REFERER' in request.environ:
			if 'event' in request.form:
				d['visit_id'] = db.session.query(models.Visit).filter_by(full_url=d['full_url'], public_ip=d['public_ip'], private_ip=d['private_ip']).order_by('-id').first().id
				d['event_type'] = request.form['event_type'].lower()
				d['element_id'] = request.form['element_id'].lower()
				d['element_type'] = request.form['element_type'].lower()
				d['element_tag'] = request.form['element_tag'].lower()
				if 'public_ip' in d: del d['public_ip']
				if 'private_ip' in d: del d['private_ip']
				if 'full_url' in d: del d['full_url']
				e = models.Event(**d)
				e.date = datetime.now()
				db.session.add(e)
				db.session.commit()
				return jsonify(**{'status':'success', 'description':'event recorded'})
			app = getModel(models.App, appid = request.form['appid'])
			if not app:
				return jsonify(**{'status':'failure', 'description':'no app found with that id'})
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
		print d
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
		p = models.Visit(**d)
		p.date = datetime.now()
		db.session.add(p)
		db.session.commit()
	except Exception as e:
		error = repr(e)
		status = 'failure'
	return jsonify(**{'status':status, 'description':error})





def get_or_create(model, **kwargs):
	instance = db.session.query(model).filter_by(**kwargs).first()
	if instance:
		return instance, False
	else:
		instance = model(**kwargs)
		db.session.add(instance)
		db.session.commit()
		return instance, True

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
			u, u_c = get_or_create(models.User, email=email)
			if not u_c:
				flash('Someone already owns this!')
			else:
				u.pw_hash = generate_password_hash(password)
				u.is_active = True
				u.is_authenticated = True
				db.session.add(u)
				db.session.commit()
				login_user(u, remember=True, force=True, fresh=False)
			return redirect('/test')
		else:
			u = getUser(email=email.lower().strip())
			print u, u.check_password(password)
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
		if 'delete' in request.form:
			a = get_or_create(models.App, appid=request.form['delete'])[0]
			db.session.delete(a)
			db.session.commit()
		elif 'site_to_track' in request.form:
			base = request.form['site_to_track'].replace('https://','').replace('http://','').replace('www.','').replace('/','').lower().strip()
			w, w_c = get_or_create(models.Website, base=base)
			a = getModel(models.App, website = w)
			if a: flash('Someone already owns this website!', 'error')
			else:	
				a = models.App(appid = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20)), user = current_user, website = w)
				db.session.add(a)
				db.session.commit()
		redirect('/test')
	apps = db.session.query(models.App).filter_by(user_id = current_user.id).all()
	return render_template('test.html', apps = apps)

#Handle Bad Requests
@application.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404


application.secret_key = 'A0Zr9slfjybdskfs8j/3yX R~XHH!jmN] sdfjhbsdfjhvbskcgvbdf394574LWX/,?RT'

if __name__ == '__main__':
    application.run(debug=True)




