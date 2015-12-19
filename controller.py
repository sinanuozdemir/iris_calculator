# coding: utf-8
import googleAPI
from datetime import timedelta
from flask import make_response, request, current_app, Flask
import os
from flask_mail import Mail, Message
from flask_apscheduler import APScheduler
from functools import update_wrapper
from bs4 import BeautifulSoup as bs
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
mail = Mail(application)

from user_agents import parse
db = SQLAlchemy(application)
import models
import geocoder
from random import randint
import json
from datetime import datetime
from collections import Counter



scheduler = APScheduler()
scheduler.init_app(application)
scheduler.start()

website_re = re.compile("(https?://)?(www.)?([^\.]+)([\.\w]+)/?((\w+/?)*(\?[\w=]+)?)", re.IGNORECASE)

def crossdomain(origin=None, methods=None, headers=None,max_age=21600, attach_to_all=True,automatic_options=True):
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, basestring):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, basestring):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator

utc = timezone('UTC')
time_zone = timezone('US/Eastern')

login_manager.login_view = "login"


@application.route("/", methods=["GET"])
def home(): 
	return render_template('splash.html')

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

def _makeDBLink(email_id, text, url, appid):
	r = re.match(website_re, url)
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
			random_link = 'll'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(62))
			l, created = get_or_create(models.Link, app_id=app.id, linkid=random_link, email_id=email_id, url=u, text = text)
		return {'success':True, 'link_id':random_link, 'url':u, 'latracking_url':'https://latracking.com/r/'+random_link}
	return {'success':False}

@application.route('/createEmail', methods=['GET', 'POST'])
def createEmail():
	if 'appid' in request.form:
		return jsonify(**_makeDBEmail(request.form))
	return jsonify(**{})

def _makeDBEmail(form_dict):
	app = getModel(models.App, appid=form_dict['appid'])
	if app:
		d = {}
		created = False
		d['app_id'] = app.id
		while not created:
			random_email = 'ee'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(62))
			d['emailid'] = random_email
			for i in ['text', 'html', 'cc_address', 'bcc_address', 'to_address', 'from_address', 'subject']:
				if i in form_dict: d[i] = form_dict[i]
			e, created = get_or_create(models.Email, **d)
		return {'success':True, 'email':e, 'email_id':e.id, 'tracking_link':'https://www.latracking.com/e/'+random_email}
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
		d = {}
		d['private_ip'] = request.environ.get('REMOTE_ADDR')
		d['public_ip'] = request.environ.get('HTTP_X_FORWARDED_FOR')
		d['full_url'] = request.environ.get('HTTP_REFERER', '').strip().lower()
		if 'appid' in request.form:
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

@application.route("/v/<path:v>", methods=['GET'])
def verify(v):
	u = getModel(models.User, login_check = v)
	if u:
		u.is_verified = True
		db.session.commit()
		login_user(u, remember=True, force=True, fresh=False)
		setItDown()
	return jsonify(**{})

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
				u.is_verified = False
				login_check_ = 'uu'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(30))
				u.login_check = login_check_
				db.session.add(u)
				db.session.commit()
				msg = Message("Click me", sender="verifications@latracking.com", recipients=[email])
				msg.html = '<b><a href="https://latracking.com/v/'+login_check_+'">click me</a></b>'
				mail.send(msg)
				login_user(u, remember=True, force=True, fresh=False)
			return redirect('/test')
		else:
			u = getUser(email=email.lower().strip())
			if u and u.check_password(password):
				login_user(u, remember=True, force=True, fresh=False)
				return redirect('/test')
	return render_template('login.html')

def checkForReplies(threadId, access_token, from_ = 'google'):
	if from_ == 'google':
		for message in googleAPI.getThreadMessages(threadId, access_token):
			g = googleAPI.cleanMessage(message)
			if not getModel(models.Email, google_message_id=g['google_message_id']):
				get_or_create(models.Email, **g)

def getUnrepliedThreadsOfUser(user_id, from_ = 'google'):
	app = db.session.query(models.App).filter_by(user_id=user_id).first()
	emails = db.session.query(models.Email).filter_by(app_id=app.id).all()
	if from_ == 'google':
		ids = [e.google_thread_id for e in emails]
		messages = [e.google_thread_id for e in db.session.query(models.Email).filter(models.Email.google_thread_id.in_(ids))]
		return [k for k, v in Counter(messages).iteritems() if v == 1 ]

def handleUser(user_id = 21):
	access_token = userGoogleAPI(db.session.query(models.User).filter_by(id=user_id).first())
	for threadId in getUnrepliedThreadsOfUser(user_id):
		print threadId
		checkForReplies(threadId, access_token, from_ = 'google')
	return jsonify(status='done')


@application.route('/check',methods=['GET'])
def check():
	handleUser()
	
	
	



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

def getAppIDForEmail(email):
	u, t = get_or_create(models.User, email=email)
	apps = db.session.query(models.App).filter_by(user = u).all()
	if len(apps):
		return apps[0].appid
	random_appid = 'aa'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(62))
	app_created = False
	
	w, w_c = get_or_create(models.Website, base=email.split('@')[1].lower().strip())
	while not app_created:
		app, app_created = get_or_create(models.App, appid=random_appid, user=u, user_id=u.id, website = w)
	return random_appid



@application.route('/setItDown',methods=['GET'])
@login_required
def setItDown():
	a = getAppIDForEmail(current_user.email)
	out = jsonify(appid=a)
	out.set_cookie('LATrackingID', value=a, max_age=None, expires=datetime.now()+timedelta(days=365))
	return out
	

def userGoogleAPI(user):
	new_token = googleAPI.refreshAccessToken(user.google_access_token, user.google_refresh_token)
	if user.google_access_token != new_token:
		print "new token"
		user.google_access_token = new_token
		db.session.commit()
	return user.google_access_token


@application.route('/convertHTML',methods=['POST', 'OPTIONS'])
@crossdomain(origin='*')
def convertHTML():
	if 'appid' not in request.form:
		return jsonify(success=False, reason='need tracking_id')
	appid = request.form['appid']
	u = getModel(models.App, appid = request.form.get('appid')).user
	if not u.is_verified:
		return jsonify(success=False, reason='not verified')
	
	html = request.form['html']
	links = []
	soup = bs(html)
	d = {'appid':appid}
	for i in ['text', 'html', 'cc_address', 'bcc_address', 'to_address', 'from_address', 'subject']:
		if i in request.form: d[i] = request.form[i]
	e = _makeDBEmail(d)
	email = e['email']
	del e['email']
	for a in soup.find_all('a'):
		if a.get('href') and 'latracking.com/r/' not in a['href'].lower():
			cleaned = _makeDBLink(e['email_id'], a.text, a['href'], appid)
			links.append({'url':a.get('href'), 'text':a.text, 'cleaned':cleaned})
			a['href'] = cleaned['latracking_url']
	new_tag = soup.new_tag("img", src=e['tracking_link'], style="height: 1px; width:1px; display: none !important;")
	soup.append(new_tag)
	if 'send' in request.form and 'to_address' in request.form:
		access_token = userGoogleAPI(u)
		response = googleAPI.sendEmail(email = u.google_email, access_token = access_token, to_address = d['to_address'], subject = d.get('subject', ''), bcc_address = d.get('bcc_address', ''), html = str(soup))
		print response
		email.google_message_id = response['id']
		email.google_thread_id = response['threadId']
		email.date_sent = datetime.utcnow()
		db.session.commit()
	return jsonify(success=True, links=links, cleaned_html=str(soup), email=e)
















############################
####### Notifications ######
############################

def cleanVisit(visit):
	d = {}
	d['state'] = visit.state
	d['country'] = visit.country
	d['city'] = visit.city
	d['public_ip'] = visit.public_ip
	d['minutes_ago'] = int((datetime.utcnow() - visit.date).total_seconds()/60)
	return d

def cleanEmail(e):
	d = {}
	d['subject'] = e.subject
	d['emailid'] = e.emailid
	return d

def cleanLink(e):
	d = {}
	d['url'] = e.url
	d['text'] = e.text
	return d

@application.route('/getInfoOnEmails',methods=['POST'])
def getInfoOnEmails():
	if 'appid' not in request.form or 'emails' not in request.form:
		return jsonify(success=False, reason='appid not in POST')
	email_ids = [a.strip() for a in request.form['emails'].split(',')]
	a = db.session.query(models.App).filter_by(appid=request.form['appid']).first().id
	emails = db.session.query(models.Email).filter(models.Email.emailid.in_(email_ids)).filter_by(app_id=a).all()
	emails = [{'links':[{'link':cleanLink(l), 'opens':map(cleanVisit,e.opens[-3:])} for l in e.links], 'email':cleanEmail(e), 'opens':map(cleanVisit,e.opens[-3:])} for e in emails]
	return jsonify(success=True, emails = emails)


@application.route('/getNotifications',methods=['GET', 'POST'])
def getNotifications():
	if 'appid' in request.form:
		long_id = request.form['appid']
		appid = getModel(models.App, appid = request.form.get('appid')).id
		print appid
	elif 'LATrackingID' in request.cookies:
		long_id = request.cookies.get('LATrackingID')
		appid = getModel(models.App, appid = request.cookies.get('LATrackingID')).id
	else:
		return jsonify(**{})
	_emails = {d.id:d.subject for d in db.session.query(models.Email).filter_by(app_id = appid).all()}
	_links = {d.id: d.text for d in db.session.query(models.Link).filter_by(app_id = appid).all()}
	emails = db.session.query(models.Visit).filter(models.Visit.email_id.in_(_emails.keys())).filter_by(notified=False).all()
	links = db.session.query(models.Visit).filter(models.Visit.link_id.in_(_links.keys())).filter_by(notified=False).all()
	n_e, n_l = [], []
	for e in emails:
		d = {}
		d['state'] = e.state
		d['subject'] = _emails[e.email_id]
		d['country'] = e.country
		d['minutes_ago'] = int((datetime.utcnow() - e.date).total_seconds()/60)
		n_e.append(d)
	for l in links:
		d = {}
		d['state'] = l.state
		d['text'] = _links[l.link_id]
		d['country'] = l.country
		d['minutes_ago'] = int((datetime.utcnow() - l.date).total_seconds()/60)
		n_l.append(d)
	return jsonify(links=n_l, emails=n_e, appid=long_id)





















application.secret_key = 'A0Zr9slfjybdskfs8j/3yX R~XHH!jfjhbsdfjhvbskcgvbdf394574LWX/,?RT'



if __name__ == '__main__':
    application.run(debug=True)




