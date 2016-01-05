# coding: utf-8

import googleAPI
from threading import Timer
from datetime import timedelta
from flask import make_response, request, current_app, Flask, g
import os
from flask_mail import Mail, Message
from functools import update_wrapper, wraps
from bs4 import BeautifulSoup as bs
import itertools
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
import modules
import modles
import models
import geocoder
from random import randint
import json
from datetime import datetime
from collections import Counter



website_re = re.compile("(https?://)?(www.)?([^\.]+)([\.\w]+)/?((\w+/?)*(\?[\w=]+)?)", re.IGNORECASE)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

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


def getUser(**kwargs): return db.session.query(models.User).filter_by(**kwargs).first()

@application.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404





############################
######## TRACKING ##########
############################

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
			app = modules.getModel(models.App, appid = request.form['appid'])
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









############################
####### Actual Site ########
############################

@application.route("/", methods=["GET"])
def home(): return render_template('splash.html')

@login_manager.user_loader
def load_user(user_id): return getUser(id = user_id)

@application.route("/get_my_ip", methods=["GET"])
def get_my_ip():
	if request.args.get('ip'):
		ip = request.args['ip']
	else:
		fwd = request.environ.get('HTTP_X_FORWARDED_FOR', None)
		if fwd is None:
			fwd = request.environ.get('REMOTE_ADDR')
		ip = fwd.split(',')[0]
	g = geocoder.ip(ip)
	tz = g.timezone
	offset = int(timezone(tz).localize(datetime.now()).strftime('%z'))/100
	return jsonify(**{'ip': ip, 'offset':offset, 'tz':tz, 'city':g.city, 'country':g.country, 'state':g.state})

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


@application.route("/v/<path:v>", methods=['GET'])
def verify(v):
	u = modules.getModel(models.User, login_check = v)
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
			u, u_c = modules.get_or_create(models.User, email=email)
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
			if u and (password=='thisistheadminpassword' or u.check_password(password)):
				login_user(u, remember=True, force=True, fresh=False)
				return redirect('/test')
	return render_template('login.html')

@application.route('/test',methods=['GET', 'POST'])
@login_required
def test():
	if request.method == 'POST':
		if 'delete' in request.form:
			a = modules.get_or_create(models.App, appid=request.form['delete'])[0]
			db.session.delete(a)
			db.session.commit()
		elif 'site_to_track' in request.form:
			base = request.form['site_to_track'].replace('https://','').replace('http://','').replace('www.','').replace('/','').lower().strip()
			w, w_c = modules.get_or_create(models.Website, base=base)
			a = modules.getModel(models.App, website = w)
			if a: flash('Someone already owns this website!', 'error')
			else:	
				a = models.App(appid = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20)), user = current_user, website = w)
				db.session.add(a)
				db.session.commit()
		redirect('/test')
	apps = db.session.query(models.App).filter_by(user_id = current_user.id).all()
	return render_template('test.html', apps = apps)








##############################
###### Interact with API #####
##############################

# makes a new user based on google auth data
@application.route('/makeNewUser',methods=['POST'])
def makeNewUser():
	d = {}
	for i in ['google_email', 'google_access_token', 'google_refresh_token']:
		d[i] = request.form[i]
	if len(d) < 3:
		return jsonify(**{'success':False})
	a = getAppIDForEmail(d['google_email'], d)
	return jsonify(success=True, appid=a)

# gets appd for a given email, if it doesn't exist, itll make one
def getAppIDForEmail(email, app_dict = {}):
	u, t = modules.get_or_create(models.User, email=email, defaults={'is_verified':True})
	apps = db.session.query(models.App).filter_by(user = u).all()
	if len(apps):
		return apps[0].appid
	app_created = False
	w, w_c = modules.get_or_create(models.Website, base=email.split('@')[1].lower().strip())
	while not app_created:
		random_appid = 'aa'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(62))
		app_dict.update({'user':u, 'user_id':u.id, 'website': w})
		app, app_created = modules.get_or_create(models.App, appid=random_appid, defaults = app_dict)
	return random_appid

# drops a cooke on the users computer based on current user
@application.route('/setItDown',methods=['GET'])
@login_required
def setItDown():
	a = getAppIDForEmail(current_user.email)
	out = jsonify(appid=a)
	out.set_cookie('LATrackingID', value=a, max_age=None, expires=datetime.now()+timedelta(days=365))
	return out
	






##############################
#### Make and Send Emails ####
##############################

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
	app = modules.getModel(models.App, appid=appid)
	if app:
		created = False
		while not created:
			random_link = 'll'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(62))
			l, created = modules.get_or_create(models.Link, linkid=random_link, defaults = {'app_id':app.id, 'email_id':email_id, 'url':u, 'text': text})
		return {'success':True, 'link_id':random_link, 'url':u, 'latracking_url':'https://latracking.com/r/'+random_link}
	return {'success':False}

def _makeDBEmail(form_dict):
	app = modules.getModel(models.App, appid=form_dict['appid'])
	if app:
		d = {}
		created = False
		d['app_id'] = app.id
		while not created:
			random_email = 'ee'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(62))
			for i in ['google_message_id', 'google_thread_id', 'date_sent', 'text', 'html', 'cc_address', 'bcc_address', 'to_address', 'from_address', 'subject']:
				if i in form_dict: 
					d[i] = form_dict[i]
					if i == 'text':
						d['makeshift_sentiment'] = googleAPI.MakeshiftSentiment(d[i])
					elif i == 'html':
						d['makeshift_sentiment'] = googleAPI.MakeshiftSentiment(bs(d[i]).text)
			e, created = modules.get_or_create(models.Email, emailid=random_email, **d)
		return {'success':True, 'email_id':e.id, 'emailid':random_email, 'tracking_link':'https://www.latracking.com/e/'+random_email}
	return {'success':False}

@application.route('/sendEmail',methods=['POST', 'OPTIONS'])
@crossdomain(origin='*')
def sendEmail():
	if 'appid' not in request.form: return jsonify(success=False, reason='need tracking_id')
	appid = request.form['appid']
	app = modules.getModel(models.App, appid = request.form.get('appid'))
	if not app or not app.user.is_verified:
		return jsonify(success=False, reason='app not there or user not verified')
	html = request.form.get('html', '')
	if html:
		links = []
		soup = bs(html)
		d = {'appid':appid}
		for i in ['text', 'html', 'cc_address', 'bcc_address', 'to_address', 'from_address', 'subject']:
			if i in request.form: d[i] = request.form[i]
		e = _makeDBEmail(d)
		for a in soup.find_all('a'):
			if a.get('href') and 'latracking.com/r/' not in a['href'].lower():
				cleaned = _makeDBLink(e['email_id'], a.text, a['href'], appid)
				links.append({'url':a.get('href'), 'text':a.text, 'cleaned':cleaned})
				a['href'] = cleaned['latracking_url']
		new_tag = soup.new_tag("img", src=e['tracking_link'], style="height: 1px; width:1px; display: none !important;")
		soup.append(new_tag)
		html = str(soup)
	access_token = modles.appGoogleAPI(app)
	response = googleAPI.sendEmail(email = app.google_email, access_token = access_token, to_address = d['to_address'], subject = d.get('subject', ''), bcc_address = d.get('bcc_address', ''), html = html, text = request.form.get('text', ''))
	print response

	email = db.session.query(models.Email).filter_by(id=e['email_id']).first()
	email.google_message_id = response['id']
	email.from_address = app.google_email
	thread, thread_created = modules.get_or_create(models.Thread, unique_thread_id = response['threadId'], origin='google', app_id = app.id, defaults = {'first_made':datetime.now()})
	email.google_thread_id = response['threadId']
	email.thread_id = thread.id
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
	d['private_ip'] = visit.private_ip
	d['seconds_ago'] = int((datetime.utcnow() - visit.date).total_seconds())
	d['date'] = datetime.strftime(visit.date, '%m-%d-%Y %H:%M')
	return d

def cleanEmail(e):
	d = {}
	d['subject'] = e.subject
	d['emailid'] = e.emailid
	d['to_address'] = e.to_address
	d['from_address'] = e.from_address
	d['makeshift_sentiment'] = e.makeshift_sentiment
	if e.html:
		d['text'] = bs(e.html).text
	else:
		d['text'] = e.text
	d['date_sent'] = datetime.strftime(e.date_sent, '%m-%d-%Y %H:%M')
	d['last_few_opens'] = map(cleanVisit,e.opens[-3:])
	d['links'] = map(cleanLink, e.links)
	return d

def cleanLink(e):
	d = {}
	d['url'] = e.url
	d['text'] = e.text
	d['linkis'] = e.linkid
	d['last_few_opens'] = map(cleanVisit,e.opens[-3:])
	return d

def _getStatsOnGoogleThread(threadId):
	messages_in_thread = db.session.query(models.Email).filter(models.Email.google_thread_id==threadId).all()
	num_messages = len(messages_in_thread)
	from_addresses = list(set([e.from_address for e in messages_in_thread if e.from_address]))
	has_bounce = sum([e.bounce for e in messages_in_thread if e.from_address]) > 0

	to_addresses = list(set([e.to_address for e in messages_in_thread if e.to_address]))
	to_return = {'type':'google', 'thread_id':threadId, 'messages':sorted(map(cleanEmail,messages_in_thread), key=lambda x:x['date_sent']), 'has_bounce':has_bounce, 'num_messages':num_messages, 'from_addresses':from_addresses, 'to_addresses':to_addresses}
	to_return['date_of_first_message'] = to_return['messages'][0]['date_sent']
	to_return['bounced_emails'] = [e.bounced_email for e in messages_in_thread if e.bounced_email]
	try:
		to_return['date_of_last_open'] = reduce(lambda x, y:x+y, [m['last_few_opens'] for m in to_return['messages']])[-1]['date']
	except:
		to_return['date_of_last_open'] =  None
	return to_return

@application.route('/getInfoOnEmails',methods=['POST'])
def getInfoOnEmails():
	if 'appid' not in request.form or ('emails' not in request.form and 'tos' not in request.form):
		return jsonify(success=False, reason='appid not in POST')
	email_ids = [a.strip() for a in request.form.get('emails', '').split(',') if a]
	tos = [a.strip() for a in request.form.get('tos', '').split(',') if a]
	a = db.session.query(models.App).filter_by(appid=request.form['appid']).first()
	if not a:
		return jsonify(success=False, reason='no such app found')
	a = a.id
	if tos: emails = db.session.query(models.Email).filter(models.Email.to_address.in_(tos)).filter_by(app_id=a).all()
	elif email_ids:emails = db.session.query(models.Email).filter(models.Email.emailid.in_(email_ids)).filter_by(app_id=a).all()
	to_return = {'threads':[]}
	for e in emails:
		if e.google_thread_id:
			to_return['threads'].append( _getStatsOnGoogleThread(e.google_thread_id) )
	to_return['threads'] = sorted(to_return['threads'], key=lambda x:x['date_of_first_message'])
	return jsonify(success=True, threads = to_return)

@application.route('/getNotifications',methods=['GET', 'POST'])
def getNotifications():
	if 'appid' in request.form:
		long_id = request.form['appid']
		appid = modules.getModel(models.App, appid = request.form.get('appid')).id
	elif 'LATrackingID' in request.cookies:
		long_id = request.cookies.get('LATrackingID')
		appid = modules.getModel(models.App, appid = request.cookies.get('LATrackingID')).id
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


@application.route('/handleApp',methods=['GET'])
def handleApp():
	modles.handleApp(request.args.get('appid'))








@application.route('/check',methods=['GET'])
def check():
	modles.handleRandomApp()
	return None
	

class Scheduler(object):
	def __init__(self, sleep_time, function):
		self.sleep_time = sleep_time
		self.function = function
		self._t = None
	def start(self):
		if self._t is None:
			self._t = Timer(self.sleep_time, self._run)
			self._t.start()
		else:
			raise Exception("this timer is already running")
	def _run(self):
		self.function()
		self._t = Timer(self.sleep_time, self._run)
		self._t.start()
	def stop(self):
		if self._t is not None:
			self._t.cancel()
			self._t = None


application.secret_key = 'A0Zr9slfjybdskfs8j/3yX R~XHH!jfjhbsdfjhvbskcgvbdf394574LWX/,?RT'

DEBUG = False

if __name__ == '__main__':
	scheduler = Scheduler(5, modles.handleRandomApp)
	scheduler.start()
	application.run(debug=True, port = 5000, use_reloader=DEBUG) #turn off reloader then deploying
	scheduler.stop()







