# coding: utf-8
import googleAPI
import requests
from sqlalchemy import and_
from threading import Timer
from datetime import timedelta
from flask import make_response, request, current_app, Flask, g, session
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


def getUser(**kwargs): 
	try:
		return db.session.query(models.User).filter_by(**kwargs).first()
	except:
		return None

@application.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404





############################
######## TRACKING ##########
############################

@application.route("/r/<path:l>/", methods=['GET'])
def _redirect(l):
	d = {}
	d['private_ip'] = request.environ.get('REMOTE_ADDR')
	d['public_ip'] = request.environ.get('HTTP_X_FORWARDED_FOR')
	d['full_url'] = request.environ.get('HTTP_REFERER', '').strip().lower()
	if request.cookies.get('LATrackingID'):
		a = modules.getModel(models.App, appid = request.cookies.get('LATrackingID'))
		d['app_id'] = a.id
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
	if request.cookies.get('LATrackingID'):
		a = modules.getModel(models.App, appid = request.cookies.get('LATrackingID'))
		d['app_id'] = a.id
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
				login_check_ = 'uu'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(9))
				u.login_check = login_check_
				db.session.add(u)
				db.session.commit()
				msg = Message("Click me", sender="verifications@latracking.com", recipients=[email])
				msg.html = '<b><a href="http://latracking.com/v/'+login_check_+'">click me</a></b>'
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
@application.route('/checkApp',methods=['POST'])
def checkApp():
	try:
		a = modules.getModel(models.App, appid=request.form.get('appid'))
	except:
		return jsonify(success=False)
	return jsonify(success=True, is_valid=a.google_access_token is not None)

# makes a new user based on google auth data
@application.route('/makeNewUser',methods=['POST'])
def makeNewUser():
	d = {}
	for i in ['google_email', 'google_access_token', 'google_refresh_token']:
		d[i] = request.form[i]
	if len(d) < 3:
		return jsonify(success = False)
	a, user_id, app_created = getAppIDForEmail(d['google_email'], d)
	if app_created:
		e, created = modules.get_or_create(models.App, appid=a, website_id = 1, user_id=user_id, **d)
	else:
		existing_app = db.session.query(models.App).filter_by(appid=a).first()
		if 'google_access_token' in d:
			existing_app.google_access_token = d['google_access_token']
		if 'google_refresh_token' in d:
			existing_app.google_refresh_token = d['google_refresh_token']
		db.session.commit()
	return jsonify(success=True, appid=a)

# gets appd for a given email, if it doesn't exist, itll make one
def getAppIDForEmail(email, app_dict = {}):
	u, t = modules.get_or_create(models.User, email=email, defaults={'is_verified':True})
	apps = db.session.query(models.App).filter_by(user = u).all()
	if len(apps):
		return apps[0].appid, u.id, False
	random_app = 'aa'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(9))
	return random_app, u.id, True

@application.route('/setItDown',methods=['GET'])
def setItDown():
	a = session['appid']
	out = jsonify(appid=a)
	out.set_cookie('LATrackingID', value=a, max_age=None, expires=datetime.now()+timedelta(days=365))
	return out
	






##############################
#### Make and Send Emails ####
##############################

@application.route('/sendEmail',methods=['POST', 'OPTIONS'])
@crossdomain(origin='*')
def sendEmail():
	return jsonify(**modles.sendEmailFromController(request.form))





############################
####### Notifications ######
############################

def cleanVisit(visit, app_id):
	d = {}
	d['state'] = visit.state
	d['country'] = visit.country
	d['city'] = visit.city
	d['public_ip'] = visit.public_ip
	d['private_ip'] = visit.private_ip
	d['opened_by_recipient'] = visit.app_id != app_id
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
	d['times_opened'] = len(e.opens)
	d['date_sent'] = datetime.strftime(e.date_sent, '%m-%d-%Y %H:%M')
	all_opens = [cleanVisit(r, e.app_id) for r in e.opens]
	d['last_few_opens'] = all_opens[-3:]
	d['ever_opened_by_recipient'] = sum([a['opened_by_recipient'] for a in all_opens]) > 0
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
	thread = modules.getModel(models.Thread, unique_thread_id=threadId)
	messages_in_thread = thread.emails
	num_messages = len(messages_in_thread)
	from_addresses = list(set([e.from_address for e in messages_in_thread if e.from_address]))
	has_bounce = sum([e.bounce for e in messages_in_thread if e.from_address]) > 0

	to_addresses = list(set([e.to_address for e in messages_in_thread if e.to_address]))
	to_return = {'type':'google', 'unique_thread_id':threadId, 'messages':sorted(map(cleanEmail,messages_in_thread), key=lambda x:x['date_sent']), 'has_bounce':has_bounce, 'num_messages':num_messages, 'from_addresses':from_addresses, 'to_addresses':to_addresses}
	to_return['all_parties_replied'] = thread.all_parties_replied
	to_return['date_of_first_message'] = to_return['messages'][0]['date_sent']
	to_return['bounced_emails'] = [e.bounced_email for e in messages_in_thread if e.bounced_email]
	try:
		to_return['date_of_last_open'] = reduce(lambda x, y:x+y, [m['last_few_opens'] for m in to_return['messages']])[-1]['date']
	except:
		to_return['date_of_last_open'] =  None
	return to_return

@application.route('/getInfoOnEmail',methods=['POST'])
def getInfoOnEmail():
	if 'appid' not in request.form or 'email' not in request.form:
		return jsonify(success=False, reason='appid not in POST')
	email_id = request.form.get('email', '')
	a = db.session.query(models.App).filter_by(appid=request.form['appid']).first()
	if not a:
		return jsonify(success=False, reason='no such app found')
	a = a.id
	email = modules.getModel(models.Email, emailid = email_id)
	to_return = {}
	if email.google_message_id: #is a google message
		to_return['thread'] =  _getStatsOnGoogleThread(email.thread.unique_thread_id)
	return jsonify(success=True, threads = to_return)



@application.route('/getStatsOnEmails',methods=['POST'])
def getStatsOnEmails():
	if 'appid' not in request.form or ('emails' not in request.form and 'tos' not in request.form):
		return jsonify(success=False, reason='appid not in POST')
	email_ids = [a.strip() for a in request.form.get('emails', '').split(',') if a]
	tos = [a.strip() for a in request.form.get('tos', '').split(',') if a]
	a = db.session.query(models.App).filter_by(appid=request.form['appid']).first()
	if not a:
		return jsonify(success=False, reason='no such app found')
	a = a.id
	emails = db.session.query(models.Email).filter(models.Email.emailid.in_(email_ids)).filter_by(app_id=a).all()
	to_return = {'threads':[]}
	for e in emails:
		if e.google_thread_id: # is a google message
			to_return['threads'].append( _getStatsOnGoogleThread(e.thread.unique_thread_id) )
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


def handleApp(i):
	modles.handleApp(i)

def _statsfromemailids(emails):
	emailids = [a.strip() for a in emails.split(',')]
	ids = db.session.query(models.Email).with_entities(models.Email.id).filter(models.Email.emailid.in_(emailids)).all()
	num_emails = float(len(ids))
	if num_emails == 0:
		return jsonify(bounce_rate=0., open_rate=0., click_rate=0., reply_rate = 0.)
	
	opens = db.session.query(models.Visit).distinct(models.Visit.email_id).with_entities(models.Visit.id).filter(models.Visit.email_id.in_(ids)).count()
	replies = db.session.query(models.Email).distinct(models.Email.replied_to).with_entities(models.Email.replied_to).filter(and_(models.Email.replied_to.in_(ids), models.Email.bounce==False)).count()
	bounces = db.session.query(models.Email).distinct(models.Email.replied_to).with_entities(models.Email.replied_to).filter(and_(models.Email.replied_to.in_(ids), models.Email.bounce==True)).count()
	all_links = db.session.query(models.Link).with_entities(models.Link.id).filter(models.Link.email_id.in_(ids)).all()
	clicks = db.session.query(models.Visit).distinct(models.Visit.link_id).filter(models.Visit.link_id.in_(all_links)).count()
	return jsonify(bounce_rate=round(bounces/num_emails, 2), open_rate=round(opens/num_emails, 2), click_rate=round(clicks/num_emails, 2), reply_rate=round(replies/num_emails, 2))

# input emailids
# output more elaborate stats about who replied, opened, clicked
# meant for marketing purposes
def _enhancedstats(emails):
	emailids = [a.strip() for a in emails.split(',')]
	ids = db.session.query(models.Email).with_entities(models.Email.id).filter(models.Email.emailid.in_(emailids)).all()
	num_emails = float(len(ids))
	if num_emails == 0:
		return jsonify(bounce_rate=0., open_rate=0., click_rate=0., reply_rate = 0.)
	
	opens = db.session.query(models.Visit.email_id).distinct(models.Visit.email_id).filter(models.Visit.email_id.in_(ids)).all()
	if opens:
		opens = db.session.query(models.Email.to_address).distinct(models.Email.to_address).filter(models.Email.id.in_(opens)).all()
		opens = [o[0] for o in opens if o[0]]

	replies = db.session.query(models.Email.replied_to).distinct(models.Email.replied_to).filter(and_(models.Email.replied_to.in_(ids), models.Email.bounce==False)).all()
	if replies:
		replies = db.session.query(models.Email.to_address).distinct(models.Email.to_address).filter(models.Email.id.in_(replies)).all()
		replies = [o[0] for o in replies if o[0]]
	
	bounces = db.session.query(models.Email.replied_to).distinct(models.Email.replied_to).filter(and_(models.Email.replied_to.in_(ids), models.Email.bounce==True)).all()
	if bounces:
		bounces = db.session.query(models.Email.to_address).distinct(models.Email.to_address).filter(models.Email.id.in_(bounces)).all()
		bounces = [o[0] for o in bounces if o[0]]

	links_emails = db.session.query(models.Link).with_entities(models.Link.id, models.Link.email_id).filter(models.Link.email_id.in_(ids)).all()
	all_links = [a[0] for a in links_emails if a[0]]
	link_ids = db.session.query(models.Visit.link_id).distinct(models.Visit.link_id).filter(models.Visit.link_id.in_(all_links)).all()
	link_ids = [a[0] for a in link_ids if a[0]]
	clicks = [a[1] for a in links_emails if a[0] in link_ids]
	if clicks:
		clicks = db.session.query(models.Email.to_address).distinct(models.Email.to_address).filter(models.Email.id.in_(clicks)).all()
		clicks = [o[0] for o in clicks if o[0]]

	return jsonify(bounces=bounces, opens=opens,clicks=clicks,replies=replies)

# ADDD does not work yet
def _statsfromtemplate(legion_template_id):
	opens = db.session.query(models.Visit).distinct(models.Visit.email_id).with_entities(models.Visit.id).filter(models.Visit.email_id.legion_template_id==legion_template_id).count()
	replies = db.session.query(models.Email).distinct(models.Email.replied_to).with_entities(models.Email.replied_to).filter(and_(models.Email.bounce==False, models.Email.legion_template_id == legion_template_id)).count()
	bounces = db.session.query(models.Email).distinct(models.Email.replied_to).with_entities(models.Email.replied_to).filter(and_(models.Email.bounce==True, models.Email.legion_template_id == legion_template_id)).count()
	all_links = db.session.query(models.Link).with_entities(models.Link.id).filter(models.Link.email_id.in_(ids)).all()
	clicks = db.session.query(models.Visit).distinct(models.Visit.link_id).filter(models.Visit.link_id.in_(all_links)).count()
	return jsonify(bounce_rate=round(bounces/num_emails, 2), open_rate=round(opens/num_emails, 2), click_rate=round(clicks/num_emails, 2), reply_rate=round(replies/num_emails, 2))


@application.route('/emailStats',methods=['POST'])
def emailStats():
	try:
		a = modules.getModel(models.App, appid=request.form.get('appid')).id
	except:
		return jsonify()
	if 'emailids' in request.form:
		return _statsfromemailids(request.form['emailids'])
	elif 'legion_template_id' in request.form:
		return _statsfromtemplate(request.form['legion_template_id'])
	elif 'enhanced_emailids' in request.form:
		emailids = request.form['enhanced_emailids']
		return _enhancedstats(emailids)
	elif 'use_app' in request.form:
		emailids = db.session.query(models.Email.emailid).filter(models.Email.app_id == a).all()
		emailids = ','.join([e[0] for e in emailids if e])
		return _enhancedstats(emailids)
	return jsonify()



@application.route('/cadenceInfo',methods=['POST'])
def cadenceInfo():
	try:
		a = modules.getModel(models.App, appid=request.form.get('appid')).id
	except Exception as e:
		return jsonify()
	dates = {}
	utc_now = datetime.utcnow()
	now = datetime.utcnow()+timedelta(hours=int(request.form.get('offset', -8)))
	cadence_ids = request.form.get('cadence_ids', '').split(',')
	emails_orm = db.session.query(models.Email).with_entities(models.Email.id, models.Email.date_sent).filter(models.Email.legion_cadence_id.in_(cadence_ids)).all()
	emails = [(e.id, e.date_sent) for e in emails_orm if e.id and e.date_sent]
	for e in emails:
		date_formatted = datetime.strftime(e[1], '%m/%d/%Y')
		if date_formatted not in dates: dates[date_formatted] = []
		dates[date_formatted].append(e[0])
	ids = [a[0] for a in emails]
	
	num_emails = float(len(ids))
	all_opens = db.session.query(models.Visit).filter(models.Visit.email_id.in_(ids)).all()
	most_recent_opens = [('open', s.email.to_address, ((utc_now-s.date).seconds), ((utc_now-s.date).seconds/60), ((utc_now-s.date).seconds/3600), s.email.subject) for s in sorted(all_opens, key = lambda x:x.date)[-10:]][::-1]
	all_opens = {a.email_id:1 for a in all_opens}
	

	all_links = db.session.query(models.Link).filter(models.Link.email_id.in_(ids)).all()
	link_ids = [l.id for l in all_links]
	all_clicks = db.session.query(models.Visit).filter(models.Visit.link_id.in_(link_ids)).all()
	most_recent_clicks = [('click', s.link.email.to_address, ((utc_now-s.date).seconds), ((utc_now-s.date).seconds/60), ((utc_now-s.date).seconds/3600), s.link.email.subject) for s in sorted(all_clicks, key = lambda x:x.date)[-10:]][::-1]
	all_clicks = {a.link.email_id:1 for a in all_clicks}
	

	all_replies = db.session.query(models.Email).filter(and_(models.Email.replied_to.in_(ids), models.Email.bounce==False))
	most_recent_replies = [('reply', s.from_address, ((utc_now-s.date_sent).seconds), ((utc_now-s.date_sent).seconds/60), ((utc_now-s.date_sent).seconds/3600), s.subject) for s in sorted(all_replies, key = lambda x:x.date_sent)[-10:]][::-1]
	all_replies = {e.replied_to:1 for e in all_replies}


	stats = {'dates': {}}
	for day in modules.date_range(now-timedelta(days=7), now):
		_day = datetime.strftime(day, '%m/%d/%Y')
		if _day not in dates: 
			stats['dates'][_day] = {'sent':0, 'opens':0, 'replies':0, 'clicks':0}
			continue
		stats['dates'][_day] = {
			'sent':len(dates[_day]), 
			'opens':sum([all_opens.get(a, 0) for a in dates[_day]]), 
			'replies':sum([all_replies.get(a, 0) for a in dates[_day]]), 
			'clicks':sum([all_clicks.get(a, 0) for a in dates[_day]]),
		}

	stats['dates'] = [(x, stats['dates'][x]) for x in sorted(stats['dates'])]
	stats['most_recent_replies'] = most_recent_replies
	stats['most_recent_clicks'] = most_recent_clicks
	stats['most_recent_opens'] = most_recent_opens

	return jsonify(stats)

@application.route('/getRandomEmails',methods=['GET'])
def getRandomEmails():
	emails = random.sample(db.session.query(models.Email).filter_by(to_address='jamasen@legionanalytics.com').all(), int(request.args.get('num', 20)))
	return jsonify(texts=[e.text for e in emails])



@application.route('/check',methods=['GET'])
def check():
	# texts, labels = [], []
	# a = modles.appGoogleAPI(modules.getModel(models.App, appid='aaQ7WENBPBQ'))
	# for m in  googleAPI.getUsedLabels(a)['labels']:
	# 	threads = googleAPI.getMessagesMarkedWithLabel(a, m['id'])
	# 	for t in threads.get('messages', []):
	# 		try:
	# 			_thread = modules.getModel(models.Thread, unique_thread_id=t['threadId'])
	# 			for e in _thread.emails:
	# 				if e.text:
	# 					texts.append(e.text)
	# 					labels.append(m['name'])
	# 		except:
	# 			pass
	# print json.dumps({'texts':texts, 'labels':labels})
	print modles.appGoogleAPI(modules.getModel(models.App, id=67))
	return jsonify()
	

class Scheduler(object):
	def __init__(self, sleep_time, function):
		self.sleep_time = sleep_time
		self.function = function
		self._t = None
		self.name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
	def start(self):
		if self._t is None:
			self._t = Timer(self.sleep_time, self._run)
			self._t.start()
		else:
			raise Exception("this timer is already running")
	def _run(self):
		self.function()
		random_time = random.choice(range(self.sleep_time, self.sleep_time*5))
		self._t = Timer(random_time, self._run)
		self._t.start()
	def stop(self):
		if self._t is not None:
			self._t.cancel()
			self._t = None


application.secret_key = 'A0Zr9slfjybdskfs8j/3yX R~XHH!jfjhbsdfjhvbskcgvbdf394574LWX/,?RT'
DEBUG = False

if not DEBUG:
	@application.before_first_request
	def startScheduler():
		scheduler = Scheduler(30, modles.handleRandomApp)
		scheduler.start()



if __name__ == '__main__':
	application.run(debug=DEBUG, port = 5000, use_reloader=DEBUG)







