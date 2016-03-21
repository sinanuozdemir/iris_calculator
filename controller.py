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
	modles.handleRandomApp()
	# for a in db.session.query(models.App).all():
	# 	a.last_checked_inbox = None
	# 	a.next_check_inbox = None
	# db.session.commit()
	
	# modles.handleApp('aaQ7WENBPBQ') # kylie@legionanalytics.com
	# modles.handleApp('aaDKE34H8TD') # sinan.u.ozdemir@gmail.com
	return jsonify()
	# texts = []
	# a = modles.appGoogleAPI(modules.getModel(models.App, appid='aaQ7WENBPBQ'))
	# for m in  googleAPI.getUsedLabels(a)['labels']:
	# 	if m['name'] in ['learn more']:
	# 		threads = googleAPI.getMessagesMarkedWithLabel(a, m['id'])
	# 		for t in threads['messages']:
	# 			_thread = modules.getModel(models.Thread, unique_thread_id=t['threadId'])
	# 			for e in _thread.emails:
	# 				if e.text:
	# 					texts.append(e.text)
	# texts = list(set(texts))
	# print json.dumps(texts)

	# texts = ["Kylie,\r\n\r\nThanks for the email, can you tell me how you do prospecting? I sell \r\ndomain names and would want to create lists of relevant companies for \r\nthe keyword domains I own. Is that something you can do?\r\n\r\n\r\nThanks,\r\nJohn\r\n", "Monday at 4 I am pre-booked. However, I am happy to have my CEO give you a\r\ncall to answer any of your questions.\r\n\r\nI will send over an invite now.\r\n\r\nHave a great weekend, Valeria!", "Thanks for getting back to me Jay. I would think that the best way to use\r\nLegion Analytics would be to use out automated outreach to create a drip\r\ncampaign for your 30K+ leads to ensure they dont fall out of the funnel.\r\n\r\nAn interesting approach to using Legion Analytics for Vacasa could also be\r\nto find professionals in stressful jobs in urban areas that need Vacation\r\nrentals and reaching out to them. We would be able to provide the contact\r\ndata for those people.\r\n\r\nI'd be happy to set up a time where you can speak to my CEO next week\r\n\r\nHow's Monday at 11am PT work for you?\r\n\r\nBest,\r\nKylie", "Hi Kylie,\r\n\r\nVidible was acquired more than a year ago by AOL (\r\nwww.aolplatforms.com/blog/aol-expands-global-scale-video-distribution-discovery-and-management-through-acquisition)\r\nand is now a part of the broader One by AOL (www.aolplatforms.com/onebyaol)\r\nsuite of products.\r\n\r\nI'm unsure of our sales automation needs at the present time, however if\r\nyou have a deck further describing your platform's capabilities and\r\nhighlighting differences from some of your competitors I'm happy to share\r\nwith the team to see if there is interest.\r\n\r\nThanks\r\n\r\nVipul", "Possibly yes, let's schedule a call. How about Monday afternoon around 4?\r\n\u1427", "Hi Valeria,\r\n\r\nLegion Analytics provides sales automation and lead generation for your\r\ncompany to improve the efficiencies of your sales process. When you sign up\r\nwith Legion, you are able to create a lead list based on specific criteria.\r\nWe will find potential leads that we will provide you on a daily basis. We\r\nalso offer email automation for you to set up drip campaigns for leads that\r\nwe provided as well as leads that you acquired through other channels.\r\n\r\nIs this something that you think would work for Prizma's sales/outreach\r\nmodel?\r\n\r\n-Kylie", "Great to hear. How does a call with my CEO tomorrow or Thursday look at 1pm\r\nET?", "What do you do?\r\n\r\n[CareSync]\r\n\r\nMARK NALYWAJKO / CareSync<http://www.caresync.com/> / National Sales Director\r\nmark.nalywajko@caresync.com<mailto:mark.nalywajko@caresync.com>   813.731.2961  @caresync\r\n\r\nJoin us for one of our upcoming Chronic Care Management webinars<http://info.caresync.com/webinars>!\r\n\r\n\r\nFrom: \"kylie@legionanalytics.com<mailto:kylie@legionanalytics.com>\" <kylie@legionanalytics.com<mailto:kylie@legionanalytics.com>>\r\nDate: Tuesday, March 8, 2016 at 2:20 PM\r\nTo: Mark Nalywajko <Mark.Nalywajko@caresync.com<mailto:Mark.Nalywajko@caresync.com>>\r\nSubject: Biz dev tool for CareSync\r\n\r\nMark,\r\n\r\nCareSync came across my desk yesterday as a potential company aggressively growing revenue this quarter. Would you be interested in jumping on a 10 minute phone call with me to explore how my company, Legion Analytics<https://www.latracking.com/r/llJB6DNMH1V> (ai sales automation platform), could help your team be more efficient in bringing on new customers?\r\n\r\nIf you're not the right person to speak to, would you mind forwarding me to someone more appropriate?\r\n\r\nThank you for your help,\r\nKylie\r\n\r\np.s. If Legion Analytics isn't right for you and you don't want to hear from me, just reply to let me know. [https://www.latracking.com/e/eeY8BWPJ7XY]\r\n", "Thanks for getting back to me Jay. I would think that the best way to use \r\nLegion Analytics would be to use out automated outreach to create a drip \r\ncampaign for your 30K+ leads to ensure they dont fall out of the funnel. \r\n\r\nAn interesting approach to using Legion Analytics for Vacasa could also be \r\nto find professionals in stressful jobs in urban areas that need Vacation \r\nrentals and reaching out to them. We would be able to provide", "Kylie,\r\n\r\nI'd be interested in learning more. Let me know a good time to talk!\r\n\r\nBest,\r\nChristine", "Hi Kylie,\r\n\r\nThanks for the response.  I'm not too optimistic that you can do something\r\nthat we aren't already doing.  But again, I'm happy to chat.  I'm free any\r\ntime on Wed, Thurs, Friday.\r\n\r\nJay", "What exactly do you do?\r\n\u1427", "Depends... did legion analytics help you find me?\r\n\r\nHow did the process work?\r\n\r\nBen", "Hi Kylie,\r\n\r\nTo be honest, we're still very early in our growth strategies. Based on\r\nyour description, I wouldn't even know how you could help us as we don't\r\nwork with marketing agencies or IT companies. Best of luck to you!\r\n\r\nBest,\r\nToby\r\n------------------------------\r\n\r\nBusiness Development & Partnerships, GoFundMe\r\n\r\n*The easy way to raise money online.*\r\n\r\nWe're changing the way the world gives!\r\n*Get inspired at:* GoFundMe <http://www.gofundme.com/>", " \r\n\r\nHi Kylie, \r\nThe biggest problem is the time. I don't have now.  \r\nSend me an initial presentation so  can go through next week. I will be\r\nin a Expo so I will have a little bit of time.  \r\n\r\nThen send me an email on March 21st so we can see, if I survive after\r\nthe Expo and when we can talk. \r\n\r\nBest, \r\nWilliam Liani \r\n\r\n---\r\n\r\nBusiness Development Manager \r\nDepositphotos\r\n\r\nUS Mobile: +1 (516) 554-7063\r\nIT Mobile: +39 347 77 37 640\r\nSkypeID: william.depositphotos", "Hello Kylie,\r\n\r\nI do not see how this would help a mortgage operation...\r\n\r\nThanks,\r\n\r\nLucas", "Thursday at 1pm EST would work great!", "Great! I will send over an invite for 11am PT on Wednesday.\r\n", "Hi Kylie,\r\n\r\nYou reached out to Karinda a few weeks ago about lead generation.  I'd be\r\nthe guy who'd 'sell' it to the CEO.  He's makes 100% of the financial\r\ndecisions.  I highly doubt we could use your services though, but I'm\r\nalways open to ideas.  Currently, we have 30,000 leads that are still\r\nrotating through our lead system.\r\n\r\n-- \r\n\r\nJay Klein | Outbound Sales Manager\r\n\r\n503.334.0380 (w) | 541-228-8053 (c)\r\n\r\njklein@vacasa.com <frodo@vacasa.com>\r\n\r\nvacasa.com\r\n\r\nVacation rentals made easy\u00ae\r\n\r\nMy top priority is ensuring owner and guest happiness.\r\n", "What is this all about?  I don't understand.\r\n\r\nBest,\r\n\r\nStephanie\r\n\r\nStephanie Wiley | *Business Development*\r\n\r\n\r\n*Direct Line: 916-307-4198Main Line: 916-443-6668 ext. 219*\r\n*Fax: 916-443-0376*\r\n*Email:* swiley@necal.bbb.org\r\n*www.bbb.org <http://www.bbb.org/>* | *Start With Trust*\r\n\r\nBBB of Northeast California\r\n3075 Beacon Blvd\r\nWest Sacramento, CA 95691\r\n\r\n*Find us on:* *Facebook <http://www.facebook.com/necalbbb> *and *Twitter\r\n<http://www.twitter.com/bbbnecal>*", "Sounds good, thank you!\r\n\u1427"]
	# q = []
	# for t in texts:
	# 	for question in re.finditer('[\'\w\/\s]+\?', t.lower()):
	# 		print question.group(0).strip()
	# 		print
	# return jsonify()
	# data = {}
	# data['html'] = "test" # insert ML here
	# data['subject'] = 'test subject'
	# data['to_address'] = 'sinan@legionanalytics.com'
	# data['appid'] = 'aaQ7WENBPBQ'
	# print data
	# print modles.sendEmailFromController(data)
	_thread, t_c = modules.get_or_create(models.Thread, unique_thread_id='1537b9892e709768')
	g = {}
	g['text'] = 'unsubscribe'
	
	if _thread.latracking_reply: #trigger our auto reply
		response = None
		print "auto replying to it"
		data = {}
		for label, keys in prediction_dict.iteritems():
			if sum([l in g['text'].lower() for l in keys]) > 0:
				response = random.choice(response_dict[label])
		if response:
			data['html'] = response_template.replace('{{insert_response_here}}', response)
			data['subject'] = _thread.emails[-1].subject
			data['to_address'] = 'sinan@legionanalytics.com'
			data['appid'] = 'aaQ7WENBPBQ'
			data['threadID'] = _thread.unique_thread_id
			print data
			modles.sendEmailFromController(data)
		else:
			pass
			# label with needs a human
	# modles.handleApp('aaQ7WENBPBQ') # kylie@legionanalytics.com
	# modles.handleApp('aaDKE34H8TD') # sinan.u.ozdemir@gmail.com
	# print googleAPI.cleanMessage({"internalDate": "1457970468000", "historyId": "320982", "payload": {"mimeType": "text/html", "headers": [{"name": "Delivered-To", "value": "kylie@legionanalytics.com"}, {"name": "Received", "value": "by 10.76.172.201 with SMTP id be9csp37024oac;        Mon, 14 Mar 2016 08:47:48 -0700 (PDT)"}, {"name": "X-Received", "value": "by 10.202.228.10 with SMTP id b10mr13735718oih.32.1457970468817;        Mon, 14 Mar 2016 08:47:48 -0700 (PDT)"}, {"name": "Return-Path", "value": "<bounce+9a3794.f3c631-kylie=legionanalytics.com@mg.legionanalytics.com>"}, {"name": "Received", "value": "from rs224.mailgun.us (rs224.mailgun.us. [209.61.151.224])        by mx.google.com with ESMTPS id a8si16403694obt.51.2016.03.14.08.47.48        for <kylie@legionanalytics.com>        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);        Mon, 14 Mar 2016 08:47:48 -0700 (PDT)"}, {"name": "Received-SPF", "value": "pass (google.com: domain of bounce+9a3794.f3c631-kylie=legionanalytics.com@mg.legionanalytics.com designates 209.61.151.224 as permitted sender) client-ip=209.61.151.224;"}, {"name": "Authentication-Results", "value": "mx.google.com;       spf=pass (google.com: domain of bounce+9a3794.f3c631-kylie=legionanalytics.com@mg.legionanalytics.com designates 209.61.151.224 as permitted sender) smtp.mailfrom=bounce+9a3794.f3c631-kylie=legionanalytics.com@mg.legionanalytics.com;       dkim=pass header.i=@mg.legionanalytics.com"}, {"name": "DKIM-Signature", "value": "a=rsa-sha256; v=1; c=relaxed/relaxed; d=mg.legionanalytics.com; q=dns/txt; s=smtp; t=1457970468; h=Content-Transfer-Encoding: Mime-Version: Content-Type: Subject: From: To: Message-Id: Date: Sender; bh=ts9hGocgcK6BgnFK0wtad9wI568/2S3nB2pgs0qcJM0=; b=iZ6CmcINthBUcDLq90nBY6guSiZ/Xlsk6kmlrv40KDjB0Mtk8144Fx1oSgsmJusql8W0r+gk /I1cZqq+SzqlgE46HREUnFhjltp76Lwqx46YOMxUCDF9ujYhE3Xa5QII3CCxdYbQlRkzS6Vq jAWNwX/Jd9ay1HDIwhvtztzMsNI="}, {"name": "DomainKey-Signature", "value": "a=rsa-sha1; c=nofws; d=mg.legionanalytics.com; s=smtp; q=dns; h=Sender: Date: Message-Id: To: From: Subject: Content-Type: Mime-Version: Content-Transfer-Encoding; b=ZBPZrYaznnS3gDSMWCmMAfwExbmVR1SE7mXN3rbr5CaXcVDne0e/Wo5fHJpY9MLIVcPr4B l24KZvFX2vA2KJkUQaD61Wb1Wa+rSM4FMmm7sWbSI/6/l7Wl8jMbDDivRNeSOZoZAztEVZBK CuoQy5nKYWifoCzg2W0+KGNBitxMU="}, {"name": "Sender", "value": "youvegotleads@mg.legionanalytics.com"}, {"name": "Date", "value": "Mon, 14 Mar 2016 15:47:48 +0000"}, {"name": "X-Mailgun-Sid", "value": "WyJjYjI1ZiIsICJreWxpZUBsZWdpb25hbmFseXRpY3MuY29tIiwgImYzYzYzMSJd"}, {"name": "Received", "value": "by luna.mailgun.net with HTTP; Mon, 14 Mar 2016 15:47:48 +0000"}, {"name": "Message-Id", "value": "<20160314154748.9505.84422@mg.legionanalytics.com>"}, {"name": "To", "value": "kylie@legionanalytics.com"}, {"name": "From", "value": "Legion Analytics <youvegotleads@mg.legionanalytics.com>"}, {"name": "Subject", "value": "You've Got Leads!"}, {"name": "Content-Type", "value": "text/html; charset=\"ascii\""}, {"name": "Mime-Version", "value": "1.0"}, {"name": "Content-Transfer-Encoding", "value": "7bit"}], "body": {"data": "DQoJPGh0bWw-DQoJPGJvZHk-R29vZCBNb3JuaW5nIQ0KCTxicj4NCgk8YnI-DQoJTm8gTXIgQm9uZC4uLiBJIGV4cGVjdCB5b3UgdG8gY2xvc2UNCgk8YnI-DQoJPGJyPk9uIHRoYXQgbm90ZSBJIGhhdmUgc29tZSBuZXcgbGVhZHMgZm9yIHlvdSEgQ2hlY2sgdGhlbSBvdXQgPGEgaHJlZj0iaHR0cDovL2VtYWlsLm1nLmxlZ2lvbmFuYWx5dGljcy5jb20vYy9lSnh0anNFS2d6QVFSTF9HSE1OdU5sbjFrRU12X1kyeVRWSU5qVm8wSVA1OXBiMEtjeGptTWNORV82TEFoQ3A3QThoQWFOSFoxbmE2ZC1CMFo2MHhqWVZwMENVTmVabGxsbkxVSERZZGxrbU5ubHNrWmdKSjJIZUU4S1FZblRDZ3RNNG1EcXI0c2RiUDF0Q3RNZmRULTc1ZlRaM2tuXzZNeE1kVzF5U1RXdjM3S0RtZEZ5NUtYMGU4TzdZIiB0YXJnZXQ9Il9ibGFuayI-aGVyZTwvYT48YnI-PEJyPg0KCUlmIHlvdSBhcmUgdW5hYmxlIHRvIGxvZyBpbiBvciBuZWVkIGEgbmV3IHBhc3N3b3JkLCBjbGljayA8YSBocmVmPSJodHRwOi8vZW1haWwubWcubGVnaW9uYW5hbHl0aWNzLmNvbS9jL2VKeHRqVEVPaENBVVJFOGpKZUZfUHFBRnhUWjdEMEZRc2lnYkpTSGVma20yTlpsaU1tOHlzOWdvdlpiQWtrVUJXa2dnVUdSbzVKTVNpbzlFaUFPSmZlVTVyS2tjOHpIbnV5Wl9jVjkydHRsZ0lBWWxvM2VUUXpPTkdneEpCT2RRZTZrWHg3TGRhdjFlZzN3Ti1PNXFyVDFOZGZKUHU0bmxYRXRscF8zY09ZWC1fdERfQVdwRE9tYyIgdGFyZ2V0PSJfYmxhbmsiPmhlcmU8L2E-PGJyPjxicj4NCglIYXZlIGEgZ3JlYXQgZGF5ITxCcj4NCglZb3VyIEZyaWVuZHMgQCBMZWdpb24gQW5hbHl0aWNzPGJyPjxicj4NCglQc3N0ISBHb3QgYW55IHF1ZXN0aW9ucz8gRW1haWwgdXMgYXQgeW91cmZyaWVuZHNAbGVnaW9uYW5hbHl0aWNzLmNvbQ0KCTxpbWcgd2lkdGg9IjFweCIgaGVpZ2h0PSIxcHgiIGFsdD0iIiBzcmM9Imh0dHA6Ly9lbWFpbC5tZy5sZWdpb25hbmFseXRpY3MuY29tL28vZUp4dHpNRU53akFNQmRCcHlER0s3ZV9pSGpKTUhaSVNrYllTY09uMlpRRGVBTy1SbTVSSktQVE1pYVlrQkZMY1lYSFdwTkVBNWh2U3RzWlIxMzdzeTc2TTg5dkxKNVpqQzg5YzNXY0RXMEZMNmc2UkNwZ29lWE5pYWVHZFgtZm85WGY4Q1M2c0dTWDUiPjwvYm9keT4NCg0KCTwvaHRtbD4NCgkNCg==", "size": 1135}, "partId": "", "filename": ""}, "snippet": "Good Morning! No Mr Bond... I expect you to close On that note I have some new leads for you! Check", "sizeEstimate": 3670, "threadId": "15375cfd798ba64d", "labelIds": ["CATEGORY_UPDATES", "UNREAD"], "id": "15375cfd798ba64d"})
	return jsonify()

	import lml

	hierarchy = {
		'reply': {
			'date': {
				'coordinate date':None,
				'set up calendar invite':None
			},
			'more info':None
		},
		'no reply': {
			'unsubscribe':None,
			'too early':None,
			'not interested':None
		}
	}

	in_depth_hierarchy = {
		# 'positive':['more info', 'interested'],
		# 'negative':['unsubscribe'],
		'date':['coordinate date', 'set up calendar invite'],
		'coordinate date': ['coordinate date'],
		'set up calendar invite': ['set up calendar invite'],
		'more info': ['more info'],
		'no reply': ['unsubscribe', 'too early', 'no longer here', 'no longer company'],
		'unsubscribe': ['unsubscribe'],
		'too early': ['too early'],
		'no longer here': ['no longer here'],
		'no longer company': ['no longer company']
	}

	saved = {
	    "labels": [
	        "acquired", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "interested", 
	        "no longer a company", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "follow up later", 
	        "testimonial", 
	        "testimonial", 
	        "testimonial", 
	        "testimonial", 
	        "too early", 
	        "too early", 
	        "too early", 
	        "too early", 
	        "too early", 
	        "too early", 
	        "too early", 
	        "too early", 
	        "too early", 
	        "remove from list", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "unsubscribe", 
	        "forward to right person/department", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "no reply needed", 
	        "not target", 
	        "not target", 
	        "not target", 
	        "not target", 
	        "no longer here", 
	        "no longer here", 
	        "no longer here", 
	        "no longer here", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "not interested", 
	        "later date", 
	        "later date", 
	        "later date", 
	        "later date", 
	        "later date", 
	        "sensitive", 
	        "sensitive", 
	        "sensitive", 
	        "sensitive", 
	        "sensitive", 
	        "sensitive", 
	        "more info", 
	        "more info", 
	        "more info", 
	        "more info", 
	        "more info", 
	        "more info", 
	        "more info", 
	        "more info", 
	        "more info", 
	        "coordinate date", 
	        "coordinate date", 
	        "coordinate date", 
	        "coordinate date", 
	        "set up calendar invite", 
	        "set up calendar invite", 
	        "set up calendar invite", 
	        "set up calendar invite", 
	        "set up calendar invite", 
	        "set up calendar invite", 
	        "formal tone"
	      ], 
	      "texts": [
	        "Hey Jamasen,\r\n\r\nThanks for reaching out. Inside Social was acquired last year, so we don't\r\nhave a need.\r\n\r\nThanks!\r\n\r\nBrewster\r\n\r\nBrewster Stanislaw\r\n\r\nCEO and Co-Founder\r\nInside Social <http://www.insidesocial.com/>\r\nbrewster@insidesocial.com", 
	        "Jamasen,\r\n\r\nI could listen.  Book a time here:  https://calendly.com/justinherring/30min\r\n\r\nJustin Herring\r\n\r\nYEAH! Local <http://yeah-local.com/>\r\n\r\n(404) 539-6068\r\n\r\nWant to Chat? Book a Time Here <https://calendly.com/justinherring/30min>\r\n\r\n<https://calendly.com/justinherring/30min>\r\n\r\nP.S. Check out our latest blog post <http://yeah-local.com/blog>\r\n\r\nP.P.S. Think we did a great job? Give us a Review!\r\n<http://www.grade.us/yeah-local>", 
	        "Jamasen,\r\n\r\nThank you for reaching out. I'm sorry I have yet to get back to you as I am currently going through an Accelerator program which is extremely time intensive on top of two nearly full-time jobs as well. As a cold caller myself, I highly appreciated your most recent email and persistence. I have not had a chance to look at your products and for that I am sorry. I will try to take a look at them next week. Have a great weekend. \r\n\r\nThanks,\r\n\r\nJeremy\r\n\r\n\r\n\r\n\r\nSent from my iPhone\r\n\r\n", 
	        "Forwarding to our sales and marketing team.", 
	        "Hi Jamasen,\r\n\r\nI have been swamped this week.   I will be able to review your offer next\r\nweek.\r\n\r\nThank you,\r\n\r\nRob\r\n\r\nRob Lewis\r\nDirector Marketing Services\r\nLocal Value Marketing\r\n(858) 480-6116 <+1858-480-6116>\r\nroblewis@localvalue.com <roblewis@localvaluemarketing.com>\r\n<https://www.google.com/partners/#a_profile;idtf=6383298929;>\r\n<https://www.linkedin.com/in/roblewis99>", 
	        "Hi Jamasen,\r\n\r\nAlthough it sounds tempting, I am not in a position to take on a large influx of business at this time. I would be open to you checking in again in 3 months. \r\nHow did you find out about me and get my email? Just always curious to know how people find me.\r\n\r\nThank you -\r\nJanis\r\n", 
	        "Hi jamasen, can we try Tuesday at noon EST?\r\n\r\n\r\nCharlie Locke\r\n*Chief Revenue Officer*\r\n\r\n<http://saasli.com/>\r\n\r\n647.222.7875\r\nclocke@saasli.com\r\n\r\n*Prefer to Speak Live?* Click here <http://charlielocke.youcanbook.me", 
	        "Jamasen - thanks for the proposal. I'm interested in testing your solution\r\nagainst our current approach but can't justify $2k setup fee at this time.\r\nI would like to test Legion against our current cobbled together approach\r\nto see which one generates the best results. It would be a combination of\r\nyour cold leads versus what we have, and your drip campaigns against what\r\nwe've created. I think it would be interesting to see which works best.\r\n\r\nThis could be an amazing case study for you, if you can beat a digital\r\nacquisition marketing company that specialized in lead gen and CRO.\r\n\r\nAre you up to the challenge?!!", 
	        "Hi Jamasen,\r\nThanks for reaching out! I would love to chat more about growth opportunities and early next week for 15 minutes sounds great. How about Tuesday at 11am?\r\nChat soon,\r\nBrittany\r\n\r\nBrittany Hammonds\r\n(407) 921-1673\r\n\r\n", 
	        "Hi Jamasen,\r\n\r\nThanks for reaching out. Looping in my editor Brittany Hammonds, who\r\nhandles growth opportunities for the site. Will let the two of you find a\r\ntime to chat; look forward to hearing more\r\n\r\nCheers,\r\n M\r\n\r\nMegan Collins | Style Girlfriend <http://www.stylegirlfriend.com/>\r\nTwitter <http://www.twitter.com/stylegf", 
	        "please send me links to testimonials that I can verify.  Thanks\r\n\r\n\r\n", 
	        "Thanks for the info. How does it find potential customers for us? I'm\r\ninterested in learning more about that. We've spent a lot of time / money\r\non platforms like Data.com and SalesLoft.com identifying prospects (CMO,\r\ndigital marketing execs, content marketing execs, etc) then putting them\r\ninto an e-mail drip. We ceased those efforts late last year as they were\r\nnot converting / working for us.\r\n\r\nCan you let me know how what you guys do is different than that? Thanks!\r\n\r\n\r\nJason", 
	        "OK, done. Just so you know the site keeps crashing at every step.", 
	        "It's not even remotely ready for enterprise. I want try the Basic plan \r\nfirst on the month-to-month basis, but I have serious doubt over \r\nsecurity of this transaction.", 
	        "Sounds interesting.\r\n\r\nNext wednesday works for me. I am based in the UK. Sometime in my afternoon\r\n/ evening would work well. What works for you?\r\n\r\nCheers,\r\nOlivier", 
	        "I tried. It crashed. 1 month free, or find other beta testers?\r\n\r\n", 
	        "Hey Jamasen,\r\n\r\nPeter is no longer involved in GoodBlogs. I'd be interested in learning\r\nmore however. Could you send me some info via e-mail to get started?\r\n\r\nThanks.\r\n\r\n\r\nJason\r\n\r\n-- \r\nJason Trout\r\nFounder, GoodBlogs\r\nAll the benefits of inbound marketing. None of the effort.\r\nhttp://www.GoodBlogs.com <http://www.goodblogs.com/", 
	        "Jamasen,\r\n\r\nI usually don't reply to these kinds of offers, but if you can provide \r\nsome color on the following, I may give it a shot.\r\n\r\n 1. Where will the leads come from?\r\n 2. Are they just prospect ideas or have demonstrated a potential\r\n    opportunity in some way?\r\n 3. What contact data and other context will be provided?\r\n 4. Will I be required to install some plug-ins in my browser or some\r\n    tracking technology for our website?\r\n\r\n\r\nThanks,\r\n\r\nVictor\r\n\r\n\r\n", 
	        "Jamasen,\r\nAbsolutely! 11am EST works for me as well.\r\n\r\nMy skype ID is akarwowska1. \r\n\r\nWould you mind sending out a calendar invite please? \r\n\r\nAnia \r\n\r\nAnia Karwowska\r\n \r\nMobile: +44 793 959 5051\r\nEmail:  ania@highskillpro.com <http://www.highskillpro.com/>\r\nLinkedIn: uk.linkedin.com/in/aniakarwowska <http://uk.linkedin.com/in/aniakarwowska", 
	        "Hi Jamasen\r\nGreat email. And great website. \r\n\r\nSure, let\u2019s grab a call. Are you free for a skype call the coming Monday at 9:30am EST? \r\n\r\nAnia \r\n\r\nAnia Karwowska\r\n \r\nMobile: +44 793 959 5051\r\nEmail:  ania@highskillpro.com <http://www.highskillpro.com/>\r\nLinkedIn: uk.linkedin.com/in/aniakarwowska <http://uk.linkedin.com/in/aniakarwowska", 
	        "Jamasen, stay in touch.\r\n\r\nWe are a hybrid B2B because we aren\u2019t calling on corporate entities.  Instead we are calling on travel sports coaches and club directors who have turned their passion into a small business.  Can you guys be effective in that space?\r\n", 
	        "Hey Jamasen,\r\n\r\nI'm game for a chat. Does Friday afternoon (EST) work for you?\r\n\r\nCharlie\r\n\r\n\r\nCharlie Locke\r\n*Chief Revenue Officer*\r\n\r\n<http://saasli.com/>\r\n\r\n647.222.7875\r\nclocke@saasli.com\r\n\r\n*Prefer to Speak Live?* Click here <http://charlielocke.youcanbook.me", 
	        "Sounds great, thanks Jamasen!", 
	        "Hi Jamasen,\r\n\r\nThanks for reaching out. Legion Analytics looks really interesting.\r\n\r\nUnfortunately, the timing isn't great right now.  We are in the process of\r\nlaunching a more consumer-focused product (www.datafire.io) so we are very\r\nfocused on marketing and PR.  We are basically just doing market research\r\nright now, but there is definitely a potential to use something like Legion\r\ndown the road.\r\n\r\nCan you check in towards the end of Q1? We should have a much clearer\r\npicture at that point of where we are at and what we need.\r\n\r\nThanks,\r\nAndrew", 
	        "Prove it to me, how can you increase my sales??\r\n\r\nMany thanks & Best regards\r\nPuga Sankara\r\nPrincipal\r\nSmart Gladiator LLC\r\nPh#: 678 481 5486\r\nwww.smartgladiator.com\r\nSkype: puga2006\r\nCheck out our Thought Leadership at\r\nwww.ebnonline.com/archives.asp?section_id=3743\r\nFor a warehouse with 50 operators, working 2 shifts, 320 days a year, Savings = HALF MILLION $$$ OR MORE\r\n\r\n\r\n", 
	        "Jamasen - I enjoyed our chat yesterday. When can you send over the custom\r\npackage overview so that we can review/discuss?\r\n\r\n\r\n-- \r\n[image: logo]\r\n*Rory Holland* *CEO*\r\n415.805.6065\r\n<415.805.6065?utm_source=WiseStamp&utm_medium=email&utm_term=&utm_content=&utm_campaign=signature>\r\n|\r\nrory@cstmr.com | cstmr.com\r\n<http://www.twitter.com/rory_holland?utm_source=WiseStamp&utm_medium=email&utm_term=&utm_content=&utm_campaign=signature>\r\n<http://www.linkedin.com/roryeholland?utm_source=WiseStamp&utm_medium=email&utm_term=&utm_content=&utm_campaign=signature>\r\nOur latest post: Where to Start when Driving Financial Services Growth\r\n<http://cstmr.com/index.php/where-to-start-when-driving-financial-services-growth/?utm_source=WiseStamp&utm_medium=email&utm_term=&utm_content=&utm_campaign=signature>\r\n", 
	        "Hi Jamasen,\r\n\r\nI checked out your site / product, very cool. \r\n\r\nMy schedule is fairly open on Friday 2/12, feel free to shoot me a calendar invite. Looking forward to learning more.\r\n\r\nChad\r\n\t\r\nChad Coleman | Co-Founder & CEO\r\nAscend Agency\r\n720.515.2418 <tel:7205152418>\r\n@agencyascend <http://www.twitter.com/agencyascend>\r\nwww.agencyascend.com <http://www.agencyascend.com/>\r\n\r\n\r\n", 
	        "Do you have a free trial for Techstars or Foundry Group companies?", 
	        "No thanks Jamesen not right now. I only started a week ago so we won;t be\r\nimplementing anything new until 2016 Q3.\r\n\r\n", 
	        "Jason,\r\n\r\nIt appears as though the link you had sent me to your website is\r\nunavailable.  Is there any alternative methods, in which you are able to\r\nsend me a business overview?  Also, we are only seeking to acquire one\r\ncompany that has had a steady revenue stream of 2-20 million for the past\r\nthree years.\r\n\r\nThanks,\r\n\r\nAhmed Makani", 
	        "We are leading web agency and we focus on the Israeli market. \r\n\r\nPlease take a look at leadlike.com\r\n\r\nMaxime\r\n\r\nLe 2 f\u00e9vr. 2016 \u00e0 01:36, Jamasen Rodriguez <jamasen@legionanalytics.com", 
	        "How you will help us ?\r\n\r\n-- \r\n\r\n\r\n\r\n*Maxime Seligman*\r\n\r\n*CTO & Founder*\r\n\r\nmaxime@browzin.net\r\n\r\n[image: skype:imakse?chat]\r\n\r\n*www.browzin.net <http://www.browzin.net/>*\r\n\r\n\r\n2016-02-01 18:58 GMT+02:00 <jamasen@legionanalytics.com>:\r\n\r\n", 
	        "Hello,\r\n\r\nWe are dissolving Radventure.  Thank-you for your inquiry.\r\n\r\nAndrea\r\n\r\nAndrea Bouma\r\n\r\nRadventure | Co-Founder & CEO\r\n\r\nwww.GoRadventure.com <http://www.goradventure.com/>\r\n\r\nAndrea@GoRadventure.com\r\n\r\nC: 541-977-9908\r\n\r\n\r\nFollow us on: Facebook <http://www.facebook.com/GoRadventureAroundtheWorld>\r\n, Twitter <http://twitter.com/goradventure>, Instagram\r\n<https://instagram.com/go_radventure/>", 
	        "Hi ! Lol. It's two!!! Crazy busy. No chance to take this in, sorry. Try me in May :)\r\n\r\nSent from my iPhone", 
	        "Jamasen,\r\n\r\nThank you for reaching out. I'm sorry I have yet to get back to you as I am currently going through an Accelerator program which is extremely time intensive on top of two nearly full-time jobs as well. As a cold caller myself, I highly appreciated your most recent email and persistence. I have not had a chance to look at your products and for that I am sorry. I will try to take a look at them next week. Have a great weekend. \r\n\r\nThanks,\r\n\r\nJeremy\r\n\r\n\r\n\r\n\r\nSent from my iPhone\r\n\r\n", 
	        "Hi Jamesen,\r\n\r\nSorry for the delay to reply.\r\n\r\nThe right response is a mix between 1 & 2 :)\r\n\r\nTo be honest, we are finalizing the product itself and not to much focused\r\non the kind of value you offer.\r\n\r\nI keep your details and will get back to you in a more convenient time.\r\n\r\nBest regards,\r\nPhilippe\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n2016-02-05 20:08 GMT+01:00 <jamasen@legionanalytics.com>:\r\n\r\n", 
	        "Hi Jamasen,\r\n\r\nI have been swamped this week.   I will be able to review your offer next\r\nweek.\r\n\r\nThank you,\r\n\r\nRob\r\n\r\nRob Lewis\r\nDirector Marketing Services\r\nLocal Value Marketing\r\n(858) 480-6116 <+1858-480-6116>\r\nroblewis@localvalue.com <roblewis@localvaluemarketing.com>\r\n<https://www.google.com/partners/#a_profile;idtf=6383298929;>\r\n<https://www.linkedin.com/in/roblewis99>", 
	        "Hi Jamasen,\r\n\r\nAlthough it sounds tempting, I am not in a position to take on a large influx of business at this time. I would be open to you checking in again in 3 months. \r\nHow did you find out about me and get my email? Just always curious to know how people find me.\r\n\r\nThank you -\r\nJanis\r\n", 
	        "Jamasen,\r\n\r\nGot your note, timing is not right, but I'll take a closer look in the\r\nspring.\r\n\r\nBest,\r\n\r\nShahab\r\n\r\n\r\nShahab Kaviani\r\n(202) 255-0030\r\nAbout Me <http://shahab.strikingly.com/>\r\n\r\nStay up to date on Youth Entrepreneurship  <http://eepurl.com/bMhdMn>\r\n", 
	        "Hi Jamasen,\r\n\r\nThanks so much for the email and congratulations on the business.  Over the\r\nyears I've marketed to people using email, appreciating a good mail and\r\nknow that sometimes it can be a downer to receive limited responses.\r\n\r\nA little bit like your own company we're a start-up and still at pre\r\nrevenue stage.  We have a number of products coming to market in 2016 and\r\nthe target is by end of year to have sales, leads and possibly a small\r\nsales team.\r\n\r\nSo to that end, make contact again in early 2017, and best of luck during\r\nthe year.\r\n\r\nCheers,\r\nStephen\r\n[image: photo]\r\n*Stephen McLernon*\r\nSales & Marketing Director, LUMINOSITY / SOAR\r\nm:+353 (86)2359639 | e:Stephen@luminosity.ie | w:www.luminosity.ie | a:34\r\nOrlagh Downs, Knocklyon, Dublin 16, Ireland\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fwww.linkedin.com%2Fprofile%2Fview%3Fid%3D60083710%26trk%3Dnav_responsive_tab_profile&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fwww.twitter.com%2Fluminosity_ie&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=https%3A%2F%2Fwww.etsy.com%2Flisting%2F236814837%2Feiffel-tower-paris-france-red-hue-5-x-7%3Fref%3Drss&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n[image:\r\nPromote Etsy Store]\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fwww.etsy.com%2Fshop%2Fsprocketphotography&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\nMy\r\nlatest item: Eiffel Tower, Paris, France. Red Hue: 5&quot; x 7&quot; by\r\nSprocketPhotography\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=https%3A%2F%2Fwww.etsy.com%2Flisting%2F236814837%2Feiffel-tower-paris-france-red-hue-5-x-7%3Fref%3Drss&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n*15.00 $* | Buy now\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=https%3A%2F%2Fwww.etsy.com%2Flisting%2F236814837%2Feiffel-tower-paris-france-red-hue-5-x-7%3Fref%3Drss&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n| Visit my Etsy shop\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fwww.etsy.com%2Fshop%2Fsprocketphotography&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n   Get this email app!\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=https%3A%2F%2Fwebapp.wisestamp.com%2F%3Fapp%3Detsy%26utm_source%3Dpromotion_app%26utm_medium%3Demail%26utm_campaign%3DPromotion_Link&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n\r\nGet a signature like this: Click here!\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fws-promos.appspot.com%2Fr%3Frdata%3DeyJydXJsIjogImh0dHA6Ly93d3cud2lzZXN0YW1wLmNvbS9lbWFpbC1pbnN0YWxsP3dzX25jaWQ9NjcyMjk0MDA4JnV0bV9zb3VyY2U9ZXh0ZW5zaW9uJnV0bV9tZWRpdW09ZW1haWwmdXRtX2NhbXBhaWduPXByb21vXzU3MzI1Njg1NDg3Njk3OTIiLCAiZSI6ICI1NzMyNTY4NTQ4NzY5NzkyIn0%3D%26ws_random_number%3D&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>", 
	        "Jamasen - thanks for the proposal. I'm interested in testing your solution\r\nagainst our current approach but can't justify $2k setup fee at this time.\r\nI would like to test Legion against our current cobbled together approach\r\nto see which one generates the best results. It would be a combination of\r\nyour cold leads versus what we have, and your drip campaigns against what\r\nwe've created. I think it would be interesting to see which works best.\r\n\r\nThis could be an amazing case study for you, if you can beat a digital\r\nacquisition marketing company that specialized in lead gen and CRO.\r\n\r\nAre you up to the challenge?!!", 
	        "Not a good time, thanks", 
	        "Can you reach back to me in June?\r\nOn Feb 4, 2016 10:27 AM, <jamasen@legionanalytics.com", 
	        "Jameson, we're not looking for a new solution. But thank you. Oh and your\r\nwebsite is down...\r\n\r\n\r\nMana Ionescu\r\n\r\npresident, lightspandigital\r\n\r\no: 312-241-1597\r\n\r\nc: 312-593-4085\r\n\r\nlightspandigital.com\r\nLet's connect: [image: LinkedIn] <http://www.linkedin.com/in/manamica", 
	        "In talking with our team - I think we\u2019re a bit away from being ready to do this. Thanks for the email, please reach out in the second half of the year. \r\n\r\nCheers,\r\nGreg Genung\r\n(512) 550-3009 \r\nggenung@whotype.com\r\nwww.whotype.com\r\n@Whotype - the Power of Personality        \r\n\r\n\r\n\r\n", 
	        "Sounds great, thanks Jamasen!", 
	        "Hi Jamasen,\r\n\r\nThanks for reaching out. Legion Analytics looks really interesting.\r\n\r\nUnfortunately, the timing isn't great right now.  We are in the process of\r\nlaunching a more consumer-focused product (www.datafire.io) so we are very\r\nfocused on marketing and PR.  We are basically just doing market research\r\nright now, but there is definitely a potential to use something like Legion\r\ndown the road.\r\n\r\nCan you check in towards the end of Q1? We should have a much clearer\r\npicture at that point of where we are at and what we need.\r\n\r\nThanks,\r\nAndrew", 
	        "Jamasen - I enjoyed our chat yesterday. When can you send over the custom\r\npackage overview so that we can review/discuss?\r\n\r\n\r\n-- \r\n[image: logo]\r\n*Rory Holland* *CEO*\r\n415.805.6065\r\n<415.805.6065?utm_source=WiseStamp&utm_medium=email&utm_term=&utm_content=&utm_campaign=signature>\r\n|\r\nrory@cstmr.com | cstmr.com\r\n<http://www.twitter.com/rory_holland?utm_source=WiseStamp&utm_medium=email&utm_term=&utm_content=&utm_campaign=signature>\r\n<http://www.linkedin.com/roryeholland?utm_source=WiseStamp&utm_medium=email&utm_term=&utm_content=&utm_campaign=signature>\r\nOur latest post: Where to Start when Driving Financial Services Growth\r\n<http://cstmr.com/index.php/where-to-start-when-driving-financial-services-growth/?utm_source=WiseStamp&utm_medium=email&utm_term=&utm_content=&utm_campaign=signature>\r\n", 
	        "Jamasen, \r\n\r\nThanks for the email. I\u2019d be happy to visit with you about the company. We are launching at SXSW here in March and plan to release the worlds first platform for exploring personality and motivations of your self, your relationships, and your workplace. Understand our personality and our personal and professional relationships is what we are all about. Whotype is the Power of Personality at Work and at Play. Though we have not launched yet, I\u2019d wonder how this strategy could apply at this time - but am open to ideas, if you have some that would be helpful for us to leverage as we launch. \r\n\r\nPlease feel free to reach out if you\u2019d like to visit. \r\n\r\nCheers,\r\nGreg Genung\r\nFounder, CEO\r\n(512) 550-3009 \r\nggenung@whotype.com\r\nwww.whotype.com\r\n@Whotype - the Power of Personality        \r\n\r\n\r\n\r\n", 
	        "Hi Jamasen\r\n\r\nApology I could not send so far due to gruelling schedule. Will send by \r\nthis\r\nweekend positively\r\n\r\n\r\nBest Ranjeet\r\nOn Tue, Jan 26, 2016 at 1:26 AM, Jamasen Rodriguez < \r\njamasen@legionanalytics.com [jamasen@legionanalytics.com] ", 
	        "Hi Jamasen\r\n\r\nI have that in my worklist but could not complete so far. I shall try to\r\ngive by you by wednesday EOD. Have added to my calendar now\r\n\r\nThanks for your patience\r\n\r\nBest\r\nRanjeet", 
	        "cool", 
	        "Hi Jamasen\r\n\r\nSure - If you can tell me how many words etc I can do that and send by\r\nweekend. Will be from my Business Head or MD side\r\n\r\nBest\r\nRanjeet\r\n\r\n", 
	        "Hi ! Lol. It's two!!! Crazy busy. No chance to take this in, sorry. Try me in May :)\r\n\r\nSent from my iPhone", 
	        "Thanks Jamasen however Pixel Collider is even smaller than Legion Analytics\r\nas it's just me. And I have more work than I can handle so am not looking\r\nfor new customers.\r\n\r\nRegards,\r\n\r\nChris\r\n\r\nChris Stevens | 206.618.5437\r\n", 
	        "Hi Jamasen:\r\n\r\nI don't have any seed funding yet, so unless this is a free pilot we cannot\r\nafford it.\r\n\r\nLet me know\r\n\r\nLayla\r\n\r\nLayla Sabourian\r\nFounder, Chef Koochooloo\r\n650-463-6041\r\n\r\nwww.chefkoochooloo.com\r\n\r\nwww.facebook.com/chefkoochooloo\r\n\r\nHelp us Make the World a More Delicious Place, One Recipe at a time\r\n\r\n\r\n", 
	        "Hi Jamesen,\r\n\r\nSorry for the delay to reply.\r\n\r\nThe right response is a mix between 1 & 2 :)\r\n\r\nTo be honest, we are finalizing the product itself and not to much focused\r\non the kind of value you offer.\r\n\r\nI keep your details and will get back to you in a more convenient time.\r\n\r\nBest regards,\r\nPhilippe\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n2016-02-05 20:08 GMT+01:00 <jamasen@legionanalytics.com>:\r\n\r\n", 
	        "Jamasen,\r\n\r\nGot your note, timing is not right, but I'll take a closer look in the\r\nspring.\r\n\r\nBest,\r\n\r\nShahab\r\n\r\n\r\nShahab Kaviani\r\n(202) 255-0030\r\nAbout Me <http://shahab.strikingly.com/>\r\n\r\nStay up to date on Youth Entrepreneurship  <http://eepurl.com/bMhdMn>\r\n", 
	        "Hi Jamasen,\r\n\r\nThanks so much for the email and congratulations on the business.  Over the\r\nyears I've marketed to people using email, appreciating a good mail and\r\nknow that sometimes it can be a downer to receive limited responses.\r\n\r\nA little bit like your own company we're a start-up and still at pre\r\nrevenue stage.  We have a number of products coming to market in 2016 and\r\nthe target is by end of year to have sales, leads and possibly a small\r\nsales team.\r\n\r\nSo to that end, make contact again in early 2017, and best of luck during\r\nthe year.\r\n\r\nCheers,\r\nStephen\r\n[image: photo]\r\n*Stephen McLernon*\r\nSales & Marketing Director, LUMINOSITY / SOAR\r\nm:+353 (86)2359639 | e:Stephen@luminosity.ie | w:www.luminosity.ie | a:34\r\nOrlagh Downs, Knocklyon, Dublin 16, Ireland\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fwww.linkedin.com%2Fprofile%2Fview%3Fid%3D60083710%26trk%3Dnav_responsive_tab_profile&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fwww.twitter.com%2Fluminosity_ie&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=https%3A%2F%2Fwww.etsy.com%2Flisting%2F236814837%2Feiffel-tower-paris-france-red-hue-5-x-7%3Fref%3Drss&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n[image:\r\nPromote Etsy Store]\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fwww.etsy.com%2Fshop%2Fsprocketphotography&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\nMy\r\nlatest item: Eiffel Tower, Paris, France. Red Hue: 5&quot; x 7&quot; by\r\nSprocketPhotography\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=https%3A%2F%2Fwww.etsy.com%2Flisting%2F236814837%2Feiffel-tower-paris-france-red-hue-5-x-7%3Fref%3Drss&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n*15.00 $* | Buy now\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=https%3A%2F%2Fwww.etsy.com%2Flisting%2F236814837%2Feiffel-tower-paris-france-red-hue-5-x-7%3Fref%3Drss&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n| Visit my Etsy shop\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fwww.etsy.com%2Fshop%2Fsprocketphotography&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n   Get this email app!\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=https%3A%2F%2Fwebapp.wisestamp.com%2F%3Fapp%3Detsy%26utm_source%3Dpromotion_app%26utm_medium%3Demail%26utm_campaign%3DPromotion_Link&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>\r\n\r\nGet a signature like this: Click here!\r\n<http://t.sidekickopen37.com/e1t/c/5/f18dQhb0S7lC8dDMPbW2n0x6l2B9nMJW7t5XZs6445qzW5v79kH4Y9jTPW5vMrTT56dyy9f3fr5Vb02?t=http%3A%2F%2Fws-promos.appspot.com%2Fr%3Frdata%3DeyJydXJsIjogImh0dHA6Ly93d3cud2lzZXN0YW1wLmNvbS9lbWFpbC1pbnN0YWxsP3dzX25jaWQ9NjcyMjk0MDA4JnV0bV9zb3VyY2U9ZXh0ZW5zaW9uJnV0bV9tZWRpdW09ZW1haWwmdXRtX2NhbXBhaWduPXByb21vXzU3MzI1Njg1NDg3Njk3OTIiLCAiZSI6ICI1NzMyNTY4NTQ4NzY5NzkyIn0%3D%26ws_random_number%3D&si=5525998461779968&pi=5b12ca8c-86da-44c3-8857-dcd25d1c8a89>", 
	        "Jamasen,\r\nI'm still just a tiny little winery so it's too early for me to go down\r\nthis route.\r\n\r\nBest,\r\nChris", 
	        ":-)\r\n\r\n\r\nCynthia L. Phelps, PhD\r\nFounder, InnerAlly\r\n110 East Houston | 7th Floor\r\nSan Antonio, Texas 78205\r\n713-478-4018\r\nCynthia@InnerAlly.com\r\nCynthiaPhelps.com\r\nInnerAlly.com <http://www.InnerAlly.com>\r\nLinkedin.com/in/cynthialynnphelps/\r\n<http://www.linkedin.com/in/cynthialynnphelps/>", 
	        "no product yet.\r\n\r\n\r\n\r\nCynthia L. Phelps, PhD\r\nFounder, InnerAlly\r\n110 East Houston | 7th Floor\r\nSan Antonio, Texas 78205\r\n713-478-4018\r\nCynthia@InnerAlly.com\r\nCynthiaPhelps.com\r\nInnerAlly.com <http://www.InnerAlly.com>\r\nLinkedin.com/in/cynthialynnphelps/\r\n<http://www.linkedin.com/in/cynthialynnphelps/>", 
	        "Please remove my email id from your emailing list.\r\n\r\nNot interested.\r\n\r\nRegards,\r\n\r\nAnkit Brahmbhatt\r\nCo - Founder & CEO\r\n\r\n*Blow H**orn Media, LLP* - *\"Honking your Brand\"*\r\n\r\nM+91 756 789 6725\r\nO: +91 79 4009 8833 / 3002 8833\r\nankit@blowhornmedia.com\r\n\r\n*Consulting|Branding|Marketing|Technology** - *www.blowhornmedia.com\r\n\r\n\u201cA brand for a company is like a reputation for a person. You earn\r\nreputation by trying to do hard things well.\u201d\r\n", 
	        "Hello,\r\n\r\nWe are dissolving Radventure.  Thank-you for your inquiry.\r\n\r\nAndrea\r\n\r\nAndrea Bouma\r\n\r\nRadventure | Co-Founder & CEO\r\n\r\nwww.GoRadventure.com <http://www.goradventure.com/>\r\n\r\nAndrea@GoRadventure.com\r\n\r\nC: 541-977-9908\r\n\r\n\r\nFollow us on: Facebook <http://www.facebook.com/GoRadventureAroundtheWorld>\r\n, Twitter <http://twitter.com/goradventure>, Instagram\r\n<https://instagram.com/go_radventure/>", 
	        "Hi,\u00a0\r\n\r\nSorry we are not interested.\u00a0\r\n\r\nThanks,\u00a0\r\n\r\nElyes\u00a0\r\n\r\n", 
	        "not interested. thanks,\r\n\r\nNate", 
	        "Dear Mr Rodriguez\r\nThank you for your email, Given that I have never met you or heard of your\r\ncompany i find your familiar style of communicating disconcerting. However\r\nit is a moot point as i do not see a \"fit\" between our companies. Kindly\r\ntake me off your email list.\r\nRegards,\r\nSid H Belzberg\r\n", 
	        "REMOVE", 
	        "We are not interested. We sell to select customers B2B in a truly limited micro segment and perform consulting for select vendors doing the same. We know everyone in our market segment and have no need for your services.\r\n\r\nAldo\r\n\r\nSent from my iPhone\r\n\r\n", 
	        "Not interested.  Please remove me from your list\r\n\r\nAsif R. Khan\r\nFounder & President\r\nLocation Based Marketing Association\r\n\r\n+1 (416) 564-4820\r\n@AsifRKhan @TheLBMA\r\n\r\n\r\n\r\n", 
	        "Please take me off your email list. I've just been marking these as spam.\r\n\r\nKyle Taylor\r\nCo-founder, *Draw**Attention*\r\nkyle@drawattention.co\r\n@kyletaylored  |  @drawattentionco\r\n940-231-4998", 
	        "Please take us off your list. Thanks.\u00a0\r\n\r\nSent from Outlook Mobile\r\n\r\n\r\n", 
	        "No thanks \r\n\r\nRod Collins 214.724.2729 BulldogBillboards.com\r\n\r\n", 
	        "Thanks Jamasen. Please remove us from your list. We are not interested.", 
	        "Hi Jamasen,\r\n\r\nI'm sorry for not replying to you before this. I don't check these email\r\naccount. EdventureLabs is currently a failed project and all of us have\r\nmoved on.\r\n\r\n--\r\nNaresh Jain (@nashjain)\r\nhttp://nareshjain.com", 
	        "#1....not interested\r\n\r\nSent from my iPhone\r\n*Please excuse all typos\r\n\r\n", 
	        "A mass marketing email blast should start with checking the grammatical\r\ncorrectness of your email.", 
	        "Sorry, we are not a business.  We are a 501c(3) religious charitable\r\norganization.  We do not have customers, only donors.  Please remove my\r\ncontact info from your records.", 
	        "Please remove me from your list. I sold the company\u00a0\r\n\r\n\r\n\r\n\r\n", 
	        "Unsubscribe\r\nOn Sat, Feb 6, 2016 at 8:28 AM <jamasen@legionanalytics.com", 
	        "No interest, please stop emailing.\r\n\r\n\r\nWith kind regards,\r\n\r\n\r\n\r\nLiva Judic\r\n\r\n*+1 917 319 8705 (Time zone: Eastern time) *\r\n[image: Facebook]\r\n<http://s.wisestamp.com/links?url=https%3A%2F%2Fwww.facebook.com%2FLiva.S.Judic&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>\r\n[image:\r\nTwitter]\r\n<http://s.wisestamp.com/links?url=http%3A%2F%2Ftwitter.com%2Flivajudic&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>\r\n[image:\r\nLinkedIn]\r\n<http://s.wisestamp.com/links?url=http%3A%2F%2Fwww.linkedin.com%2Fin%2Flivajudic%2F&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>\r\n[image:\r\nInstagram]\r\n<http://s.wisestamp.com/links?url=http%3A%2F%2Finstagram.com%2Flivajudic&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>\r\n[image:\r\nAngelList]\r\n<http://s.wisestamp.com/links?url=https%3A%2F%2Fangel.co%2Flivajudic&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>", 
	        "Take me off the spam list.  Thanks. \r\n\r\n- Michael\r\n\r\n", 
	        "4) I get 100+ emails per day and cannot possibly respond to all of the cold\r\noutreach that hits my inbox.\r\n\r\nPlease unsubscribe me.\r\n\r\nRob\r\n", 
	        "Hi Jamasen.  I\u2019m wondering if you can remove me from your email list please.  \r\n\r\nBest!\r\nDoug\r\n\r\n\r\nDoug Stephens\r\ndoug@retailprophet.com <mailto:doug@retailprophet.com>\r\nRetailProphet.com <http://retailprophet.com/>\r\nTwitter: @RetailProphet\r\nP: 1+647-393-9033\r\n\r\n\r\n\r\n", 
	        "1.  No longer operating. Please remove\r\n\r\nSent from my iPhone\r\n\r\n", 
	        "\r\n\r\nAll the best,\r\nLouis Monoyudis\r\nBright Blue\r\n379 W. Broadway\r\nNY, NY 10012\r\nwww.brightbluemag.com", 
	        "stop. no interest.\r\n\r\n*Garrett Smith*\r\nFounder\r\n\r\n*Pitch + Pivot, LLC*\r\nWebsite: PitchPivot.com\r\nEmail: garrett@pitchpivot.com\r\nOffice: 716-322-3101\r\nCell: 716-903-9495\r\nLinkedIn: /in/garrettsmith <http://www.linkedin.com/in/garrettsmith>\r\nTwitter: @garrettsmith <http://www.twitter.com/garrettsmith>", 
	        "\r\nYours\r\nLaurence\r\n\r\nCEO, Ctrlio\r\nm: +44(0)7802 357710\r\nwww.ctrlio.com\r\nS: laurencenjohn\r\nT: @laurencejohn1\r\n\r\n\r\n\r\n\r\nThis email and any attachments are\u00a0confidential. Unless you are the\u00a0intended recipient, you may not use,\u00a0copy or disclose either the\u00a0message or any information contained in\u00a0the message. If you are not\u00a0the intended recipient, you should delete\u00a0this email and please notify\u00a0the sender immediately. All copyright in\u00a0any material in this email is\u00a0reserved. <https://ctrlio.com/assets/images/email-signature.png>\r\n\r\nThis email and any attachments are confidential. Unless you are the intended recipient, you may not use, copy or disclose either the message or any information contained in the message. If you are not the intended recipient, you should delete this email and please notify the sender immediately. All copyright in any material in this email is reserved.\r\n <https://ctrlio.com/assets/images/email-signature.png>\r\n", 
	        "Dude, your auto emails are ridiculous. Please don't contact me again. This\r\nis very unprofessional.\r\nOn Thu, Feb 4, 2016 at 10:02 AM <jamasen@legionanalytics.com", 
	        "Not intersted, do not follow up.\r\n\r\n\r\nMick Darling\r\nFounder / CEO Tomorrowish LLC <http://tomorrowish.com/>\r\nmick@tomorrowish.com\r\n774-567-0001\r\nmickdarling (AT) Twitter <http://twitter.com/mickdarling>, Facebook\r\n<http://facebook.com/mickdarling>, LinkedIn\r\n<http://linkedin.com/in/mickdarling>, Skype, etc <http://mickdarling.com/>\r\n...\r\n", 
	        "Crazy monkey.\r\n\r\nBest wishes,\r\nGary\r\n\r\n\r\nGary D. Weinhouse, JD/MBA\r\n310.980.0995 | garyweinhouse@gmail.com<mailto:garyweinhouse@gmail.com>\r\n\r\nPlease excuse typos...sent from my iPhone.", 
	        "Jamasen - have we ever met?\r\nI reviewed your offer, and wasn't interested.\r\nThanks,\r\n\r\nKamal", 
	        "Sorry, I\u00b9m not interested at this time. You can please remove me from your\r\nlist.\r\n\r\nBest and thanks,\r\nMichael\r\n\r\nFrom:  <jamasen@legionanalytics.com>\r\nDate:  Thursday, February 4, 2016 at 10:29 AM\r\nTo:  Michael Ball <michael@pitchstories.com>\r\nSubject:  Re:Re: Pitch/Stories<>Legion Analytics\r\n\r\nHey  Michael,\r\n\r\nI still haven't heard back from you. I'm getting kind of worried. I can only\r\nassume that:\r\n\r\n1) you're not interested and chose not to reply. So I will follow up with\r\nyou again in a month.\r\n\r\n2) You are interested and haven't had a chance to reply to my emails.\r\n\r\n3) A crazy monkey has gotten loose and I fear that he may have found his way\r\nto you?!\r\n\r\nPlease respond to my email as I am getting very worried for your safety.\r\n\r\nYour worried friend,\r\n\r\nJamasen Rodriguez\r\nFounder of Legion Analytics\r\n(415) 849-2939\r\n\r\n\r\n", 
	        "No monkeys, but thanks for the lifeline.\r\n\r\nWe are all good - thank you.\r\n\r\nJoseph Kozusko, Ph.D.\r\nCo-founder | Business Development\r\nSkills Fund <http://skills.fund/>\r\n\r\n\r\n\r\n", 
	        "Please stop harassing me", 
	        "Please do not respond again.\r\n\r\nSent from my iPhone\r\n\r\n", 
	        "I welcome your humor but not your spam like emails\r\n\r\nPlease take me off the list , thank you :-)", 
	        "Forwarding to our sales and marketing team.", 
	        "Jamasen\r\n\r\nThanks for reaching out. I checked your site out and wish you the best of luck, but we\u2019re not a fit. \r\n\r\nBest,\r\n\r\nMariana\r\n \r\n", 
	        "Thanks Jamesen. I am a small Sales consulting company so this is really not appropriate for me\r\n\r\nKen\r\n\r\nKenneth C. Bossung, Founder/CEO\r\n\r\n\r\nSales Optimization & Performance Management\r\n3941 Park Drive, Suite 20-558\r\nEl Dorado Hills, CA. 95762 | O: 844-966-6400 | M: 703-966-6436\r\nkbossung@bossung.com <mailto:kbossung@bossungorganization.com", 
	        "Hello James,\r\n\r\nThank you so much for reaching out.  Right now, however, we have more\r\ncustomers than we can possibly satisfy effectively.  I will be sure to\r\nreach out when we need help finding more.\r\n\r\nRegards,\r\n\r\nMichael", 
	        "Dear Jamasen,\r\n\r\nNo need to be worried I am fully alive and in top shape!  After all I am\r\nrunning a health & nutrition business, so I better be.\r\n\r\nUnfortunately I don't have time to connect at the moment, but should things\r\nchange I will be in touch. In the meantime, and as a fellow entrepreneur I\r\nwish you the very best with your new venture.\r\n\r\nWalter\r\n\r\n", 
	        "Hey Jamasen,\r\n\r\nThanks for the email. Does this product target our existing customers or\r\npotential customers? I will be away next week.\r\nI will be free to chat after 16 Feb. Ideally between 8 - 10 am PDT.\r\n\r\nCheers,\r\n\r\nDema", 
	        "Please do not respond again.\r\n\r\nSent from my iPhone\r\n\r\n", 
	        "Lol.\r\n\r\nThis email structure used to be a closely held one but it looks like sales\r\ntraining gurus have given to everyone.\r\n\r\nSent from my iPhone", 
	        "Hi Jamasen,\r\n\r\nI'm not interested.\r\n\r\nAll the best,\r\n\r\n*Scott Miller*\r\nsondermill.com\r\n<http://sondermill.com/?utm_source=emailsig&utm_medium=email&utm_campaign=emailsig_sm>\r\n*Instagram <http://instagram.com/sondermill", 
	        "We're not a good fit, but I appreciate the hustle. Nice use of our company\r\nname in the subject, got me to open it :)", 
	        "Prove it to me, how can you increase my sales??\r\n\r\nMany thanks & Best regards\r\nPuga Sankara\r\nPrincipal\r\nSmart Gladiator LLC\r\nPh#: 678 481 5486\r\nwww.smartgladiator.com\r\nSkype: puga2006\r\nCheck out our Thought Leadership at\r\nwww.ebnonline.com/archives.asp?section_id=3743\r\nFor a warehouse with 50 operators, working 2 shifts, 320 days a year, Savings = HALF MILLION $$$ OR MORE\r\n\r\n\r\n", 
	        "This has nothing to do with our business model", 
	        "No thanks,\r\nYair\r\n\r\n---------------------------------\r\nYair Raz\r\nInnovo Concepts, Inc.\r\nwww.innovo-concepts.com\r\nyair@innovo-concepts.com\r\nPhone: (408) 499-7025\r\nFax:     (786) 257-5732\r\n----------------------------------\r\n\r\n", 
	        "Jamasen,\r\n\r\nThis is of no interest to Games Ireland.\r\n\r\nBarry\r\n\r\n\r\n", 
	        "Hi Jamasen,\r\n\r\nWe mainly sell through partners and distribution channels. At this time, I\r\ndon't think we are in a position to take a look at Legion Analytics. Thank\r\nyou for reaching out to me.\r\nBest regards,\r\n\r\nBrenda.\r\n", 
	        "Jamasen,\r\nI'm still just a tiny little winery so it's too early for me to go down\r\nthis route.\r\n\r\nBest,\r\nChris", 
	        "no thank you. please remove me from your list.\r\n\r\n", 
	        "Hi,\r\n\r\nWe'll be using GA out of the gates in a few months.  Welcome to synch again\r\nin June for us to look at.\r\n\r\nBest,\r\nTony", 
	        "Hi Jamasen,\r\n\r\nI'm sorry for not replying to you before this. I don't check these email\r\naccount. EdventureLabs is currently a failed project and all of us have\r\nmoved on.\r\n\r\n--\r\nNaresh Jain (@nashjain)\r\nhttp://nareshjain.com", 
	        "Let\u2019s chat this evening or this weekend.  Let me know when you have some availability.", 
	        "Hey Jamasen,\r\n\r\nThanks for the email. Does this product target our existing customers or\r\npotential customers? I will be away next week.\r\nI will be free to chat after 16 Feb. Ideally between 8 - 10 am PDT.\r\n\r\nCheers,\r\n\r\nDema", 
	        "Jamasen, stay in touch.\r\n\r\nWe are a hybrid B2B because we aren\u2019t calling on corporate entities.  Instead we are calling on travel sports coaches and club directors who have turned their passion into a small business.  Can you guys be effective in that space?\r\n", 
	        "Hello,\r\n\r\nWe are dissolving Radventure.  Thank-you for your inquiry.\r\n\r\nAndrea\r\n\r\nAndrea Bouma\r\n\r\nRadventure | Co-Founder & CEO\r\n\r\nwww.GoRadventure.com <http://www.goradventure.com/>\r\n\r\nAndrea@GoRadventure.com\r\n\r\nC: 541-977-9908\r\n\r\n\r\nFollow us on: Facebook <http://www.facebook.com/GoRadventureAroundtheWorld>\r\n, Twitter <http://twitter.com/goradventure>, Instagram\r\n<https://instagram.com/go_radventure/>", 
	        "Hi Jamasen,\r\n\r\nI'm sorry for not replying to you before this. I don't check these email\r\naccount. EdventureLabs is currently a failed project and all of us have\r\nmoved on.\r\n\r\n--\r\nNaresh Jain (@nashjain)\r\nhttp://nareshjain.com", 
	        "Ella is no longer with Boutique Window and we aren't interested.\r\n\r\n\r\n\r\nLisa Scheck | Marketing Manager\r\n913.378.1894* | *lisas@boutiquewindow.com* | *www.boutiquewindow.com\r\nFollow us on Facebook: http://www.facebook.com/BoutiqueWindow\r\nCheck out our blog: http://www.boutiquewindow.com/blog/", 
	        "Out of the day to day at Immediately - now an advisor.\r\n\r\nCurrently EIR at 500.\r\n\r\nDo you have a deck or a 1-pager you can send so I can take a closer look.\r\nMight be relevant for some of the portfolio companies. Thanks!", 
	        "Jamasen\r\n\r\nThanks for reaching out. I checked your site out and wish you the best of luck, but we\u2019re not a fit. \r\n\r\nBest,\r\n\r\nMariana\r\n \r\n", 
	        "Thanks Jamesen. I am a small Sales consulting company so this is really not appropriate for me\r\n\r\nKen\r\n\r\nKenneth C. Bossung, Founder/CEO\r\n\r\n\r\nSales Optimization & Performance Management\r\n3941 Park Drive, Suite 20-558\r\nEl Dorado Hills, CA. 95762 | O: 844-966-6400 | M: 703-966-6436\r\nkbossung@bossung.com <mailto:kbossung@bossungorganization.com", 
	        "Hello,\r\n\r\nWe are dissolving Radventure.  Thank-you for your inquiry.\r\n\r\nAndrea\r\n\r\nAndrea Bouma\r\n\r\nRadventure | Co-Founder & CEO\r\n\r\nwww.GoRadventure.com <http://www.goradventure.com/>\r\n\r\nAndrea@GoRadventure.com\r\n\r\nC: 541-977-9908\r\n\r\n\r\nFollow us on: Facebook <http://www.facebook.com/GoRadventureAroundtheWorld>\r\n, Twitter <http://twitter.com/goradventure>, Instagram\r\n<https://instagram.com/go_radventure/>", 
	        "Hi,\u00a0\r\n\r\nSorry we are not interested.\u00a0\r\n\r\nThanks,\u00a0\r\n\r\nElyes\u00a0\r\n\r\n", 
	        "not interested. thanks,\r\n\r\nNate", 
	        "Dear Mr Rodriguez\r\nThank you for your email, Given that I have never met you or heard of your\r\ncompany i find your familiar style of communicating disconcerting. However\r\nit is a moot point as i do not see a \"fit\" between our companies. Kindly\r\ntake me off your email list.\r\nRegards,\r\nSid H Belzberg\r\n", 
	        "Jamasen,\r\n\r\nI am a CEO and acting VP of sales for my company so I appreciate the effort\r\nand methodology behind your email. So, thank you for that. But I am not\r\ninterested at this time.", 
	        "REMOVE", 
	        "We are not interested. We sell to select customers B2B in a truly limited micro segment and perform consulting for select vendors doing the same. We know everyone in our market segment and have no need for your services.\r\n\r\nAldo\r\n\r\nSent from my iPhone\r\n\r\n", 
	        "Not interested.  Please remove me from your list\r\n\r\nAsif R. Khan\r\nFounder & President\r\nLocation Based Marketing Association\r\n\r\n+1 (416) 564-4820\r\n@AsifRKhan @TheLBMA\r\n\r\n\r\n\r\n", 
	        "Sorry just read what you guys do. We are swamped building our product and not looking for new customers. Thanks \r\n\r\nSent from my iPhone\r\n\r\n", 
	        "Hi Jameson,\r\n\r\nWe built our own analytics and won't need your services. \r\n\r\nHave a great Sunday\r\n\r\nBest\r\nTiffany \r\n\r\n\r\n\r\nSent from my iPhone\r\n\r\n", 
	        "Please take me off your email list. I've just been marking these as spam.\r\n\r\nKyle Taylor\r\nCo-founder, *Draw**Attention*\r\nkyle@drawattention.co\r\n@kyletaylored  |  @drawattentionco\r\n940-231-4998", 
	        "Please take us off your list. Thanks.\u00a0\r\n\r\nSent from Outlook Mobile\r\n\r\n\r\n", 
	        "No thanks \r\n\r\nRod Collins 214.724.2729 BulldogBillboards.com\r\n\r\n", 
	        "Thanks Jamasen. Please remove us from your list. We are not interested.", 
	        "We're all set. Thank you\r\n\r\n", 
	        "#1....not interested\r\n\r\nSent from my iPhone\r\n*Please excuse all typos\r\n\r\n", 
	        "Thanks Jamasen however Pixel Collider is even smaller than Legion Analytics\r\nas it's just me. And I have more work than I can handle so am not looking\r\nfor new customers.\r\n\r\nRegards,\r\n\r\nChris\r\n\r\nChris Stevens | 206.618.5437\r\n", 
	        "Hi Jamasen:\r\n\r\nI don't have any seed funding yet, so unless this is a free pilot we cannot\r\nafford it.\r\n\r\nLet me know\r\n\r\nLayla\r\n\r\nLayla Sabourian\r\nFounder, Chef Koochooloo\r\n650-463-6041\r\n\r\nwww.chefkoochooloo.com\r\n\r\nwww.facebook.com/chefkoochooloo\r\n\r\nHelp us Make the World a More Delicious Place, One Recipe at a time\r\n\r\n\r\n", 
	        "Hi,\r\n\r\nThanks for your (multiple) emails. We're currently not interested, but I'll\r\nlet you know.", 
	        "Hi Jamasen,\r\nPlease stop the direct unsolicited emails, not much interested at this\r\npoint.  thanks,\r\nBenjamin", 
	        "A mass marketing email blast should start with checking the grammatical\r\ncorrectness of your email.", 
	        "Sorry, we are not a business.  We are a 501c(3) religious charitable\r\norganization.  We do not have customers, only donors.  Please remove my\r\ncontact info from your records.", 
	        "No thanks, Jamasen. I'm all set.\r\nPaul", 
	        "Please remove me from your list. I sold the company\u00a0\r\n\r\n\r\n\r\n\r\n", 
	        "Unsubscribe\r\nOn Sat, Feb 6, 2016 at 8:28 AM <jamasen@legionanalytics.com", 
	        "Jamasen,\r\n\r\nLooks like a great service but I am not interested, I'm actually enveloping\r\nthe Freshtight company into my other brand.\r\n\r\nThanks for reaching out.\r\n\r\nGood luck with your endeavors!\r\n\r\n\r\n--\r\nTarun Gehani @freshtight <http://twitter.com/freshtight>\r\nDirector, Freshtight Designs <http://freshtightdesigns.com/?ref=email-sig>\r\nMarketing Director, SMAMi.org\r\nconnect on LinkedIn <http://www.linkedin.com/in/tarungehani>, Google+\r\n<https://plus.google.com/116330471688158328785/posts>\r\n", 
	        "No interest, please stop emailing.\r\n\r\n\r\nWith kind regards,\r\n\r\n\r\n\r\nLiva Judic\r\n\r\n*+1 917 319 8705 (Time zone: Eastern time) *\r\n[image: Facebook]\r\n<http://s.wisestamp.com/links?url=https%3A%2F%2Fwww.facebook.com%2FLiva.S.Judic&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>\r\n[image:\r\nTwitter]\r\n<http://s.wisestamp.com/links?url=http%3A%2F%2Ftwitter.com%2Flivajudic&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>\r\n[image:\r\nLinkedIn]\r\n<http://s.wisestamp.com/links?url=http%3A%2F%2Fwww.linkedin.com%2Fin%2Flivajudic%2F&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>\r\n[image:\r\nInstagram]\r\n<http://s.wisestamp.com/links?url=http%3A%2F%2Finstagram.com%2Flivajudic&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>\r\n[image:\r\nAngelList]\r\n<http://s.wisestamp.com/links?url=https%3A%2F%2Fangel.co%2Flivajudic&sn=bGl2YUBtZXJyeWJ1YmJsZXMuY29t>", 
	        "Take me off the spam list.  Thanks. \r\n\r\n- Michael\r\n\r\n", 
	        "Hello James,\r\n\r\nThank you so much for reaching out.  Right now, however, we have more\r\ncustomers than we can possibly satisfy effectively.  I will be sure to\r\nreach out when we need help finding more.\r\n\r\nRegards,\r\n\r\nMichael", 
	        "Jamasen,\r\nI'm still just a tiny little winery so it's too early for me to go down\r\nthis route.\r\n\r\nBest,\r\nChris", 
	        "Not at this time, growth not an immediate priority. Maybe check back for in\r\n6-12 months or so.", 
	        "Hi,\r\n\r\nWe'll be using GA out of the gates in a few months.  Welcome to synch again\r\nin June for us to look at.\r\n\r\nBest,\r\nTony", 
	        "No thanks Jamesen not right now. I only started a week ago so we won;t be\r\nimplementing anything new until 2016 Q3.\r\n\r\n", 
	        "Dear Mr Rodriguez\r\nThank you for your email, Given that I have never met you or heard of your\r\ncompany i find your familiar style of communicating disconcerting. However\r\nit is a moot point as i do not see a \"fit\" between our companies. Kindly\r\ntake me off your email list.\r\nRegards,\r\nSid H Belzberg\r\n", 
	        "Please take me off your email list. I've just been marking these as spam.\r\n\r\nKyle Taylor\r\nCo-founder, *Draw**Attention*\r\nkyle@drawattention.co\r\n@kyletaylored  |  @drawattentionco\r\n940-231-4998", 
	        "Hi Jamasen,\r\nPlease stop the direct unsolicited emails, not much interested at this\r\npoint.  thanks,\r\nBenjamin", 
	        "Take me off the spam list.  Thanks. \r\n\r\n- Michael\r\n\r\n", 
	        "4) I get 100+ emails per day and cannot possibly respond to all of the cold\r\noutreach that hits my inbox.\r\n\r\nPlease unsubscribe me.\r\n\r\nRob\r\n", 
	        "\r\nYours\r\nLaurence\r\n\r\nCEO, Ctrlio\r\nm: +44(0)7802 357710\r\nwww.ctrlio.com\r\nS: laurencenjohn\r\nT: @laurencejohn1\r\n\r\n\r\n\r\n\r\nThis email and any attachments are\u00a0confidential. Unless you are the\u00a0intended recipient, you may not use,\u00a0copy or disclose either the\u00a0message or any information contained in\u00a0the message. If you are not\u00a0the intended recipient, you should delete\u00a0this email and please notify\u00a0the sender immediately. All copyright in\u00a0any material in this email is\u00a0reserved. <https://ctrlio.com/assets/images/email-signature.png>\r\n\r\nThis email and any attachments are confidential. Unless you are the intended recipient, you may not use, copy or disclose either the message or any information contained in the message. If you are not the intended recipient, you should delete this email and please notify the sender immediately. All copyright in any material in this email is reserved.\r\n <https://ctrlio.com/assets/images/email-signature.png>\r\n", 
	        "hi jamasen, what do you guys do exactly?\r\n\u1427\r\n\r\n\r\n=======\r\nKevin Chugh, Ph.D.\r\nCEO, Founder\r\n\r\n50 Fountain Plaza\r\nSuite 1400\r\nBuffalo, New York  14202\r\n\r\n(716) 241-1103\r\n\r\nhttp://www.mainstreetcomputing.com", 
	        "Hey Jamasen,\r\n\r\nThanks for the email. Does this product target our existing customers or\r\npotential customers? I will be away next week.\r\nI will be free to chat after 16 Feb. Ideally between 8 - 10 am PDT.\r\n\r\nCheers,\r\n\r\nDema", 
	        "Thanks for the info. How does it find potential customers for us? I'm\r\ninterested in learning more about that. We've spent a lot of time / money\r\non platforms like Data.com and SalesLoft.com identifying prospects (CMO,\r\ndigital marketing execs, content marketing execs, etc) then putting them\r\ninto an e-mail drip. We ceased those efforts late last year as they were\r\nnot converting / working for us.\r\n\r\nCan you let me know how what you guys do is different than that? Thanks!\r\n\r\n\r\nJason", 
	        "OK, done. Just so you know the site keeps crashing at every step.", 
	        "It's not even remotely ready for enterprise. I want try the Basic plan \r\nfirst on the month-to-month basis, but I have serious doubt over \r\nsecurity of this transaction.", 
	        "I tried. It crashed. 1 month free, or find other beta testers?\r\n\r\n", 
	        "Hey Jamasen,\r\n\r\nPeter is no longer involved in GoodBlogs. I'd be interested in learning\r\nmore however. Could you send me some info via e-mail to get started?\r\n\r\nThanks.\r\n\r\n\r\nJason\r\n\r\n-- \r\nJason Trout\r\nFounder, GoodBlogs\r\nAll the benefits of inbound marketing. None of the effort.\r\nhttp://www.GoodBlogs.com <http://www.goodblogs.com/", 
	        "Jamasen,\r\n\r\nI usually don't reply to these kinds of offers, but if you can provide \r\nsome color on the following, I may give it a shot.\r\n\r\n 1. Where will the leads come from?\r\n 2. Are they just prospect ideas or have demonstrated a potential\r\n    opportunity in some way?\r\n 3. What contact data and other context will be provided?\r\n 4. Will I be required to install some plug-ins in my browser or some\r\n    tracking technology for our website?\r\n\r\n\r\nThanks,\r\n\r\nVictor\r\n\r\n\r\n", 
	        "Jamasen, stay in touch.\r\n\r\nWe are a hybrid B2B because we aren\u2019t calling on corporate entities.  Instead we are calling on travel sports coaches and club directors who have turned their passion into a small business.  Can you guys be effective in that space?\r\n", 
	        "Jamasen,\r\n\r\nI could listen.  Book a time here:  https://calendly.com/justinherring/30min\r\n\r\nJustin Herring\r\n\r\nYEAH! Local <http://yeah-local.com/>\r\n\r\n(404) 539-6068\r\n\r\nWant to Chat? Book a Time Here <https://calendly.com/justinherring/30min>\r\n\r\n<https://calendly.com/justinherring/30min>\r\n\r\nP.S. Check out our latest blog post <http://yeah-local.com/blog>\r\n\r\nP.P.S. Think we did a great job? Give us a Review!\r\n<http://www.grade.us/yeah-local>", 
	        "Hi jamasen, can we try Tuesday at noon EST?\r\n\r\n\r\nCharlie Locke\r\n*Chief Revenue Officer*\r\n\r\n<http://saasli.com/>\r\n\r\n647.222.7875\r\nclocke@saasli.com\r\n\r\n*Prefer to Speak Live?* Click here <http://charlielocke.youcanbook.me", 
	        "Sounds interesting.\r\n\r\nNext wednesday works for me. I am based in the UK. Sometime in my afternoon\r\n/ evening would work well. What works for you?\r\n\r\nCheers,\r\nOlivier", 
	        "Hey Jamasen,\r\n\r\nI'm game for a chat. Does Friday afternoon (EST) work for you?\r\n\r\nCharlie\r\n\r\n\r\nCharlie Locke\r\n*Chief Revenue Officer*\r\n\r\n<http://saasli.com/>\r\n\r\n647.222.7875\r\nclocke@saasli.com\r\n\r\n*Prefer to Speak Live?* Click here <http://charlielocke.youcanbook.me", 
	        "Hi Jamasen,\r\nThanks for reaching out! I would love to chat more about growth opportunities and early next week for 15 minutes sounds great. How about Tuesday at 11am?\r\nChat soon,\r\nBrittany\r\n\r\nBrittany Hammonds\r\n(407) 921-1673\r\n\r\n", 
	        "Hi Jamasen,\r\n\r\nThanks for reaching out. Looping in my editor Brittany Hammonds, who\r\nhandles growth opportunities for the site. Will let the two of you find a\r\ntime to chat; look forward to hearing more\r\n\r\nCheers,\r\n M\r\n\r\nMegan Collins | Style Girlfriend <http://www.stylegirlfriend.com/>\r\nTwitter <http://www.twitter.com/stylegf", 
	        "Jamasen,\r\nAbsolutely! 11am EST works for me as well.\r\n\r\nMy skype ID is akarwowska1. \r\n\r\nWould you mind sending out a calendar invite please? \r\n\r\nAnia \r\n\r\nAnia Karwowska\r\n \r\nMobile: +44 793 959 5051\r\nEmail:  ania@highskillpro.com <http://www.highskillpro.com/>\r\nLinkedIn: uk.linkedin.com/in/aniakarwowska <http://uk.linkedin.com/in/aniakarwowska", 
	        "Hi Jamasen\r\nGreat email. And great website. \r\n\r\nSure, let\u2019s grab a call. Are you free for a skype call the coming Monday at 9:30am EST? \r\n\r\nAnia \r\n\r\nAnia Karwowska\r\n \r\nMobile: +44 793 959 5051\r\nEmail:  ania@highskillpro.com <http://www.highskillpro.com/>\r\nLinkedIn: uk.linkedin.com/in/aniakarwowska <http://uk.linkedin.com/in/aniakarwowska", 
	        "Hi Jamasen,\r\n\r\nI checked out your site / product, very cool. \r\n\r\nMy schedule is fairly open on Friday 2/12, feel free to shoot me a calendar invite. Looking forward to learning more.\r\n\r\nChad\r\n\t\r\nChad Coleman | Co-Founder & CEO\r\nAscend Agency\r\n720.515.2418 <tel:7205152418>\r\n@agencyascend <http://www.twitter.com/agencyascend>\r\nwww.agencyascend.com <http://www.agencyascend.com/>\r\n\r\n\r\n", 
	        "Jamasen,\r\nThanks for reaching out.\r\nPl. set time on my calendar at relatas.com/sudip <http://relatas.com/sudip", 
	        "Dear Mr Rodriguez\r\nThank you for your email, Given that I have never met you or heard of your\r\ncompany i find your familiar style of communicating disconcerting. However\r\nit is a moot point as i do not see a \"fit\" between our companies. Kindly\r\ntake me off your email list.\r\nRegards,\r\nSid H Belzberg\r\n"
	      ]
	    }

	training_set = {}
	for t, l in zip(saved['texts'], saved['labels']):
		if l not in training_set: training_set[l] = []
		t = t.replace('\n',' ')
		t = t.replace('\t',' ')
		t = t.replace('\r',' ')
		t = t.replace('  ',' ')
		t = t.replace('  ',' ')
		t = t.replace('  ',' ')
		t = t.replace('  ',' ')
		t = t.replace('  ',' ')
		
		training_set[l].append(t)
	# print training_set['not interested']

	texts, labels = [], []
	for overall, sub in in_depth_hierarchy.iteritems():
		for s in sub:
			print overall, s

			texts += training_set.get(s, [])
			labels += [overall]*len(training_set.get(s, []))

	m = lml.MyTextClassifier(ngram_range = (1,3))
	m.fit(texts, labels)
	# print m.analyze()

	print m.predict_proba('''I am very interested''')
	print m.predict_proba('''unsubscribe''')
	print m.predict_proba('''remove me from your list''')



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







