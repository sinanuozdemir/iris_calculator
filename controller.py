import re
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response, redirect, abort
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.cors import CORS


application = Flask(__name__)
application.config.from_object('config')
CORS(application)
from user_agents import parse
db = SQLAlchemy(application)
import models
import geocoder
from random import randint
import json
from datetime import datetime
from collections import Counter


@application.route("/get_my_ip", methods=["GET"])
def get_my_ip():
	fwd = request.environ.get('HTTP_X_FORWARDED_FOR', None)
	if fwd is None:
		fwd = request.environ.get('REMOTE_ADDR')
	# sometimes x-forwarded-for contains multiple addresses,
	# actual client is first, rest are proxy
	ip = fwd.split(',')[0]
	if request.args.get('format') == 'json':
		return jsonify(**{'ip': ip})
	else:
		return ip


@application.route("/data/<path:host>")
def chart_data(host):
	data_set = db.session.query(models.Visit).filter(models.Visit.full_url.ilike('%'+host+'%')).values('date', 'browser')
	browsers = []
	dates = []
	for d in data_set:
		browsers.append(d[1])
		dates.append(datetime.strftime(d[0], '%m-%d-%Y'))
	data = {
		'host':host,
		'browsers': [{'label':k, 'y':v} for k, v in Counter(browsers).iteritems()],
		'visits': sorted([{'label':k, 'y':v} for k, v in Counter(dates).iteritems()], key = lambda x:x['label'])
	}
	js = json.dumps(data)

	resp = Response(js, status=200, mimetype='application/json')

	return resp

website_re = re.compile("(https?://)(www.)?([^\.]+).\w+/?((\w+/?)*(\?[\w=]+)?)", re.IGNORECASE)

@application.route('/insert', methods=['GET', 'POST'])
def insert():
	error = 'tracked visit. Nothing more to see here'
	try:
		d = {}
		print request.__dict__
		d['private_ip'] = request.environ.get('REMOTE_ADDR')
		d['public_ip'] = request.environ.get('HTTP_X_FORWARDED_FOR', None)
		print "IPPPPP", d
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
		d['full_url'] = request.environ.get('HTTP_REFERER')
		d['website_id'] = 1
		if request.args.get('emailid'):
			d['email_id'] = db.session.query(models.Email).filter_by(emailid=request.args.get('emailid')).first()
			if d['email_id']:
				d['email_id'] = d['email_id'].id
				d['website_id'] = 1
				error = 'successfully tracked email'
			else:
				error = 'no such email found'
		elif d['full_url']:
			ur = d['full_url'].replace('https://','').replace('http://','').replace('www.','')
			if '/' not in ur: ur += '/'
			base, d['after'] = ur[:ur.index('/')], ur[ur.index('/')+1:]
			d['website_id'] = get_or_create(models.Website, base = base).id
		
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
		else:
			error = 'no recognized action taken'
		print d
		p = models.Visit(**d)
		p.date = datetime.now()
		db.session.add(p)
		db.session.commit()
	except Exception as e:
		print e
		error = repr(e)
	return jsonify(**{'status':'success', 'description':error})

def get_or_create(model, **kwargs):
    instance = db.session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance
    else:
        instance = model(**kwargs)
        db.session.add(instance)
        db.session.commit()
        return instance

def getUser(email):
	return db.session.query(models.User).filter(models.User.email.like(email)).first()

def getWebsite(base_):
	return db.session.query(models.Website).filter(models.Website.base.like(base_)).first()


@application.route('/check',methods=['GET'])
def check():
	# u = models.User(email='sinan@legionanalytics.com')
	# db.session.add(u)
	# db.session.commit()
	# a = models.App(user = getUser('sinan@legionanalytics.com'), website = getWebsite('legionanalytics.com'))
	# db.session.add(a)
	# db.session.commit()
	# print load_user(2)
	# print db.session.query(models.Website).filter_by(**{'base':'legionanalytics.com'}).first()
	print request.args.get('emailid')
	# for w in db.session.query(models.Website).all():
	# 	print w.visits, w


@application.route('/test',methods=['GET', 'POST'])
def model():
	return render_template('model.html')

#Handle Bad Requests
@application.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404




if __name__ == '__main__':
    application.run(debug=True)


