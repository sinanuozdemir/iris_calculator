from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.cors import CORS
application = Flask(__name__)
application.config.from_object('config')
CORS(application)
db = SQLAlchemy(application)
import models


@application.route('/insert', methods=['POST'])
def insert():
	error = 'nothing more to see here'
	try:
		d = {}
		print request.__dict__
		print request.form['full_url'], "here"
		print request.form
		d['private_ip'] = request.environ.get('REMOTE_ADDR')
		d['public_ip'] = request.environ.get('HTTP_X_FORWARDED_FOR')
		d['browser'] = request.environ.get('HTTP_USER_AGENT')
		d['full_url'] = request.form.get('full_url')
		print d
		p = models.Visit(**d)
		p.date = datetime.now()
		db.session.add(p)
		db.session.commit()
	except Exception as e:
		print e
		error = e
	return jsonify(**{'status':'success', 'description':error})



@application.route('/test',methods=['GET', 'POST'])
def model():
	print db.session.query(models.Visit).count()
	return render_template('model.html')

#Handle Bad Requests
@application.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

if __name__ == '__main__':
    application.run(debug=True)