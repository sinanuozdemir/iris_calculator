from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask.ext.sqlalchemy import SQLAlchemy
application = Flask(__name__)
application.config.from_object('config')
db = SQLAlchemy(application)
import models


@application.route('/insert', methods=['POST'])
def insert():
	error = 'nothing more to see here'
	try:
		d = {}
		for k, v in request.form.copy().items():
			d[k] = v
		p = models.Visit(**d)
		p.date = datetime.now()
		db.session.add(p)
		db.session.commit()
	except Exception as e:
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