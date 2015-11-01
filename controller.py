from flask import Flask, render_template, g, redirect, url_for, jsonify, request
from flask_bootstrap import Bootstrap
from flask.ext.sqlalchemy import SQLAlchemy
application = Flask(__name__)
application.config.from_object('config')
db = SQLAlchemy(application)
import models


@application.route('/insert', methods=['GET', 'POST'])
def insert():
	print request.method
	if request.method == 'POST':
		try:
			p = models.Visit(**request.form)
			db.session.add(p)
			db.session.commit()
		except Exception as e:
			print e, "error"
	print "here"
	return jsonify(**{'status':'success'})



@application.route('/test',methods=['GET', 'POST'])
def model():
	return render_template('model.html')

#Handle Bad Requests
@application.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

if __name__ == '__main__':
    application.run(debug=True)