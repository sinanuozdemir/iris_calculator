from flask import Flask, render_template, g, redirect, url_for, jsonify
from flask_bootstrap import Bootstrap
from flask.ext.sqlalchemy import SQLAlchemy
from flask import request


application = Flask(__name__)
application.config.from_object('config')
db = SQLAlchemy(application)
import models


@application.route('/insert', methods=['POST'])
def insert():
	p = models.Visit(**request.form)
	db.session.add(p)
	db.session.commit()
	return jsonify(**{'status':'success', 'visit id':str(p.id)})



@application.route('/test',methods=['GET', 'POST'])
def model():
	return render_template('model.html')

#Handle Bad Requests
@application.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

if __name__ == '__main__':
    application.run(debug=True)