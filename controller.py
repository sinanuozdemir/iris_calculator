from flask import Flask, render_template, g, redirect, url_for, jsonify
from flask_bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import IntegerField, StringField, SubmitField, SelectField, DecimalField
from wtforms.validators import Required, Optional
from flask.ext.sqlalchemy import SQLAlchemy
from flask import request


application = Flask(__name__)
application.config.from_object('config')
db = SQLAlchemy(application)
import models


def insert_(table, fields=(), values=()):
	cur = db.cursor()
	query = 'INSERT INTO %s (%s) VALUES (%s)' % (
		table,
		', '.join(fields),
		', '.join(['?'] * len(values))
	)
	cur.execute(query, values)
	g.db.commit()
	id_ = cur.lastrowid
	cur.close()
	return id_


@application.route('/insert', methods=['POST'])
def insert():
	p = models.Visit(**request.form)
	db.session.add(p)
	db.session.commit()
	return jsonify(**{'status':'success', 'visit id':str(p.id)})



@application.route('/test',methods=['GET', 'POST'])
def model():
	print db.session.query(models.Visit).count()
	return render_template(
		'model.html'
		)






#Handle Bad Requests
@application.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

if __name__ == '__main__':
    application.run(debug=True)