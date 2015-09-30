import operator
import numpy as np
import json
import sqlite3
from artichoke import UpworkScraper, IndeedScraper
from keywords import getKeyWords
from flask import Flask, render_template, g, redirect, url_for
from flask_bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import IntegerField, StringField, SubmitField, SelectField, DecimalField
from wtforms.validators import Required, Optional

import sys
reload(sys)
sys.setdefaultencoding("utf-8")

#Initialize Flask App
app = Flask(__name__)

def get_db():
	DATABASE = 'artichoke.db'
	db = getattr(g, 'db', None)
	if db is None:
		db = g.db = sqlite3.connect(DATABASE)
	return db

def init_db():
	db = get_db()
	cur = db.cursor()
	cur.execute('''DROP TABLE pick''')
	cur.execute('''CREATE TABLE pick (name text, pos text, mine text)''')


def insert(table, fields=(), values=()):
	cur = get_db().cursor()
	query = 'INSERT INTO %s (%s) VALUES (%s)' % (
		table,
		', '.join(fields),
		', '.join(['?'] * len(values))
	)
	cur.execute(query, values)
	g.db.commit()
	id = cur.lastrowid
	cur.close()
	return id

def display(dict_of_df):
	db = get_db()
	cur = get_db().cursor()
	mine = cur.execute('''select * from pick where mine="t" ''').fetchall()
	mine = [{'pos':m[1], 'name':m[0].title()} for m in mine]
	allowed = {'QB':2, 'TE':4, 'WR':5, 'DEF':1, 'K':1, 'RB':4}
	left = allowed.copy()
	chosen = {'QB':0, 'TE':0, 'WR':0, 'DEF':0, 'K':0, 'RB':0}
	for m in mine:
		left[m['pos']] -= 1
		chosen[m['pos']] += 1
	picks = {}
	urgency = {}
	for pos in ['QB', 'RB', 'WR', 'TE']:
		short = dict_of_df[pos].sort_index(by = 'distance', ascending = False).head(7)
		std_ = np.std(list(dict_of_df[pos].sort_index(by = 'distance', ascending = False).head(10)['distance']))
		
		urgency[pos] = round(std_, 3)
		# urgency[pos] = round(std_ / (1 - (chosen[pos] / float(allowed[pos]))), 3)
		picks[pos] = list(short['Name'] + ' / ' + short['distance'].astype(str))
	picks['mine'] = mine
	picks['left'] = left
	picks['chosen'] = chosen
	picks['urgency'] = urgency
	picks['top_field'] = max(urgency.iteritems(), key=operator.itemgetter(1))[0]
	picks['top_pick'] = picks[max(urgency.iteritems(), key=operator.itemgetter(1))[0]][0].split(' / ')[0]
	return picks



class SearchForm(Form):
	keywords = StringField('Submit')
	submit = SubmitField('Submit')




@app.route('/',methods=['GET', 'POST'])
def model():

	search_form = SearchForm(csrf_enabled=False)
	keywords = None
	results = None
	new_keywords = None
	if search_form.validate_on_submit():
		init_db()
		# store the submitted values
		submitted_data = search_form.data
		keywords = submitted_data.get('keywords', '')
		if len(keywords):
			results = IndeedScraper('baltimore').get_postings(keywords, pages=1)
			if len(results):
				texts = [posting['description'] for posting in results]
				new_keywords = list(getKeyWords(texts))
				new_keywords = ',  '.join(new_keywords)
				print new_keywords

	

	return render_template(
		'model.html',
		search_form = search_form,
		new_keywords = new_keywords,
		results = results,
		keywords = keywords)






#Handle Bad Requests
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)