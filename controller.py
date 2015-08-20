import operator
import numpy as np
import json
import sqlite3
import ff_work
from flask import Flask, render_template, g, redirect, url_for
from flask_bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import IntegerField, StringField, SubmitField, SelectField, DecimalField
from wtforms.validators import Required, Optional
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LinearRegression
from sklearn.datasets import load_iris
import pickle

#Initialize Flask App
app = Flask(__name__)
dict_of_df = pickle.load(open('nfl_model.pkl', 'r'))
names = []
for pos, df in dict_of_df.items():
	names += list(df['Name']+' / ' + df['Pos'])
names = [(n, n) for n in names]

def get_db():
	DATABASE = 'kickass_db.db'
	db = getattr(g, 'db', None)
	if db is None:
		db = g.db = sqlite3.connect(DATABASE)
	return db

def getUpToDate():
	dict_of_df = pickle.load(open('nfl_model.pkl', 'r'))
	cur = get_db().cursor()
	for name, pos, mine in cur.execute(''' select * from pick '''):
		print name, pos, mine
		ff_work.removePlayerFromPos(dict_of_df, name, pos)
	return ff_work.calculateImportances(dict_of_df)



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
		if left[pos] > 0:
			short = dict_of_df[pos].sort_index(by = 'distance', ascending = False).head(7)
			std_ = np.std(list(dict_of_df[pos].sort_index(by = 'distance', ascending = False).head(10)['distance']))
			urgency[pos] = round(std_ * (1 - (chosen[pos] / float(allowed[pos]))), 2)
			picks[pos] = list(short['Name'] + ' / ' + short['distance'].astype(str))
	picks['mine'] = mine
	picks['left'] = left
	picks['chosen'] = chosen
	picks['urgency'] = urgency
	picks['top_field'] = max(urgency.iteritems(), key=operator.itemgetter(1))[0]
	picks['top_pick'] = picks[max(urgency.iteritems(), key=operator.itemgetter(1))[0]][0].split(' / ')[0]
	return picks



class PickForm(Form):
	name = SelectField('Name', choices=names)
	submit = SubmitField('Submit')
	mine = SelectField('Name', choices=[('f', 'NOT MINE'), ('t', 'MINE')])




# this will take in the form data on the front end and train the model and store it in the model folder!
class TrainForm(Form):
	write = DecimalField('write any number in here to refresh', places=2, validators=[Required()])
	submit = SubmitField('Submit')




@app.route('/',methods=['GET', 'POST'])
def model():

	dict_of_df = getUpToDate()

	train_form = TrainForm(csrf_enabled=False)
	pick_form = PickForm(csrf_enabled=False)
	picks = display(dict_of_df)

	if train_form.validate_on_submit():
		init_db()
		# store the submitted values
		submitted_data = train_form.data
		# ff_work.gatherStats()
		dict_of_df = pickle.load(open('nfl_model_backup.pkl', 'r'))


		return redirect('/')

	

	elif pick_form.validate_on_submit():
		db = get_db()
		cur = db.cursor()
		# store the submitted values
		submitted_data = pick_form.data
		name, pos = submitted_data['name'].split(' / ')
		mine = submitted_data.get('mine', 'f')
		insert('pick', ['name', 'pos', 'mine'], [name.lower(), pos, mine])
		return redirect('/')


	return render_template(
		'model.html',
		pick_form=pick_form, 
		train_form = train_form,
		picks = picks)






#Handle Bad Requests
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)