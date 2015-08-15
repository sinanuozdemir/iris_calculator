from flask import Flask, render_template
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

#Initialize Form Class
# This form will take in the form data on the front end and use it to predict
# using a pre-loaded model in the model folder!!!!
class PredictForm(Form):
	sepal_length = DecimalField('Sepal Length (cm):', places=2, validators=[Required()])
	sepal_width = DecimalField('Sepal Width (cm):', places=2, validators=[Required()])
	petal_length = DecimalField('Petal Length (cm):', places=2, validators=[Required()])
	petal_width = DecimalField('Petal Width (cm):', places=2, validators=[Required()])
	submit = SubmitField('Submit')


# this will take in the form data on the front end and train the model and store it in the model folder!
class TrainForm(Form):
	n_neighb = SelectField('Number of Neighbors:', choices=[(2,2),(3,3),(4,4),(5,5),(6,6)],coerce=int)
	param_2 = DecimalField('Paramter 2 (Optional)', places = 2, validators=[Optional()])
	param_3 = DecimalField('Paramter 3 (Optional)', places = 2, validators=[Optional()])
	param_4 = DecimalField('Paramter 4 (Optional)', places = 2, validators=[Optional()])
	submit = SubmitField('Submit')


@app.route('/',methods=['GET', 'POST'])
def model():
	#Load Iris Data
	iris_data = load_iris()
	features = iris_data.data
	feature_names = iris_data.feature_names
	target = iris_data.target
	target_names = iris_data.target_names
	prediction, sepal_length, sepal_width, petal_length, petal_width, n_neighb  = None, None, None, None, None, None
	train_form = TrainForm(csrf_enabled=False)
	predict_form = PredictForm(csrf_enabled=False)
	if train_form.validate_on_submit():
		# store the submitted values
		submitted_data = train_form.data
		print submitted_data



		#Retrieve values from form
		n_neighb = submitted_data['n_neighb']
		param_2 = submitted_data['param_2']
		# notice I'm using the same names I used in my TrainForm class up there!!!! On line 27
		

		# lin_reg = LinearRegression()
		# print lin_reg

		knn = KNeighborsClassifier(n_neighbors = n_neighb)
		knn.fit(features, target)
		with open('model/my_model.pkl', 'wb') as f:
			pickle.dump(knn, f)
		print "Trained"
	elif predict_form.validate_on_submit():
		# store the submitted values
		submitted_data = predict_form.data
		print submitted_data

		#Retrieve values from form
		sepal_length = submitted_data['sepal_length']
		sepal_width = submitted_data['sepal_width']
		petal_length = submitted_data['petal_length']
		petal_width = submitted_data['petal_width']
		# notice I'm using the same names I used in my PredictForm class up there!!!! On line 18

		#Create array from values
		flower_instance = [sepal_length, sepal_width, petal_length, petal_width]

		# unpickle my model
		knn = pickle.load(open('model/my_model.pkl'))

		# the machine learning part!!!
		my_prediction = knn.predict(flower_instance)


		# Return only the Predicted iris species
		prediction = target_names[my_prediction][0].capitalize()


	return render_template(
		'model.html',
		predict_form=predict_form, 
		train_form = train_form, 
		prediction=prediction)

#Handle Bad Requests
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)