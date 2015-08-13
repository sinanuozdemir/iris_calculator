from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import IntegerField, StringField, SubmitField, SelectField, DecimalField
from wtforms.validators import Required
from sklearn.neighbors import KNeighborsClassifier
from sklearn.datasets import load_iris

#Load Iris Data
iris_data = load_iris()
features = iris_data.data
feature_names = iris_data.feature_names
target = iris_data.target
target_names = iris_data.target_names

#Fit Model
knn = KNeighborsClassifier(n_neighbors=3)
knn.fit(features, target)

#Initialize Flask App
app = Flask(__name__)

#Initialize Form Class
class theForm(Form):
	n_neighb = SelectField('Number of Neighbors:', choices=[(2,2),(3,3),(4,4),(5,5),(6,6)],coerce=int)
	sepal_length = DecimalField('Sepal Length (cm):', places=2, validators=[Required()])
	sepal_width = DecimalField('Sepal Width (cm):', places=2, validators=[Required()])
	petal_length = DecimalField('Petal Length (cm):', places=2, validators=[Required()])
	petal_width = DecimalField('Petal Width (cm):', places=2, validators=[Required()])
	submit = SubmitField('Submit')

@app.route('/',methods=['GET', 'POST'])
def model():
	prediction, sepal_length, sepal_width, petal_length, petal_width, n_neighb  = None, None, None, None, None, None
	form = theForm(csrf_enabled=False)
	if form.validate_on_submit():
		#Retrieve values from form
		sepal_length = form.sepal_length.data
		sepal_width = form.sepal_width.data
		petal_length = form.petal_length.data
		petal_width = form.petal_width.data
		n_neighb = form.n_neighb.data
		#Create array from values
		flower_instance = [int(sepal_length), int(sepal_width), int(petal_length), int(petal_width)]
		#Fit model with n_neigh neighbors
		knn = KNeighborsClassifier(n_neighbors=n_neighb)
		knn.fit(features, target)
		#Return only the Predicted iris species
		prediction = target_names[knn.predict(flower_instance)][0].capitalize()
	return render_template('model.html',form=form,prediction=prediction,sepal_length=sepal_length,
							sepal_width=sepal_width,petal_length=petal_length,petal_width=petal_width,n_neighb=n_neighb)

#Handle Bad Requests
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)