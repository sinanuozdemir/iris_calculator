from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.cors import CORS
application = Flask(__name__)
application.config.from_object('config')
CORS(application)
from user_agents import parse
db = SQLAlchemy(application)
import models
import geocoder


@application.route('/insert', methods=['POST'])
def insert():
	error = 'nothing more to see here'
	try:
		d = {}
		print request.__dict__
		d['private_ip'] = request.environ.get('REMOTE_ADDR')
		d['public_ip'] = request.environ.get('HTTP_X_FORWARDED_FOR')
		if d['public_ip']:
			g = geocoder.ip(d['public_ip'])
			d['lat'], d['lng'] = g.latlng
			d['city'] = g.city
			d['country'] = g.country
		d['user_agent'] = request.environ.get('HTTP_USER_AGENT')
		if d['user_agent']:
			user_agent = parse(d['user_agent'])
			d['browser'] = user_agent.browser.family
			d['is_bot'], d['is_mobile'], d['is_tablet'], d['is_pc'] = user_agent.is_bot, user_agent.is_mobile, user_agent.is_tablet, user_agent.is_pc
		d['full_url'] = request.environ.get('HTTP_ORIGIN')
		d['secure'] = 'https://' in d['full_url']
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



'''
   <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js"></script>

	<script type="application/javascript">
	$(document).ready(function(){
	var j = {"full_url":window.location.origin}; 
			$.ajax({
			  type: "POST",
			  crossDomain: true,
              // contentType: "application/json; charset=utf-8",
              // dataType: "jsonp",
			  url: "https://latracking.com/insert",
			  data: j,
			})
	});
		
</script>
'''


