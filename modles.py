from datetime import datetime, timedelta	
import time
import random
from collections import Counter
import googleAPI
from controller import db
import models
import modules

def appGoogleAPI(app):
	new_token = googleAPI.refreshAccessToken(app.google_access_token, app.google_refresh_token)
	if app.google_access_token != new_token:
		print "new token"
		app.google_access_token = new_token
		db.session.commit()
	return app.google_access_token

def checkForReplies(thread, access_token, from_ = 'google'):
	if from_ == 'google':
		for message in googleAPI.getThreadMessages(thread.unique_thread_id, access_token):
			g = googleAPI.cleanMessage(message)
			g['thread_id'] = thread.id
			modules.get_or_create(models.Email, google_message_id=g['google_message_id'], defaults = g)

def getThreadsOfApp(app, from_ = 'google'):
	threads = app.threads
	ids = [(t, len(t.emails)) for t in threads if t.origin == from_ and t.first_made > (datetime.now()-timedelta(days=60)) and (t.last_checked is None or t.last_checked <(datetime.now() - timedelta(hours=1)))]
	return ids

def handleApp(appid = None):
	if not appid: return False
	print "checking app %s" %(appid)
	a = db.session.query(models.App).filter_by(appid=appid).first()
	access_token = appGoogleAPI(a)
	threads = getThreadsOfApp(a)
	for thread in threads:
		print "looking for replies to thread %s which currently has %d messages in it" % thread
		thread[0].last_checked = datetime.now()
		db.session.commit()
		checkForReplies(thread[0], access_token, from_ = 'google')
		thread[0].last_checked = datetime.now()
		tos, froms = [], []
		for t, f in [(t.to_address, t.from_address) for t in thread[0].emails]:
			tos += t.split(',')
			froms += f.split(',')
		thread[0].people_in_conversation = len(set(tos) | set(froms))
		thread[0].all_parties_replied = len(set(tos) | set(froms)) == len(set(tos) & set(froms))
		db.session.commit()
	return {'status':'done', 'appid':appid}

def handleRandomApp():
	print "attempting to handle a random app"
	u = random.sample(db.session.query(models.App.appid).all(), 1)[0][0]
	handleApp(u)
	return True





