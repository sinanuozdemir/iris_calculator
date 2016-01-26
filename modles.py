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
			g = googleAPI.cleanMessage(access_token, message)
			g['thread_id'] = thread.id
			g['replied_to'] = thread.emails[-1].id
			modules.get_or_create(models.Email, google_message_id=g['google_message_id'], defaults = g)

def getThreadsOfApp(app, from_ = 'google'):
	threads = app.threads
	ids = [t for t in threads if t.origin == from_ and t.first_made > (datetime.now()-timedelta(days=60)) and (t.last_checked is None or t.last_checked <(datetime.now() - timedelta(minutes=5)))]
	# ids = [t for t in threads[:1000] if t.origin == from_ and t.first_made > (datetime.now()-timedelta(days=1))]
	return ids


#ADDDD eventually need to see if its an outlook or google thread
def handleApp(appid = None):
	if not appid: return False
	print "checking app %s" %(appid)
	a = db.session.query(models.App).filter_by(appid=appid).first()
	access_token = appGoogleAPI(a)
	print access_token
	threads = getThreadsOfApp(a)
	for thread in threads:
		print "looking for replies to thread %s " % thread
		thread.last_checked = datetime.now()
		db.session.commit()
		try:
			checkForReplies(thread, access_token, from_ = 'google')
		except Exception as eeeee:
			print eeeee, "error at checkforreplies"
			continue
		thread.last_checked = datetime.now()
		tos, froms = [], []
		for t, f in [(t.to_address, t.from_address) for t in thread.emails]:
			tos += [a.lower() for a in t.split(',')]
			froms += [a.lower() for a in f.split(',')]
		thread.people_in_conversation = len(set(tos) | set(froms))
		thread.all_parties_replied = len(set(tos) | set(froms)) == len(set(tos) & set(froms))
		db.session.commit()
	return {'status':'done', 'appid':appid}

def handleRandomApp():
	print "attempting to handle a random app"
	try:
		u = random.sample(db.session.query(models.App.appid).all(), 1)[0][0]
		handleApp(u)
	except Exception as random_eror:
		print random_eror, "ERROR AT HANDLE RANDOM APP"
	return True





