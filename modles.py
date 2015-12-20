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



def checkForReplies(threadId, access_token, from_ = 'google'):
	if from_ == 'google':
		for message in googleAPI.getThreadMessages(threadId, access_token):
			g = googleAPI.cleanMessage(message)
			modules.get_or_create(models.Email, google_message_id=g['google_message_id'], defaults = g)

def getUnrepliedThreadsOfApp(app_id, from_ = 'google'):
	emails = db.session.query(models.Email).filter_by(app_id=app_id).all()
	if from_ == 'google':
		ids = [e.google_thread_id for e in emails]
		messages = [e.google_thread_id for e in db.session.query(models.Email).filter(models.Email.google_thread_id.in_(ids))]
		to_return = [k for k, v in Counter(messages).iteritems() if v == 1]
		random.shuffle(to_return)
		return to_return

def handleApp(app_id = 21):
	print "checking app %d" %(app_id)
	access_token = appGoogleAPI(db.session.query(models.App).filter_by(id=app_id).first())
	unread_threads = getUnrepliedThreadsOfApp(app_id)
	print "%d unread threads" %(len(unread_threads))
	for threadId in unread_threads:
		print "looking for replies to thread %s" %(threadId)
		time.sleep(random.randint(2,20))
		checkForReplies(threadId, access_token, from_ = 'google')
	return {'status':'done', 'app_id':app_id}

def handleApps():
	for u in db.session.query(models.App.id).all():
		print handleApp(u[0])

def handleRandomApp():
	u = random.sample(db.session.query(models.App.id).all(), 1)[0][0]
	time.sleep(random.randint(4,15))
	handleApp(u)
	return True





