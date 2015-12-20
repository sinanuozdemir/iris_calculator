import time
import random
from collections import Counter
import googleAPI
from controller import db
import models
import modules

def userGoogleAPI(user):
	new_token = googleAPI.refreshAccessToken(user.google_access_token, user.google_refresh_token)
	if user.google_access_token != new_token:
		print "new token"
		user.google_access_token = new_token
		db.session.commit()
		db.session.close()
	return user.google_access_token



def checkForReplies(threadId, access_token, from_ = 'google'):
	if from_ == 'google':
		for message in googleAPI.getThreadMessages(threadId, access_token):
			g = googleAPI.cleanMessage(message)
			modules.get_or_create(models.Email, google_message_id=g['google_message_id'], defaults = g)

def getUnrepliedThreadsOfUser(user_id, from_ = 'google'):
	app = db.session.query(models.App).filter_by(user_id=user_id).first()
	emails = db.session.query(models.Email).filter_by(app_id=app.id).all()
	if from_ == 'google':
		ids = [e.google_thread_id for e in emails]
		messages = [e.google_thread_id for e in db.session.query(models.Email).filter(models.Email.google_thread_id.in_(ids))]
		return random.shuffle([k for k, v in Counter(messages).iteritems() if v == 1])

def handleUser(user_id = 21):
	print "checking user %d" %(user_id)
	access_token = userGoogleAPI(db.session.query(models.User).filter_by(id=user_id).first())
	unread_threads = getUnrepliedThreadsOfUser(user_id)
	print "%d unread threads" %(len(unread_threads))
	for threadId in unread_threads:
		print "looking for replies to thread %s" %(threadId)
		time.sleep(random.randint(2,7))
		checkForReplies(threadId, access_token, from_ = 'google')
	return {'status':'done', 'user_id':user_id}

def handleUsers():
	for u in db.session.query(models.User.id).all():
		print handleUser(u[0])

def handleRandomUser():
	u = random.sample(db.session.query(models.User.id).all(), 1)[0][0]
	time.sleep(random.randint(4,10))
	handleUser(u)
	return True





