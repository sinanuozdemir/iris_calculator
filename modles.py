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
		thread_emails = thread.emails
		sent_through_latracking = len([a.app_id for a in thread_emails if a.app_id]) > 0
		print sent_through_latracking, "sent_through_latracking"
		messages = googleAPI.getThreadMessages(thread.unique_thread_id, access_token)
		if len(messages) == len(thread_emails):
			print "no new messages"
			return
		for message in messages:
			g = googleAPI.cleanMessage(access_token, message, sent_through_latracking)
			g['thread_id'] = thread.id
			if len(thread.emails) > 0:
				g['replied_to'] = sorted(thread.emails, key = lambda x: x.date_sent)[-1].id
			modules.get_or_create(models.Email, google_message_id=g['google_message_id'], defaults = g)


	a = db.session.query(models.App).filter_by(appid=appid).first()
	access_token = modles.appGoogleAPI(a)
	threads = googleAPI.getThreads(access_token)
	for thread in threads:
		print thread
		t, t_c = modules.get_or_create(models.Thread, unique_thread_id=thread['id'])
		checkForReplies(t, access_token)

#ADDDD eventually need to see if its an outlook or google thread
def handleApp(appid = None):
	if not appid: return False
	print "checking app %s" %(appid)
	a = db.session.query(models.App).filter_by(appid=appid).first()
	access_token = appGoogleAPI(a)
	threads = googleAPI.getThreads(access_token)
	for thread in threads:
		print "looking for replies to thread %s " % thread
		_thread, t_c = modules.get_or_create(models.Thread, unique_thread_id=thread['id'])
		try:
			checkForReplies(_thread, access_token)
			print "CHECKED"
		except Exception as ee:
			print ee, "handle check for replies error"
		_thread.last_checked = datetime.now()
		tos, froms = [], []
		for t, f in [(t.to_address, t.from_address) for t in _thread.emails]:
			tos += [a.lower() for a in t.split(',')]
			froms += [a.lower() for a in f.split(',')]
		_thread.people_in_conversation = len(set(tos) | set(froms))
		_thread.all_parties_replied = len(set(tos) | set(froms)) == len(set(tos) & set(froms))
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





