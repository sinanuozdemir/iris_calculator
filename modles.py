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
		# print sent_through_latracking, "sent_through_latracking"
		messages = googleAPI.getThreadMessages(thread.unique_thread_id, access_token)
		if len(messages) == len(thread_emails):
			# print "no new messages"
			return
		for message in messages:
			try:
				g = googleAPI.cleanMessage(access_token, message, sent_through_latracking)
			except Exception as clean_error:
				print clean_error, "clean_error"
			g['thread_id'] = thread.id	
			if len(thread.emails) > 0:
				g['replied_to'] = sorted(thread.emails, key = lambda x: x.date_sent)[-1].id
			elif g['auto_reply']:
				print "IS AN AUTOREPLY"
				email = None
				try:
					email = sorted(db.session.query(models.Email).filter_by(from_address=g['to_address'], to_address=g['from_address']).all(), key=lambda x:x.date_sent)[-1]
				except Exception as autoreply_error:
					print autoreply_error, "line 42 error"
				print email
				if email:
					g['replied_to'] = email.id
			if 'replied_to' not in g:
				print "could not find reply, looking for last email exchange"
				email = None
				try:
					email = sorted(db.session.query(models.Email).filter_by(from_address=g['to_address'], to_address=g['from_address']).all(), key=lambda x:x.date_sent)[-1]
					print email, "email"
					if email:
						g['replied_to'] = email.id
				except Exception as error:
					print error, "line 54 error"
			if 'auto_reply' in g: del g['auto_reply']
			modules.get_or_create(models.Email, google_message_id=g['google_message_id'], defaults = g)



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
		except Exception as ee:
			print ee, "handle check for replies error"
		_thread.last_checked = datetime.now()
		tos, froms = [], []
		for t, f in [(t.to_address, t.from_address) for t in _thread.emails]:
			if t and f:
				tos += [a.lower() for a in t.split(',')]
				froms += [a.lower() for a in f.split(',')]
		if len(tos) > 0 and len(froms) > 0:
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





