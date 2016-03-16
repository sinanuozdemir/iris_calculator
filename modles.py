import re
from datetime import datetime, timedelta	
import time
import random
from collections import Counter
import googleAPI
from controller import db
import models
import modules
from bs4 import BeautifulSoup as bs
import string

website_re = re.compile("(https?://)?(www.)?([^\.]+)([\.\w]+)/?((\w+/?)*(\?[\w=]+)?)", re.IGNORECASE)


response_template = '''{{insert_response_here}}<br><br><br>Best,<br>Kylie'''
prediction_dict = {
	'unsubscribe':['unsubscribe', "remove me", "take me off", "stop spamming", "spam", "stop emailing me", 'not interested', "please stop"],
	'learn_more': ['could you send me more info', 'what do you do', "how can you help me", "pass along to my manager", "send me a summary"],
	"follow_up": ['reach out in Q']
}

response_dict = {
	'unsubscribe': ['I am sorry to bother you. You have been removed from our list of contacts.', 'My apologies. I will take you off my list of potential prospects. Enjoy the rest of your day.', 'I am so sorry to bother you! I will remove you from the list immediately.'],
	'learn_more':['Thank you for getting back to me. I’m happy to provide more info.<br><br>Legion Analytics empowers sales reps to book more opportunities with less effort by providing fully automated drip campaigns that are consistently populated with net-new prospects by Legion. Create a lead list with demographic filters (Job Title, Industry, Revenue, Location, Keywords, etc) and set up your drip campaign to get started. Legion will then find net-new prospects that fit your demographic criteria and automatically email them per your drip campaign rules. It’s that easy. Once set up, let it run and get interested prospects’ responses in your inbox.<br><br>Would you be interested in a demo with one of our account managers next week?', "I’m happy to provide a summary.<br><br>Legion Analytics empowers sales reps to book more opportunities with less effort by providing fully automated drip campaigns that are consistently populated with net-new prospects by Legion. Create a lead list with demographic filters (Job Title, Industry, Revenue, Location, Keywords, etc) and set up your drip campaign to get started. Legion will then find net-new prospects that fit your demographic criteria and automatically email them per your drip campaign rules. It’s that easy. Once set up, let it run and get interested prospects’ responses in your inbox.<br><br>If you need more information, I’d be happy to coordinate a demo with one of our account managers. How does your next Tuesday look at 11am PT look?"],
	'follow_up':["Sure thing. <br><br>I’ll set a reminder to follow up with you in July. In the mean time, visit some of our <a href='https://www.legionanalytics.com'>free resources</a> for great sales tools you can use."]
}

def appGoogleAPI(app):
	new_token = googleAPI.refreshAccessToken(app.google_access_token, app.google_refresh_token)
	if app.google_access_token != new_token:
		app.google_access_token = new_token
		db.session.commit()
	return app.google_access_token

def checkForReplies(app_id, user_email, thread, access_token, from_ = 'google'):
	text_to_respond_to = None
	if from_ == 'google':
		thread_emails = thread.emails
		sent_through_latracking = len([a.app_id for a in thread_emails if a.app_id]) > 0
		messages = googleAPI.getThreadMessages(thread.unique_thread_id, access_token)
		if len(messages) == len(thread_emails):
			# print  "no new messages"
			return
		for message in messages:
			try:
				g = googleAPI.cleanMessage(message)
			except Exception as clean_error:
				print clean_error, "clean_error"
				pass
			g['thread_id'] = thread.id	
			if len(thread.emails) > 0:
				g['replied_to'] = sorted(thread.emails, key = lambda x: x.date_sent)[-1].id
			elif g['auto_reply']: #  "IS AN AUTOREPLY"
				email = None
				try: email = sorted(db.session.query(models.Email).filter_by(from_address=g['to_address'], to_address=g['from_address']).all(), key=lambda x:x.date_sent)[-1]
				except: pass
				if email: g['replied_to'] = email.id
			

			if 'replied_to' not in g:   #  "could not find reply, looking for last email exchange"
				email = None
				try: email = sorted(db.session.query(models.Email).filter_by(from_address=g['to_address'], to_address=g['from_address']).all(), key=lambda x:x.date_sent)[-1]
				except: pass
				if email: g['replied_to'] = email.id

			# archive bounces and auto-replies if it was sent through latracking
			if (g['auto_reply'] or g['bounce']) and sent_through_latracking: 
				try:
					googleAPI.archiveThread(access_token, g['google_thread_id'])
				except Exception as archive_error:
					print archive_error, "archive_error", g
			
			if 'auto_reply' in g: del g['auto_reply']



			email_in_db, email_created = modules.get_or_create(models.Email, google_message_id=g['google_message_id'], defaults = g)
			if email_created and g['to_address'].lower() == user_email.lower() and g.get('text') and g.get('from_address'):
				text_to_respond_to = g['text']
				from_address = g['from_address']
				email_id = email_in_db.id

		if thread.latracking_reply and text_to_respond_to: #trigger our auto reply
			print "responding to ", text_to_respond_to
			response = None
			for label, keys in prediction_dict.iteritems():
				if sum([l.lower() in text_to_respond_to.lower() for l in keys]) > 0:
					response = random.choice(response_dict[label])
			if response:
				data = {}
				data['html'] = response_template.replace('{{insert_response_here}}', response)
				data['subject'] = thread.emails[-1].subject
				data['to_address'] = from_address
				data['appid'] = app_id
				data['threadID'] = thread.unique_thread_id
				data['replied_to'] = email_id
				print "auto replying to it", data
				sendEmailFromController(data)
			else:
				pass
				# maybe label with needs a human


def _makeDBLink(email_id, text, url, appid):
	r = re.match(website_re, url)
	if '.' not in r.group(4):
		return {'success': False, 'reason': 'not a valid url'}
	if not r.group(1):
		u = 'http://'
	else:
		u = r.group(1)
	u+=r.group(3)+r.group(4)
	if r.group(5): u += '/'+r.group(5)
	app = modules.getModel(models.App, appid=appid)
	if app:
		created = False
		while not created:
			random_link = 'll'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(9))
			l, created = modules.get_or_create(models.Link, linkid=random_link, defaults = {'app_id':app.id, 'email_id':email_id, 'url':u, 'text': text})
		return {'success':True, 'link_id':random_link, 'url':u, 'latracking_url':'https://www.latracking.com/r/'+random_link}
	return {'success':False}

def _makeDBEmail(form_dict):
	app = modules.getModel(models.App, appid=form_dict['appid'])
	if app:
		d = {}
		created = False
		d['app_id'] = app.id
		while not created:
			random_email = 'ee'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(9))
			for i in ['google_message_id', 'google_thread_id', 'date_sent', 'text', 'html', 'cc_address', 'bcc_address', 'to_address', 'from_address', 'subject']:
				if i in form_dict: 
					d[i] = form_dict[i]
					if i == 'text':
						d['makeshift_sentiment'] = googleAPI.MakeshiftSentiment(d[i])
					elif i == 'html':
						d['makeshift_sentiment'] = googleAPI.MakeshiftSentiment(bs(d[i]).text)
			e, created = modules.get_or_create(models.Email, emailid=random_email, **d)
		return {'success':True, 'email_id':e.id, 'emailid':random_email, 'tracking_link':'https://www.latracking.com/e/'+random_email}
	return {'success':False}

	
def sendEmailFromController(email_dict):
	if 'appid' not in email_dict: 
		return {'success':False, 'reason':'need tracking_id'}
	appid = email_dict['appid']
	app = modules.getModel(models.App, appid = email_dict.get('appid'))
	if not app or not app.user.is_verified:
		return {'success':False, 'reason':'bad app id'}
	html = email_dict.get('html', '')
	try:
		if db.session.query(models.Email).filter_by(subject=email_dict['subject'], html = html, from_address=app.google_email, to_address=email_dict['to_address']).first():
			return {'success':False, 'reason':'duplicate email alert'}
	except Exception as ee:
		pass
	if html:
		links = []
		soup = bs(html)
		d = {'appid':appid}
		for i in ['text', 'html', 'cc_address', 'bcc_address', 'to_address', 'from_address', 'subject']:
			if i in email_dict: d[i] = email_dict[i]
		e = _makeDBEmail(d)
		for a in soup.find_all('a'):
			if a.get('href') and 'latracking.com/r/' not in a['href'].lower() and 'mailto:' not in a['href'].lower() and 'tel:' not in a['href'].lower():
				cleaned = _makeDBLink(e['email_id'], a.text, a['href'], appid)
				if cleaned['success']:
					links.append({'url':a.get('href'), 'text':a.text, 'cleaned':cleaned})
					a['href'] = cleaned['latracking_url']
		new_tag = soup.new_tag("img", src=e['tracking_link'], style="height: 1px; width:1px; display: none !important;")
		soup.append(new_tag)
		html = str(soup)
	access_token = appGoogleAPI(app)
	threadID = None
	if email_dict.get('threadID'):
		tt = modules.getModel(models.Thread, unique_thread_id=email_dict.get('threadID'))
		threadID = tt.unique_thread_id
	response = googleAPI.sendEmail(email = app.google_email, access_token = access_token, to_address = d['to_address'], subject = d.get('subject', ''), bcc_address = d.get('bcc_address', ''), html = html, text = email_dict.get('text', ''), threadID = threadID)
	email = db.session.query(models.Email).filter_by(id=e['email_id']).first()
	email.google_message_id = response['id']
	email.from_address = app.google_email
	thread_created = False
	while not thread_created:
		random_thread = 'tt'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(9))
		thread, thread_created = modules.get_or_create(models.Thread, threadid=random_thread, unique_thread_id = response['threadId'], origin='google', app_id = app.id, defaults = {'first_made':datetime.now()})
	if ('demi' in app.google_email or 'kylie' in app.google_email) and ('sinan' in email_dict['to_address'] or 'jamasen' in email_dict['to_address']):
		thread.latracking_reply = True
	email.google_thread_id = response['threadId']
	if email_dict.get('replied_to'):
		email.replied_to = email_dict.get('replied_to')
	email.thread_id = thread.id
	if email_dict.get('threadID'):
		email.google_thread_id = email_dict['threadID']
		email.thread_id = tt.id
	email.date_sent = datetime.utcnow()
	db.session.commit()
	return {'success':True, 'links':links, 'cleaned_html':str(soup), 'email':e, 'threadid':random_thread}
	# j = jsonify(success=True, links=links, cleaned_html=str(soup), email=e, threadid = random_thread)
	# return j


#ADDDD eventually need to see if its an outlook or google thread
def handleApp(appid = None):
	if not appid: return False
	a = db.session.query(models.App).filter_by(appid=appid).first()
	print "handling app", appid
	access_token = appGoogleAPI(a)
	threads = googleAPI.getThreads(access_token, a.google_email)
	for thread in threads:
		_thread, t_c = modules.get_or_create(models.Thread, unique_thread_id=thread['id'])
		try:
			checkForReplies(appid, a.google_email, _thread, access_token)
		except Exception as ee:
			print ee, "check_for_replies_error"
	return {'status':'done', 'appid':appid}

def handleRandomApp():
	try:
		u = random.sample(db.session.query(models.App.appid).all(), 1)[0][0]
		handleApp(u)
	except Exception as random_eror:
		pass
	return True





