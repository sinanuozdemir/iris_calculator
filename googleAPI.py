import re
import dateutil.parser
import json
import string
import random
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import cgi


########################################
##### GOOGLE API / SENDING EMAILS ######
########################################

SIMPLE_EMAIL_REGEX = '(([a-zA-Z0-9][\w\.-]+)@([a-z-_A-Z0-9\.]+)\.(\w\w\w?))'

'''
INPUT : google auth token
OUTPUT: bool
	T -> auth token is good to go
	F -> auth token is not good to go
'''
def goodGoogleAuth(token):
	try:
		r = requests.get('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'%token)
		return 'error' not in r.json()
	except:
		return False

def detectBouncedEmailFromMessage(message):
	SIMPLE_EMAIL_REGEX = '(([a-zA-Z0-9][\w\.-]+)@([a-z-_A-Z0-9\.]+)\.(\w\w\w?))'
	snippet = message['snippet']
	if 'delivery' in snippet.lower() and 'failed' in snippet.lower():
		return re.search(SIMPLE_EMAIL_REGEX, snippet).group(1)
	return None

def getGoogleAccessToken(refresh_token):
	r = requests.post('https://www.googleapis.com/oauth2/v3/token', data = {
	'client_secret': 'VQ2sIQGhXH-ue6olCgUY9L3g',
	'client_id': '994895035422-bes5cqbhmf140j906598j1q91pvcnn08.apps.googleusercontent.com',
	'refresh_token': refresh_token,
	'grant_type': 'refresh_token'
	})
	response = r.json()
	# print response
	try:
		return response['access_token']
	except:
		return None

def getEmailFromText(t):
	try:
		return re.search(SIMPLE_EMAIL_REGEX, t).group(1)
	except:
		return None

def cleanMessage(m):
	new_m = {}
	new_m['google_message_id'] = m.get('id')
	new_m['google_thread_id'] = m.get('threadId')
	new_m['text'] = m.get('snippet')
	payload = m['payload']['headers']
	for p in payload:
		if p['name'] in ['to', 'Delivered-To', "To"]:
			new_m['to_address'] = getEmailFromText(p['value'])
		elif p['name'] in ['from', 'Return-Path', "From"]:
			new_m['from_address'] = getEmailFromText(p['value'])
		elif p['name'] in ['Date']:
			new_m['date_sent'] = dateutil.parser.parse(p['value'])
		elif p['name'] in ['Subject']:
			new_m['subject'] = p['value']
		elif p['name'] in ['Cc']:
			new_m['cc_address'] = getEmailFromText(p['value'])
		elif p['name'] in ['Bcc']:
			new_m['bcc_address'] = getEmailFromText(p['value'])
	new_m['emailid'] = 'ee'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(62))
	new_m['bounce'] = detectBouncedEmailFromMessage(m) is not None
	return {k:v for k, v in new_m.iteritems() if v}

def getThreadMessages(threadId, access_token):
	url = 'https://www.googleapis.com/gmail/v1/users/me/threads/'+threadId
	headers = {}
	headers['authorization'] = 'Bearer ' + access_token
	messages = requests.get(url, headers = headers).json()['messages']
	return messages


def refreshAccessToken(access, refresh):
	if not goodGoogleAuth(access):
		access = getGoogleAccessToken(refresh)
	return access

def sendEmail(email, access_token, to_address, body = '', subject = '', bcc_address = None, html = None):
	url = 'https://www.googleapis.com/gmail/v1/users/me/messages/send'
	headers = {}
	headers['content-type'] = 'application/json'
	headers['authorization'] = 'Bearer ' + access_token
	headers['content-length'] = 101
	unique = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(70))
	body = cgi.escape(body, True)
	body = body.replace("\n","<br />")
	message = MIMEMultipart('alternative')
	message['to'] = to_address
	message['from'] = email
	if bcc_address: message['bcc'] = bcc_address
	message['subject'] = subject
	part1 = MIMEText(body, 'plain')
	part2 = MIMEText(html, 'html')
	message.attach(part1)
	message.attach(part2)
	data = json.dumps({'raw': base64.urlsafe_b64encode(message.as_string())})
	try:
		r = requests.post(url, data=data, headers = headers)
		return r.json()
	except Exception as e:
		return {'error':str(e)}
