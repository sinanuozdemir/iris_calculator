import time
import re
from bs4 import BeautifulSoup as bs
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

def getEmailFromText(t):
	try:
		return re.search(SIMPLE_EMAIL_REGEX, t).group(1).lower()
	except:
		return None

def detectAutoReply(email_dict):
	subject = email_dict.get('subject', '').lower()
	text = email_dict.get('text', '').lower()+' '+email_dict.get('snippet', '').lower()+' '+email_dict.get('html', '').lower()
	if 'delayed response' in subject or 'automatic reply' in subject:
		return True
	if 'out of office' in subject or 'out of office' in text:
		return True
	if 'ooo-' in subject or 'ooo -' in subject:
		return True
	return False


def detectBouncedEmailFromMessage(d):
	SIMPLE_EMAIL_REGEX = '(([a-zA-Z0-9][\w\.-]+)@([a-z-_A-Z0-9\.]+)\.(\w\w\w?))'
	snippet = d.get('text', '').lower()

	if snippet == '': snippet = d.get('html', '').lower()
	if snippet == '': snippet = d.get('snippet', '').lower()
	subject = d.get('subject', '').lower()
	from_address = d.get('from_address', '').lower()


	if 'delivery' in snippet and 'failed' in snippet:
		try:
			return re.search(SIMPLE_EMAIL_REGEX, snippet).group(1)
		except:
			return 'unknown'
	elif 'failure notice' in subject or 'delivery failure' in subject:
		try:
			return re.search(SIMPLE_EMAIL_REGEX, snippet).group(1)
		except:
			return 'unknown'
	elif 'delivery' in snippet and 'delay' in snippet:
		try:
			return re.search(SIMPLE_EMAIL_REGEX, snippet).group(1)
		except:
			return 'unknown'
	elif 'delivery' in subject and 'delay' in subject:
		try:
			return re.search(SIMPLE_EMAIL_REGEX, subject).group(1)
		except:
			return 'unknown'
	elif 'undelivered mail' in snippet or 'undelivered mail' in subject:
		try:
			return re.search(SIMPLE_EMAIL_REGEX, snippet).group(1)
		except:
			return 'unknown'
	elif 'undeliverable' in snippet or 'undeliverable' in subject:
		try:
			return re.search(SIMPLE_EMAIL_REGEX, subject).group(1)
		except:
			return 'unknown'
	elif 'mailer-daemon' in from_address:
		return 'unknown'
	return None

def getGoogleAccessToken(refresh_token):
	r = requests.post('https://www.googleapis.com/oauth2/v3/token', data = {
	'client_secret': 'VQ2sIQGhXH-ue6olCgUY9L3g',
	'client_id': '994895035422-bes5cqbhmf140j906598j1q91pvcnn08.apps.googleusercontent.com',
	'refresh_token': refresh_token,
	'grant_type': 'refresh_token'
	})
	response = r.json()
	try:
		return response['access_token']
	except:
		return None

def MakeshiftSentiment(text):
	text = text.lower().strip()
	negs = {'no':-3, 'no thank you':-1, 'remove me':-5, 'unsubscribe':-5}
	pos = {'sure':1, 'yes':1, 'love to':2, 'set up a':1, 'why not':1}
	score = 0
	for k, v in sorted(negs.items(), key=lambda x:-len(x)):
		score += v*text.count(k)
		text = re.sub(k, '', text)
	for k, v in sorted(pos.items(), key=lambda x:-len(x)):
		score += v*text.count(k)
		text = re.sub(k, '', text)
	return score

def cleanMessage(m):
	new_m = {}
	new_m['google_message_id'] = m.get('id')
	new_m['google_thread_id'] = m.get('threadId')
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
	payload = m['payload'].get('parts', [])
	for p in payload:
		if 'text/plain' in p['mimeType']:
			new_m['text'] = base64.urlsafe_b64decode(str(p['body']['data'])).split('\r\n\r\nOn')[0]
		elif 'html' in p['mimeType']:
			new_m['html'] = base64.urlsafe_b64decode(str(p['body']['data']))
	if new_m.get('html') and not new_m.get('text'):
		new_m['text'] = bs(new_m['html']).text
	if 'text' not in new_m and 'snippet' in m:
		new_m['text'] = m['snippet']
	if new_m.get('text'):
		new_m['makeshift_sentiment'] = MakeshiftSentiment(new_m.get('text'))
	new_m['emailid'] = 'ee'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(9))
	try:
		_bounce = detectBouncedEmailFromMessage(new_m)
	except:
		_bounce = None
	new_m['bounced_email'] = _bounce
	new_m['bounce'] = _bounce is not None
	new_m['auto_reply'] = detectAutoReply(new_m)
	return {k:v for k, v in new_m.iteritems() if v is not None and v != '' and v != []}

def archiveThread(access_token, threadId):
	url = 'https://www.googleapis.com/gmail/v1/users/me/threads/'+threadId+'/modify'
	headers = {}
	headers['content-type'] = 'application/json'
	headers['authorization'] = 'Bearer ' + access_token
	data = {}
	data['removeLabelIds']=['INBOX', "UNREAD"]
	data = json.dumps(data)
	message = requests.post(url, headers = headers, data = data).json()
	return message

def getUsedLabels(access_token):
	url = 'https://www.googleapis.com/gmail/v1/users/me/labels'
	headers = {}
	headers['content-type'] = 'application/json'
	headers['authorization'] = 'Bearer ' + access_token
	message = requests.get(url, headers = headers).json()
	return message

def getMessagesMarkedWithLabel(access_token, label_id):
	url = 'https://www.googleapis.com/gmail/v1/users/me/messages?labelIds='+label_id
	headers = {}
	headers['content-type'] = 'application/json'
	headers['authorization'] = 'Bearer ' + access_token
	messages = requests.get(url, headers = headers).json()
	return messages


def getThreadMessages(threadId, access_token):
	url = 'https://www.googleapis.com/gmail/v1/users/me/threads/'+threadId
	headers = {}
	headers['authorization'] = 'Bearer ' + access_token
	messages = requests.get(url, headers = headers).json()['messages']
	try:
		messages = sorted(messages, key = lambda x:x['internalDate'])
	except Exception as sorted_error:
		pass
	return messages


def getThreads(access_token, email):
	headers = {}
	headers['authorization'] = 'Bearer ' + access_token
	next_page = '1'
	threads = []
	num = 2 # gets two pages worth of threads directly sent to this person, thats 200 of them
	# specifically gets threads aimed at user
	while next_page is not None:
		if next_page == '1':
			url = 'https://www.googleapis.com/gmail/v1/users/me/threads?maxResults=100&q=to:'+email
		else:
			url = 'https://www.googleapis.com/gmail/v1/users/me/threads?maxResults=100&pageToken='+next_page+'&q=to:'+email
		response = requests.get(url, headers = headers).json()
		next_page = response.get('nextPageToken')
		if 'threads' in response:
			threads += response['threads']
		time.sleep(2)
		num -=1
		if num <=0: break

	num = 2 # gets two pages worth of threads, thats 200 of them
	# gets threads in general
	while next_page is not None:
		if next_page == '1':
			url = 'https://www.googleapis.com/gmail/v1/users/me/threads?maxResults=100'
		else:
			url = 'https://www.googleapis.com/gmail/v1/users/me/threads?maxResults=100&pageToken='+next_page
		response = requests.get(url, headers = headers).json()
		next_page = response.get('nextPageToken')
		if 'threads' in response:
			threads += response['threads']
		time.sleep(2)
		num -=1
		if num <=0: break
	return threads


def getMessage(messageId, access_token, att):
	url = 'https://www.googleapis.com/gmail/v1/users/me/messages/'+messageId
	headers = {}
	headers['authorization'] = 'Bearer ' + access_token
	message = requests.get(url, headers = headers).json()

	return message

def refreshAccessToken(access, refresh):
	if not goodGoogleAuth(access):
		access = getGoogleAccessToken(refresh)
	return access



def sendEmail(email, access_token, to_address, text = '', subject = '', bcc_address = None, html = '', threadID = None):
	url = 'https://www.googleapis.com/gmail/v1/users/me/messages/send'
	headers = {}
	headers['content-type'] = 'application/json'
	headers['authorization'] = 'Bearer ' + access_token
	headers['content-length'] = 101
	text = cgi.escape(text, True)
	text = text.replace("\n","<br />")
	message = MIMEMultipart('alternative')
	message['to'] = to_address
	message['from'] = email
	if bcc_address: message['bcc'] = bcc_address
	message['subject'] = subject
	part1 = MIMEText(text, 'plain')
	part2 = MIMEText(html, 'html')
	message.attach(part1)
	message.attach(part2)
	data = {'raw': base64.urlsafe_b64encode(message.as_string())}
	if threadID:
		data['threadID'] = threadID
	data = json.dumps(data)
	try:
		r = requests.post(url, data=data, headers = headers)
		return r.json()
	except Exception as e:
		return {'error':str(e)}


