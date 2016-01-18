import time
import random
import telnetlib
import os
import re
import socket
import smtplib
import dns.resolver
import celery

# get domain host from 'nslookup'
def getHost(domain) :
    query = 'nslookup -q=mx {0}'
    pattern = '\*\*\sserver\scan\'t\sfind'
    reg = re.compile('mail exchanger = \d+ (\S+)', re.IGNORECASE)
    mx_hosts = []
    connect = False
    count = 0
    command = query.format(domain)
    with os.popen(command) as response :
        result = response.readlines()
        cleaned_results = [re.search(reg, r).group(1)[:-1] for r in result if re.search(reg, r)]
        for clean_result in cleaned_results:
            try:
                tn = telnetlib.Telnet(clean_result, 25, timeout = 5)
                tn.close()
                return clean_result
            except:
                pass
    return None


def domainIsCatchAll(domain):
	return validate('blehblehblehbleh@'+domain).get('is_deliverable') == 'Valid'


def _validateOnRecord(e, rec):
	host = socket.gethostname()
	# SMTP lib setup (use debug level for full output)
	server = smtplib.SMTP(timeout=10)
	server.set_debuglevel(0)
	# SMTP Conversation
	server.connect(rec)
	time.sleep(random.choice(range(3)))
	server.helo(host)
	time.sleep(random.choice(range(3)))
	server.mail(addressToVerify)
	time.sleep(random.choice(range(3)))
	code, message = server.rcpt(str(e))
	time.sleep(random.choice(range(3)))
	server.quit()
	print code, message
	# Assume 250 as Success
	if code == 250:
		return 'Valid'
	else:
		return 'Invalid'

@celery.task(queue='latacking', name="validate_email")
def validate(addressToVerify):
	addressToVerify = addressToVerify.strip().lower()
	match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', addressToVerify)
	handle, domain = addressToVerify.split('@')
	if match == None:
		print 'Bad Syntax'
		raise ValueError('Bad Syntax')
	try:
		records = dns.resolver.query(domain, 'MX')
		mxRecord = records[0].exchange
		mxRecord = str(mxRecord)
	except:
		return {'status':'failed', 'reason': 'no MX record found'}
	if mxRecord is None:
		return {'status':'failed', 'reason': 'no MX record found'}
	print mxRecord
	for record in records:
		try:
			i = _validateOnRecord(addressToVerify, record.exchange)
		except Exception as ee:
			print ee
			i = None
		print record.exchange, i
		if i:
			break
	to_return = {'status':'success', 'is_deliverable':i}


	return to_return


