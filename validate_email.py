import time
import random
import telnetlib
import os
import re
import socket
import smtplib
import dns.resolver

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


def validate(addressToVerify):
	match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', addressToVerify)
	handle, domain = addressToVerify.split('@')
	if match == None:
		print 'Bad Syntax'
		raise ValueError('Bad Syntax')

	
	try:
		records = dns.resolver.query(domain, 'MX')
		mxRecord = records[0].exchange
		mxRecord = str(mxRecord)
		# mxRecord = getHost(domain)
	except:
		return None
	print mxRecord, "mx ercord"
	if mxRecord is None:
		return {'status':'failed', 'reason': 'no MX record found'}

	if handle != 'blehblehblehbleh' and domainIsCatchAll(domain):
		return {'status':'success', 'is_deliverable':'Valid', 'catch_all':True}
	# Get local server hostname
	host = socket.gethostname()
	# SMTP lib setup (use debug level for full output)
	server = smtplib.SMTP()
	server.set_debuglevel(0)

	# SMTP Conversation
	server.connect(mxRecord)
	time.sleep(random.choice(range(3)))
	server.helo(host)
	time.sleep(random.choice(range(3)))
	server.mail(addressToVerify)
	time.sleep(random.choice(range(3)))
	code, message = server.rcpt(str(addressToVerify))
	time.sleep(random.choice(range(3)))
	server.quit()
	print code, message
	# Assume 250 as Success
	if code == 250:
		i = 'Valid'
	else:
		i = 'Invalid'
	to_return = {'status':'success', 'is_deliverable':i}
	if handle != 'blehblehblehbleh':
		to_return['catch_all'] = domainIsCatchAll(domain)
	return to_return


