#!/usr/bin/python

from StringIO import StringIO
import gzip
import urllib2
import string
import subprocess
import argparse
from urlparse import urlparse



#--Notes for each vuln--
#Secure Renegotiation IS NOT supported (openssl) -- Need to test for this  openssl s_client -connect gw-homologa.serasa.com.br:443
#Secure Renegotiation IS supported (openssl)

#Compression: NONE = protected from CRIME (openssl) -- Need to test for this

#no http compression - protected from BREACH/TIME -- Need to test for this

#AES/CBC = Vulnerable to BEAST -- TLS1.1 Only protected from breach -- patched client software makes this infeasible

#Lucky 13 - check for timing differences in invalid padding (practically infeasible)

#RC4 Biases - Move to patched CBC (practically infeasible)

#--todo--
#improve prarser with examples
#improve evidence section (provide leading and trailing text)
#look into recent developments in BEAST
#check ssl ciphers


logLevel = 0

#input a URL to append to
#returns responses
def isHTTPCompressed(url):
	HTTPCompression = False
	HTTPCompressionEvidence = ""

	request = urllib2.Request(url)
	request.add_header('Accept-encoding', 'gzip')

	#to set a proxy
	#proxy = urllib2.ProxyHandler({'http': 'http://127.0.0.1:8080'})
	#opener = urllib2.build_opener(proxy)
	#urllib2.install_opener(opener)

				
	response = urllib2.urlopen(request)	
	if response.getcode() != 200:
		print "Warning, response code is not 200.  Choose a URL which returns a 200 instead of " + response.getcode()

	if response.info().get('Content-Encoding') == 'gzip':
		#log(1, "Evidence for HTTP compression: " + "Content-Encoding: gzip")
		HTTPCompressionEvidence += "Content-Encoding: " + response.info().get('Content-Encoding')

		HTTPCompression = True

	    #to uncompress response
	    #buf = StringIO( response.read())
	    #f = gzip.GzipFile(fileobj=buf)
	    #data = f.read()
	    #print "compressed length: " + str(buf.len) + " Attempt: " + suffix
    
	return {"HTTPCompression": HTTPCompression, "HTTPCompressionEvidence": HTTPCompressionEvidence}
	

	#return secureHTTPCompression


def openSSL(hostname, port, capath):

	secureRenegotiation = False
	secureTLSCompression = False
	secureRenegotiationEvidence = ""
	secureTLSCompressionEvidence = ""

	cmd = "echo 'QUIT' | openssl s_client -connect " + str(hostname)+":"+str(port) + " -CApath " + capath

	log(1, "Executing: " + cmd)

	proc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	for line in proc.stdout:
		log(2, line.replace("\n", ""))
		
		if line.find("Secure Renegotiation IS NOT supported") != -1:
			secureRenegotiation = False
			#log(1, "Evidence for Secure Renegotiation: " + line.replace("\n", ""))
			secureRenegotiationEvidence += line.replace("\n", "")
		if line.find("Secure Renegotiation IS supported") != -1:
			secureRenegotiation = True
			#log(1,"Evidence for Secure Renegotiation: " + line.replace("\n", ""))
			secureRenegotiationEvidence += line.replace("\n", "")

		if line.find("Compression: NONE") != -1:
			secureTLSCompression = True
			#log(1, "Evidence for TLS compression: " + line.replace("\n", ""))
			secureTLSCompressionEvidence += line.replace("\n", "")
		elif line.find("Compression:") != -1:
			#log(1, "Evidence for TLS compression: " + line.replace("\n", ""))
			secureTLSCompressionEvidence += line.replace("\n", "")


	log(2, "------------Begin OpenSSL STDErr------------")
	for line in proc.stderr:
		#logging.info(line.replace("\n", "")),
		log(2, line.replace("\n", ""))
	log(2, "------------END OpenSSL STDErr------------")

	return {"secureRenegotiation": secureRenegotiation, "secureRenegotiationEvidence": secureRenegotiationEvidence, "secureTLSCompression": secureTLSCompression, "secureTLSCompressionEvidence": secureTLSCompressionEvidence  }


def log(level, msg):
	if logLevel >= level:
		print msg

def main():



	parser = argparse.ArgumentParser(description='Scan server for all "practical" SSL vulnerabilities.', epilog='Example of use: ./ssl.py -u "https://www.site.com/" -vv')
	parser.add_argument('-u', '--url', metavar='URL', type=str, required=True,
	                   help='url for testing')
	parser.add_argument('-p', '--port', default=443,
	                   help='port (default: 443)')
	parser.add_argument('-c',  dest='capath', default='/etc/ssl/certs',
	                   help='CA Path (default: /etc/ssl/certs [debian])')
	parser.add_argument('-v', dest='verbose', action='store_true', default=False,
	                   help='verbose output')
	parser.add_argument('-vv', dest='veryverbose', action='store_true', default=False,
	                   help='verbose output')

	args = parser.parse_args()

	global logLevel

	url = str(args.url)
	hostname = urlparse(url).hostname
	port = str(args.port)
	capath = str(args.capath)
	if args.verbose == True:
		logLevel = 1
	if args.veryverbose == True:
		logLevel = 2



	#get openssl results
	results = openSSL(hostname, port, capath)

	positive = ""
	negative = ""

	#output
	if results['secureRenegotiation']:
		negative += "Secure Renegotiation\n"
		negative += "Evidence: " + results['secureRenegotiationEvidence'] + "\n"
	else:
		positive += "Secure Renegotiation is not supported\n"
		positive += "Evidence for report: " + results['secureRenegotiationEvidence'] + "\n"		
	if results['secureTLSCompression']:
		negative += "Secure TLS Compression (no compression)\n"
		negative += "Evidence: " + results['secureTLSCompressionEvidence'] + "\n"
	else:
		positive += "Insecure TLS Compression\n"
		positive += "Evidence for report: " + results['secureTLSCompressionEvidence'] + "\n"		


	results = isHTTPCompressed(url)

	if results['HTTPCompression']:
		positive += "HTTP Compression Enabled. Vulnerable to BREACH/TIME if this is a sensitve page.  You may need to verify a sensitive page is affected manually.\n"
		positive += "Evidence for report: " + results['HTTPCompressionEvidence'] + "\n"
	else:
		negative += "HTTP Compression disabled (safe from BREACH/TIME)\n"
		negative += "Evidence: " + results['HTTPCompressionEvidence'] + "\n"


	print "\n----Positives (need reported)----"
	print positive

	print "----Negatives (dont need reported)----"
	print negative


if __name__ == "__main__":
	main()
