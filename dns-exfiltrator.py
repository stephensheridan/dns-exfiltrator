import time
from noise import pnoise1
from noise import snoise2
from numpy import interp
import numpy as np
import matplotlib.pyplot as plt
from subprocess import call
from scapy.all import *

# Obfuscation types
RANDOM = 1
POISSON = 2
PERLIN = 3
PIGGYBACK_HTTP = 4
PIGGYBACK_DNS = 5

# Maximum wait time (in seconds) between communications
MAX_WAIT = 30
MAX_BURST = 10

# Globals
base = 2
step = 0.01
prev_pval = 2
poissonList = []
currPoisson = 0;
domain_rotate = 0 # used in testing to query alexa top 100000

def makeDnsQuery():
	global domain_rotate
	#call(["dig", lines[domain_rotate].rstrip()])
	query = lines[domain_rotate].rstrip()
	answer = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=query)),verbose=0)
	#print answer.show()
	domain_rotate = domain_rotate + 1
	if (domain_rotate == len(lines)):
		domain_rotate = 0


def generateRandomDNS():
	# Write the code to create random DNS queries here
	delay = np.random.randint(0,MAX_WAIT)
	time.sleep(delay)
	for x in range(np.random.randint(1, MAX_BURST)):
		makeDnsQuery()


def generatePoissonDNS():
	global poissonList
	global currPoisson
	# Write the code to do poisson distribution DNS here
	if (len(poissonList) == 0):
		poissonList = np.random.poisson(MAX_WAIT/2, 10000)

	delay = poissonList[currPoisson]
	currPoisson = currPoisson + 1
	time.sleep(delay)
	for x in range(np.random.randint(1, MAX_BURST)):
		makeDnsQuery()

	if (currPoisson == len(poissonList)):
		currPoisson = 0



def generatePerlinDNS():
	global base
	global step
	global prev_pval
	
	pval = pnoise1(base, 5)
	if (pval < prev_pval):
		current_burst = 0
		delay = np.random.randint(0,5,1) + np.random.random(1)
		print "Sleeping for ", delay
		time.sleep(delay)
		base = base + 0.01
	else:
		makeDnsQuery()
		time.sleep(abs(pval))
		base = base + 0.01
		
	prev_pval = pval
	

def GET_print(packet1):
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n"
    return ret

def handle_Http_Packets(pkt):
    try:
    	# We have some activity on port 80
    	http_packet = str(pkt)
        if (http_packet.find('GET')):
        	if pkt.sprintf("{Raw:%Raw.load%}") != "":
        		makeDnsQuery()
    except:
    	pass

def handle_Dns_Packets(pkt):
	try:
		if DNSQR in pkt and pkt.dport == 53:
			makeDnsQuery()
	except:
		pass
	
def generatePiggybackHttpDns():
	interface = 'en0'
  	filter_bpf = 'tcp and port 80'
  	print "Starting sniff"
  	sniff(iface=interface, filter=filter_bpf, timeout=30, store=0,  prn=handle_Http_Packets)
  	print "Stoppping sniff"

def generatePiggybackDnsDns():
	interface = 'en0'
  	filter_bpf = 'udp and port 53'
  	print "Starting sniff"
  	sniff(iface=interface, filter=filter_bpf, timeout=30, store=0,  prn=handle_Dns_Packets)
  	print "Stoppping sniff"

def exfiltrate(obsType):
	if (obsType == RANDOM):
		generateRandomDNS()
	elif (obsType == POISSON):
		generatePoissonDNS()
	elif (obsType == PERLIN):
		generatePerlinDNS()
	elif (obsType == PIGGYBACK_HTTP):
		generatePiggybackHttpDns()
	elif (obsType == PIGGYBACK_DNS):
		generatePiggybackDnsDns()


lines = [line.rstrip('\n') for line in open('alexa_100k_names.txt')]


max_time = int(raw_input('Enter the amount of seconds you want to run Data Exfiltration for: '))
start_time = time.time()  # remember when we started
while (time.time() - start_time) < max_time:
    exfiltrate(RANDOM)
