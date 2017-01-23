import time
from noise import pnoise1
from noise import snoise2
from numpy import interp
import numpy as np
import matplotlib.pyplot as plt
from subprocess import call
from scapy.all import *
#from random import randint

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
#max_burst = 20
#current_burst = 0


domain_rotate = 0 # used in testing to query alexa top 100000


def makeDnsQuery():
	global domain_rotate
	call(["dig", lines[domain_rotate].rstrip()])
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
	#global max_burst
	#global current_burst
	
	pval = pnoise1(base, 5)
	if (pval < prev_pval):
		current_burst = 0
		delay = np.random.randint(0,5,1) + np.random.random(1)
		print "Sleeping for ", delay
		#time.sleep(np.random.randint(1,5))
		time.sleep(delay)
		base = base + 0.01
	else:
		makeDnsQuery()
		time.sleep(abs(pval)) #might remove this
		base = base + 0.01
		#boost = randint(1,10)
		#for i in range(boost):
		#	base = base + (step + 0.3)		
	prev_pval = pval
	#base = base + step	


def handle_Packets(pkt):
    #pkt_time = pkt.sprintf('%sent.time%')
    try:
    	# We have some activity on port 80
        http_packet = str(pkt)
        if (http_packet.find('GET')):
        	for x in range(np.random.randint(1, MAX_BURST)):
        		makeDnsQuery()
    except:
    	pass

def generatePiggybackHttpDns():
	# Write the code to do http piggyback exfil here
	interface = 'en0'
  	filter_bpf = 'tcp port 80' # Look for DNS stuff
  	#print "Starting sniff"
  	sniff(iface=interface, filter=filter_bpf, timeout=30, store=0,  prn=handle_Packets)
  	#print "Stoppping sniff"

def generatePiggybackDnsDns():
	# Write the code to do dns piggyback exfil here
	s = ""

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
    exfiltrate(PIGGYBACK_HTTP)
