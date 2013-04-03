#!/usr/bin/python

import re, sys, os, string
from time import strftime

buffer = []
nameBuffer = []
routeBuffer = []
date = ""
buffcheck = 0
CurTime = ""



def searchfile(filename):
   global CurTime
   buffcheck = 0
   file = open(filename, 'r')

   StartPat = re.compile('.*(OpenVPN CLIENT LIST).*')
   EndPat = re.compile('.*(END)\n')
   CurTime = strftime("%a %b %d %H:%M:%S %Y")
   TimePat = re.compile('.*Updated,(.*)\n')

   dirtypid = os.popen('/sbin/pidof openvpn').readlines()
   cleanpid = string.atoi(str(dirtypid[0]).strip('[]').replace('\n', ''))
   os.kill(cleanpid, 12)

   while 1:
      line = file.readline()
      if not line:
         break

      if StartPat.match(line):
	 while 1:
	    nline = file.readline()
	    if not nline:
	       break
	    if EndPat.match(nline):
	       break
	    if TimePat.match(nline):
	       if TimePat.match(nline).group(1) == CurTime: buffcheck = 1
	       #print 'CurTime: ' + CurTime
               #print 'TimePat: ' + TimePat.match(nline).group(1)
	    if buffcheck > 0: buffer.append(nline)
   return buffer

def parsebuffer(buffer):

   datePat = re.compile('.*Updated,(.*)\n')
   comPat = re.compile('.*: (RU.*|UNDEF.*)')
   routingPat = re.compile('.*: (\d+.*)')
   
   for line in buffer:
      if datePat.match(line):
         date = datePat.match(line).group(1).strip()
      if comPat.match(line):
         #print comPat.match(line).group(1).strip()
	 nameBuffer.append(comPat.match(line).group(1).strip())
      if routingPat.match(line):
         #print 'Routing information: '
         #print routingPat.match(line).group(1).strip()
	 routeBuffer.append(routingPat.match(line).group(1).strip())
         
         
def buildDisplay(nameBuffer, routeBuffer):
   sep1 = '-'*100
   sep2 = '.'*100

   formName = '''%(rname)s  %(raddress)s          %(brecv)s      %(bsent)s   %(date)s'''
   formRoute = '''%(vaddress)s  %(rname)s          %(raddress)s    %(lastref)s'''
   print sep1
   print 'OpenVPN Clients Connected'
   print 'Time reported: ' + CurTime
   
   print sep1
   print formName % {'rname':"Name", 'raddress':'IP Address', 'brecv':'Bytes Received', 'bsent':'Bytes Sent', 'date':'Date Connected'}
   print sep1
   for line in nameBuffer:
      (nameIP, counts) = line.split(':', 1)
      (name, IP) = nameIP.split(',')
      (port, received, sent, date) = counts.split(',')
      print formName % {'rname':name, 'raddress':IP, 'brecv':received, 'bsent':sent, 'date':date}
   print sep1
   print sep2
   print sep1
   print 'OpenVPN Current Routes'
   print sep1
   print formRoute % {'vaddress':'Virtual Address', 'rname':'Name', 'raddress':'Remote Address (port)', 'lastref':'Last Update'}
   print sep1
   for line in routeBuffer:
      (vaddress, name, raddress, date) = line.split(',')
      print formRoute % {'vaddress':vaddress, 'rname':name, 'raddress':raddress, 'lastref':date}
	
parsebuffer(searchfile('/var/log/messages'))
buildDisplay(nameBuffer, routeBuffer)
