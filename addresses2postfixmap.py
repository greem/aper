#!/usr/bin/python
# open the phishing reply addresses file, generate a disallowed recipient hash
# from it

import urllib2
import sys
import string
import datetime
import os

# main
address_file_url='http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_reply_addresses' # see http://anti-phishing-email-reply.googlecode.com for more detail
delta=datetime.timedelta(days=30) # how far back do we care?
reject_map_file='/etc/postfix/phishing-disallowed-recipients'
postmap='/usr/sbin/postmap'
addresses=set()
today=datetime.date.today()

# first, make sure we can open the url
try:
        req = urllib2.Request(address_file_url)
        response = urllib2.urlopen(req)
except urllib2.URLError, e:
        print 'failed to open url ', address_file_url
        print 'reason: ', e
        sys.exit()

# ok, try to make a backup file
try:
        backup=reject_map_file + '.bak'
        os.rename(reject_map_file, backup)
except OSError, e:
        print e

# open map file for writing
try:
        mapfile=open(reject_map_file, 'w')
except  IOError, e:
        print e
        sys.exit()

# iterate through the address file and build a postfix map
for line in response:
        if line.startswith('#'):
                continue
        address, code, datestamp = line.split(',')
        year=int(datestamp[0:4])
        month=int(datestamp[4:6])
        day=int(datestamp[6:8])
        date=datetime.date(year, month, day)
        if (date > (today - delta)) :
                       addresses.add(address)

for entry in sorted(addresses):
               mapfile.write(entry + '\t REJECT\n')
mapfile.close()

# call postmap on it
os.system(postmap + ' ' + reject_map_file)

sys.exit()
