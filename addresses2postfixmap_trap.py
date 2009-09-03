#!/usr/bin/python
#************************************************************************ #
# phish_add.py
# 7/9/2008; tmg
# 7/10/2008; tmg
# 7/31/2008; zhs
# 8/5/2008; tmg
# 8/21/2008; tmg
#************************************************************************ #
# 
'''phish_add -- Reads email addresses or files of email addresses and adds
them to the virtual domain file on the TAMU relays, in order to trap replies
to those addresses that pass through the relays.  

Can parse the community file at: 
http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_reply_addresses
'''
import commands
import getopt
import os
import re
import urllib

def output_read(fname):
    wx_l = []
    fd = open(fname, 'r')
    lines = fd.readlines()
    fd.close()

    for line in lines:
        cur_addr = line.strip().split()[0].lower()
        if cur_addr:
            wx_l.append(cur_addr)

    return wx_l

def source_read(fname, verbose):
    wx_l = []
    addr_match = re.compile('^[\w][\w.-]*@[\w.-]+.(\w){2,4}').match

    if fname[:4] == 'http':
        fd = urllib.urlopen(fname)
        lines = fd.read()
        fd.close()
        lines = lines.split('\n')
    else:
        fd = open(fname, 'r')
        lines = fd.readlines()
        fd.close()

    for line in lines:
        if not line or line[0] == '#':
            continue
        new_addr = line.strip().split(',')[0].lower()
        if new_addr and addr_match(new_addr):
            wx_l.append(new_addr)
        elif verbose:
            print "Didn't match **%s**" % (new_addr)

    return wx_l

def regex_write(new_l, output_file, verbose):
    # An address for quarantining suspect senders; Could just as easily "DISCARD"
    #  or "REJECT"
    wx_str = '/(From:|Reply-To:).*%s/    REDIRECT phish-quarantine@ourdomain.edu\n'
    wx_l = []
    if verbose:
        print "Building header_check file"
    for address in new_l:
        wx_l.append(wx_str % (address))
        
    try:
        if verbose:
            print "Writing phisher header_check file"
        fd=open(output_file, 'w')
        for line in wx_l:
            fd.writelines(line)
        fd.close()
        results = True
    except Exception, err:
        print "Couldn't write regex!"
        print err
        results = False
        
    return results

def addr_merge(dest_l, new_l, verbose):
    tmp_l = dest_l[:]
    if verbose:
        print "Merging %i addresses into %i existing addresses" % (len(new_l), len(dest_l))
    for addr in new_l:
        if addr not in tmp_l:
            tmp_l.append(addr)
        elif verbose:
            print "Already listing %s" % (addr)

    tmp_l.sort()

    return tmp_l

def addr_write(f_name, addr_l):
    try:
        tmp_name = f_name + '.prev'
        if os.path.isfile(tmp_name):
            os.remove(tmp_name)
        os.rename(f_name, tmp_name)
        fd = open(f_name, 'w')
    except OSError:
        print "Error! Can't open %s for writing." % (f_name)
        return False

    for elem in addr_l:
        # An address to trap outbound replies
        outline = '%s\tphish-reply-trap@ourdomain.edu\n' % (elem)
        fd.writelines(outline)

    fd.close()

    return True

def main(new_addr, verbose, is_file=False, OUTPUT=None):
    if not OUTPUT:
        OUTPUT = '/etc/postfix/virtual_trap'
    REGEX_OUT = '/etc/postfix/phish_headers.regex'

    cur_addr_l = output_read(OUTPUT)
    len_1 = len(cur_addr_l)

    if is_file:
        if new_addr[:4] == 'http' or os.path.isfile(new_addr):
            new_addr_l = source_read(new_addr,verbose)
        else:
            print "Couldn't find input file %s" % (new_addr)
            os.sys.exit(1)
    else:
        new_addr_l = [ new_addr.split(',')[0] ]

    new_addr_l = addr_merge(cur_addr_l, new_addr_l, verbose)
    len_2 = len(new_addr_l)

    if len_1 == len_2:
        if verbose :
            print "No changes to the address list. Exiting now."
        return 0
    else:
        update = addr_write(OUTPUT, new_addr_l)
        if update:
            status, output = commands.getstatusoutput('/usr/sbin/postmap hash:%s' % (OUTPUT))
            if status != 0:
                print output
            else:
                print "Updated %s" % (OUTPUT)
            #TAMU mail is hosted in a load-balanced cluster. "config_sync.py" sync's 
            # configuration files across the cluster.
            #status, output = commands.getstatusoutput('/usr/local/sbin/config_sync.py %s' % (OUTPUT))
            #if status != 0:
            #    print output
            #else:
            #    print "Synched %s" % (OUTPUT)

            regex_res = regex_write(new_addr_l, REGEX_OUT, verbose)
            if regex_res:
                # TAMU mail is hosted in a load-balanced cluster. "config_sync.py" sync's 
                #  configuration files across the cluster.
                #status, output = commands.getstatusoutput('/usr/local/sbin/config_sync.py %s' % (REGEX_OUT))
                #if status != 0:
                #    print output
                #else:
                #    print "Updated and synched %s" % (REGEX_OUT)
                print "Updated %s" % (REGEX_OUT)
            else:
                print "Failed to update %s" % (REGEX_OUT)
                return 3
            return 0
        else:
            return 2

if __name__ == '__main__':
    usage = '''phish_add.py -f <address_file> | -a <address> [ -o <output_file> ] [ -v ]

    Updates addresses in a virtual maps file, then synch's the new file between
    mail relays.
    Specifiy an address file of 'remote' to fetch the current list from googlecode.'''

    remote_url = 'http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_reply_addresses'

    if len(os.sys.argv) < 2:
        print usage
        os.sys.exit(1)
    else:
        try:
            optlist, args = getopt.getopt(os.sys.argv[1:], 'f:a:o:v', ['file-name', 'address',
                                                                'output-file', 'verbose'])
        except getopt.GetoptError, err:
            print err
            print usage
            os.sys.exit(1)

    output_file = ''
    input_file = ''
    new_addr = ''
    verbose = False

    for flag, value in optlist:
        if flag in ('-f', '--file-name'):
            input_file = value
            if input_file == 'remote':
                input_file = remote_url
        if flag in ('-a', '--address'):
            new_addr = value
        if flag in ('-o', '--output-file'):
            output_file = value
        if flag in ('-v', '--verbose'):
            verbose = True

    if not (new_addr or input_file):
        print usage
        os.sys.exit(1)

    if new_addr and input_file:
        print usage
        os.sys.exit(1)

    if input_file:
        res = main(input_file, verbose, is_file=True, OUTPUT=output_file)
    else:
        res = main(new_addr, verbose, is_file=False, OUTPUT=output_file)

    os.sys.exit(res)
