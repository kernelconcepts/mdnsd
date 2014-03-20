ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = mhttp mquery

mhttp_SOURCES = mhttp.c mdnsd.c rfc1035.c dns_sd_txt.c shash.c
mhttp_CFLAGS = -D_GNU_SOURCE -Wall -Wextra -Wno-pointer-sign -g
mhttp_LDADD = 

mquery_SOURCES = mquery.c mdnsd.c rfc1035.c dns_sd_txt.c shash.c
mquery_CFLAGS = -D_GNU_SOURCE -Wall -Wextra -Wno-pointer-sign -g
mquery_LDADD = 

#EXTRA_DIST = \
#	AUTHORS                 \
#	COPYING                 \
#	README
