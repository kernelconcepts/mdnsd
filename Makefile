all: mhttp mquery

mhttp: mhttp.c mdnsd.c rfc1035.c dns_sd_txt.c shash.c
	$(CC) -D_GNU_SOURCE -Wall -Wextra -Wno-pointer-sign -g -o mhttp mhttp.c mdnsd.c rfc1035.c dns_sd_txt.c shash.c

mquery: mquery.c mdnsd.c rfc1035.c dns_sd_txt.c shash.c
	$(CC) -D_GNU_SOURCE -Wall -Wextra -Wno-pointer-sign -g -o mquery mquery.c mdnsd.c rfc1035.c dns_sd_txt.c shash.c

netwatch: netwatch.c
	$(CC) -D_GNU_SOURCE -Wall -Wextra -DNETWATCH_MAIN -g -o $@ $<

clean:
	rm -f mquery mhttp netwatch
