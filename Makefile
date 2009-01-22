all: mquery mhttp

mhttp: mhttp.c mdnsd.c 1035.c sdtxt.c xht.c
	$(CC) -Wall -Wno-pointer-sign -g -o mhttp mhttp.c mdnsd.c 1035.c sdtxt.c xht.c

mquery: mquery.c mdnsd.c 1035.c sdtxt.c xht.c
	$(CC) -Wall -Wno-pointer-sign -g -o mquery mquery.c mdnsd.c 1035.c sdtxt.c xht.c

clean:
	rm -f mquery mhttp
