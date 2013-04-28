all: mhttp mquery netwatch

mhttp: mhttp.c mdnsd.c 1035.c sdtxt.c xht.c
	$(CC) -Wall -Wno-pointer-sign -g -o mhttp mhttp.c mdnsd.c 1035.c sdtxt.c xht.c netwatch.c

mquery: mquery.c mdnsd.c 1035.c
	$(CC) -Wall -Wno-pointer-sign -g -o mquery mquery.c mdnsd.c 1035.c sdtxt.c xht.c

netwatch: netwatch.c
	$(CC) -Wall -DNETWATCH_MAIN -g -o $@ $<

clean:
	rm -f mquery mhttp netwatch
