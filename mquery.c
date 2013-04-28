#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mdnsd.h"
#include "shash.h"
#include "rfc1035.h"
#include "dns_sd_txt.h"

void txt_printer (SHASH UNUSED(hash), const char *key, void *val, void *UNUSED(arg))
{
    printf ("   %s=%s\n", key, (char *) val);
}


// print an answer
int ans(TMdnsdAnswer *answer, void *UNUSED(arg))
{
    int now;
    SHASH hash;
    struct in_addr ip_addr;
    if(answer->ttl == 0) now = 0;
    else now = answer->ttl - time(0);
    switch(answer->type)
    {
        case QTYPE_A:
            ip_addr = answer->ip;
            printf("A %s for %d seconds to ip %s\n",answer->name,now,inet_ntoa(ip_addr));
            break;
        case QTYPE_PTR:
            printf("PTR %s for %d seconds to %s\n",answer->name,now,answer->rdname);
            break;
        case QTYPE_SRV:
            printf("SRV %s for %d seconds to %s:%d\n",answer->name,now,answer->rdname,answer->srv.port);
            break;
        case QTYPE_TXT:
            printf("TXT %s for %d seconds:\n",answer->name,now);
            hash = DnsTxt2Sd (answer->rdata, answer->rdlen);
            SHashForEach(hash, txt_printer, NULL);
            SHashFree (hash);
            break;
        default:
            printf("%d %s for %d seconds with %d data\n",answer->type,answer->name,now,answer->rdlen);
    }

    return 0;
}

// create multicast 224.0.0.251:5353 socket
int msock()
{
    int s, flag = 1, ittl = 255;
    struct sockaddr_in in;
    struct ip_mreq mc;
    char ttl = 255;

    bzero(&in, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(MDNS_PORT);
    in.sin_addr.s_addr = 0;

    if((s = socket(AF_INET,SOCK_DGRAM,0)) < 0) return 0;
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (char*)&flag, sizeof(flag));
#endif
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag));
    if(bind(s,(struct sockaddr*)&in,sizeof(in))) { close(s); return 0; }

    mc.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mc.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mc, sizeof(mc));
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ittl, sizeof(ittl));

    flag =  fcntl(s, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(s, F_SETFL, flag);

    return s;
}

int main(int argc, char *argv[])
{
    TMdnsd *d;
    DNSMESSAGE m;
    struct in_addr ip;
    uint16_t port;
    struct timeval *tv;
    int bsize, ssize = sizeof(struct sockaddr_in);
    uint8_t buf[MAX_PACKET_LEN];
    struct sockaddr_in from, to;
    fd_set fds;
    int s;

    if(argc != 3) { printf("usage: mquery 12 _http._tcp.local.\n"); return -1; }

    d = MdnsdNew(1, 1000);
    if((s = msock()) == 0) { printf("can't create socket: %s\n",strerror(errno)); return 1; }

    MdnsdQuery(d,argv[2],atoi(argv[1]),ans,0);

    while(1)
    {
        tv = MdnsdGetMaxSleepTime(d);
        FD_ZERO(&fds);
        FD_SET(s,&fds);
        select(s+1,&fds,0,0,tv);

        if(FD_ISSET(s,&fds))
        {
            while((bsize = recvfrom(s,buf,MAX_PACKET_LEN,0,(struct sockaddr*)&from,&ssize)) > 0)
            {
                bzero(&m,sizeof(DNSMESSAGE));
                DnsParseMsg(&m,buf);
                MdnsdInput(d, &m, from.sin_addr, from.sin_port);
            }
            if(bsize < 0 && errno != EAGAIN) { printf("can't read from socket %d: %s\n",errno,strerror(errno)); return 1; }
        }

        while(MdnsdOutput(d,&m,&ip,&port))
        {
            bzero(&to, sizeof(to));
            to.sin_family = AF_INET;
            to.sin_port = port;
            to.sin_addr = ip;
            if(sendto(s,DnsMsg2Pkt(&m),DnsMsgLen(&m),0,(struct sockaddr *)&to,sizeof(struct sockaddr_in)) != DnsMsgLen(&m))  { printf("can't write to socket: %s\n",strerror(errno)); return 1; }
        }
    }

    MdnsdShutdown(d);
    MdnsdFree(d);
    return 0;
}

