#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "mdnsd.h"
#include "dns_sd_txt.h"

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#define HOSTNAMESIZE 64

typedef enum {
    MDNSD_PROBE,
    MDNSD_ANNOUNCE,
    MDNSD_RUN,
    MDNSD_SHUTDOWN
} TMdnsdState;

typedef struct _service_info
{
    TMdnsd        *mdnsd;
    char           hostname[HOSTNAMESIZE];
    char          *servicename;

    char          *ip;
    int            port;

    /* service-discovery records */
    TMdnsdRecord  *host_to_ip;
    TMdnsdRecord  *ip_to_host;
    struct in_addr announce_ip;

    SHASH          metadata;

    /* service-discovery records */
    TMdnsdRecord  *srv_to_host;
    TMdnsdRecord  *txt_for_srv;

    TMdnsdRecord  *ptr_to_srv;

    TMdnsdState    state;
} ServiceInfo;

static ServiceInfo service_info;

void     request_service      (ServiceInfo *info, int stage);
void     request_ip_addresses (ServiceInfo *info);

char *increment_name (char *name)
{
    int   id = 1;
    char *pos;
    char *end = NULL;
    char *ret = NULL;

    pos = strrchr (name, '-');

    if (pos) {
        id = strtol (pos + 1, &end, 10);
        if (*end == '\0') {
            *pos = '\0';
        } else {
            id = 1;
        }
    }

    id += 1;

    asprintf (&ret, "%s-%d", name, id);

    return ret;
}


/* conflict handling */
void handle_conflict (TMdnsdRecord *record, char *name, int UNUSED(type), void *arg)
{
    ServiceInfo *info = (ServiceInfo *) arg;
    char *newname;

    if (record == info->ip_to_host) {
        /* can't do anything about a reverse lookup conflict. Just stop
         * announcing it. */
        info->ip_to_host = NULL;
        fprintf (stderr, "zeroconf reverse lookup conflict for %s!\n", info->ip);
        return;
    }

    if (record == info->host_to_ip) {
        info->host_to_ip = NULL;
        info->announce_ip.s_addr = 0;
    }

    if (info->servicename == NULL) {
        newname = increment_name (info->hostname);
    } else {
        newname = increment_name (info->servicename);
        free (info->servicename);
    }

    info->servicename = newname;

    if (record == info->srv_to_host) {
        info->srv_to_host = NULL;
    }

    if (record == info->txt_for_srv) {
        info->txt_for_srv = NULL;
    }

    fprintf (stderr, "conflicting name \"%s\". trying %s\n",
             name, info->servicename);

    /* The hostname was changed, so go back to probe state */
    info->state = MDNSD_PROBE;
}


/* quit and updates */
void sighandler (int sig)
{
    if (sig != SIGHUP) {
        service_info.state = MDNSD_SHUTDOWN;
    }
}


/* create multicast 224.0.0.251:5353 socket */
int msock ()
{
    int    sock_fd;
    int    flag = 1;
    int    ittl = 255;
    char   ttl = 255;
    struct sockaddr_in in;
    struct ip_mreq mc;

    bzero (&in, sizeof (in));
    in.sin_family = AF_INET;
    in.sin_port = htons (MDNS_PORT);
    in.sin_addr.s_addr = 0;

    if ((sock_fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
        return 0;
    }

    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char*) &flag, sizeof (flag));
    if (bind (sock_fd, (struct sockaddr*) &in, sizeof (in))) {
        close(sock_fd);
        return 0;
    }

    mc.imr_multiaddr.s_addr = inet_addr ("224.0.0.251");
    mc.imr_interface.s_addr = htonl (INADDR_ANY);
    setsockopt (sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mc,   sizeof (mc));
    setsockopt (sock_fd, IPPROTO_IP, IP_MULTICAST_TTL,  &ttl,  sizeof (ttl));
    setsockopt (sock_fd, IPPROTO_IP, IP_MULTICAST_TTL,  &ittl, sizeof (ittl));

    flag =  fcntl (sock_fd, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl (sock_fd, F_SETFL, flag);

    return sock_fd;
}

void request_ip_addresses (ServiceInfo *info)
{
    char revlookup[256];
    char hostlocal[256];
    struct in_addr ip;
    int  num_ips = 0;

    sprintf (hostlocal, "%s.local.", info->servicename ? info->servicename : info->hostname);

    if (info->ip) {
        ip.s_addr = inet_addr (info->ip);

        if (ip.s_addr != info->announce_ip.s_addr) {
            snprintf (revlookup, 256, "%d.%d.%d.%d.in-addr.arpa.",
                      (ip.s_addr >> 24) & 0xff, (ip.s_addr >> 16) & 0xff,
                      (ip.s_addr >> 8) & 0xff, (ip.s_addr >> 0) & 0xff);

            if (!info->host_to_ip) {
                info->host_to_ip  = MdnsdAllocUnique(info->mdnsd, hostlocal,
                                                             QTYPE_A, 120, handle_conflict, info);
            }
            MdnsdSetRaw (info->mdnsd, info->host_to_ip, (char *) &ip, 4);

            if (!info->ip_to_host) {
                info->ip_to_host  = MdnsdAllocUnique(info->mdnsd, revlookup,
                                                             QTYPE_PTR, 120, handle_conflict, info);
            }
            MdnsdSetHost (info->mdnsd, info->ip_to_host, hostlocal);

            info->announce_ip = ip;
        }

        num_ips++;
    } else {
        if (info->host_to_ip) {
            MdnsdDone (service_info.mdnsd, info->host_to_ip);
        }
        if (info->ip_to_host) {
            MdnsdDone (service_info.mdnsd, info->ip_to_host);
        }

        info->host_to_ip = NULL;
        info->ip_to_host = NULL;
        info->announce_ip.s_addr = 0;
    }
}

void request_service (ServiceInfo *info, int stage)
{
    uint8_t *packet;
    char     servlocal[256];
    char     hostlocal[256];
    int      len = 0;

    sprintf (servlocal, "%s._http._tcp.local.",
             info->servicename ? info->servicename : info->hostname);

    /*
     * Timeouts according to
     *   http://files.multicastdns.org/draft-cheshire-dnsext-multicastdns.txt
     *
     * As a general rule, the recommended TTL value for Multicast DNS
     * resource records with a host name as the resource record's name
     * (e.g. A, AAAA, HINFO, etc.) or contained within the resource record's
         * rdata (e.g. SRV, reverse mapping PTR record, etc.) is 120 seconds.
             *
     * The recommended TTL value for other Multicast DNS resource records
     * is 75 minutes.
     */

    switch (stage)
    {
        case 0:
            request_ip_addresses (info);

            break;

        case 1:
            sprintf (hostlocal, "%s.local.",
                     info->servicename ? info->servicename : info->hostname);

            if (!info->srv_to_host) {
                info->srv_to_host = MdnsdAllocUnique (info->mdnsd, servlocal,
                                                      QTYPE_SRV, 120, handle_conflict, info);
            }

            MdnsdSetSrv (info->mdnsd, info->srv_to_host, 0, 0, info->port, hostlocal);

            if (!info->txt_for_srv) {
                info->txt_for_srv = MdnsdAllocUnique (info->mdnsd, servlocal,
                                                      QTYPE_TXT, 4500, handle_conflict, info);
            }

            packet = DnsSd2Txt (info->metadata, &len);
            MdnsdSetRaw (info->mdnsd, info->txt_for_srv, packet, len);
            free(packet);
            break;

        case 2:
            if (!info->ptr_to_srv) {
                info->ptr_to_srv  = MdnsdAllocShared (info->mdnsd, "_http._tcp.local.",
                                                  QTYPE_PTR, 4500);
            }
            MdnsdSetHost (info->mdnsd, info->ptr_to_srv, servlocal);

            if (info->ip) {
                fprintf (stderr, "Announcing \"%s.local\" to %s:%d\n",
                         info->servicename ? info->servicename : info->hostname,
                         info->ip, info->port);
            }
            break;

        default:
            fprintf (stderr, "announce stage %d is invalid\n", stage);
            break;
    }
}

int main(int argc, char *argv[])
{
    DNSMESSAGE msg;
    uint16_t   port;
    struct timeval tv;
    int        bsize;
    int        ssize = sizeof(struct sockaddr_in);
    uint8_t    buf[MAX_PACKET_LEN];
    struct sockaddr_in from;
    struct sockaddr_in to;
    int        idx;
    int        s;
    struct in_addr remote_ip;
    char      *value;
    int        polltime = 0;
    int        announce_stage = 0;
    struct pollfd fds[1];

    if(argc < 4)
    {
        fprintf (stderr, "usage: mhttp <ip> <port> <key1>=<value1> <key2>=<value2> ...\n");
        fprintf (stderr, "   <ip>  The IP address to promote\n");
        fprintf (stderr, "   <port> is the port number of the service to be advertized\n");
        fprintf (stderr, "   <key>=<value> are the keys that get embedded into the TXT record.\n");
        return -1;
    }

    service_info.mdnsd = MdnsdNew (1, 1000);

    //gethostname (service_info.hostname, HOSTNAMESIZE);
    sprintf(service_info.hostname, "reinhardt");
    service_info.hostname[HOSTNAMESIZE-1] = '\0';
    if (strchr (service_info.hostname, '.'))
        strchr (service_info.hostname, '.')[0] = '\0';

    service_info.servicename = NULL;

    service_info.ip          = strdup(argv[1]);
    service_info.announce_ip.s_addr = inet_addr(service_info.ip);
    service_info.host_to_ip  = NULL;
    service_info.ip_to_host  = NULL;

    service_info.port = atoi(argv[2]);

    service_info.metadata = SHashInit (11);
    for (idx = 2; idx < argc; idx++) {
        value = index (argv[idx], '=');
        if (value) {
            value[0] = '\0';
            value++;
            SHashSet (service_info.metadata, argv[idx], value);
        }
    }

    service_info.ptr_to_srv     = NULL;
    service_info.srv_to_host    = NULL;
    service_info.txt_for_srv    = NULL;

    signal(SIGHUP,  sighandler);
    signal(SIGINT,  sighandler);
    signal(SIGQUIT, sighandler);
    signal(SIGTERM, sighandler);

    if ((s = msock()) == 0)
    {
        fprintf (stderr, "can't create socket: %s\n", strerror(errno));
        return -1;
    }

    request_ip_addresses (&service_info);

    service_info.state = MDNSD_PROBE;

    while(1) {
        fds[0].fd      = s;
        fds[0].events  = POLLIN;
        fds[0].revents = 0;

        poll (fds, 1, polltime);

        switch (service_info.state)
        {
            case MDNSD_PROBE:

                if (service_info.ptr_to_srv) {
                    MdnsdDone (service_info.mdnsd, service_info.ptr_to_srv);
                }

                if (service_info.srv_to_host) {
                    MdnsdDone (service_info.mdnsd, service_info.srv_to_host);
                }

                if (service_info.txt_for_srv) {
                    MdnsdDone (service_info.mdnsd, service_info.txt_for_srv);
                }

                service_info.ptr_to_srv     = NULL;
                service_info.srv_to_host    = NULL;
                service_info.txt_for_srv    = NULL;

                if (service_info.host_to_ip) {
                    MdnsdDone (service_info.mdnsd, service_info.host_to_ip);
                }

                if (service_info.ip_to_host) {
                    MdnsdDone (service_info.mdnsd, service_info.ip_to_host);
                }

                service_info.host_to_ip  = NULL;
                service_info.ip_to_host  = NULL;
                service_info.announce_ip.s_addr = 0;

                service_info.state = MDNSD_ANNOUNCE;
                announce_stage = 0;
                tv.tv_sec = 0;
                tv.tv_usec = 0;
                break;

            case MDNSD_ANNOUNCE:
                if (announce_stage < 3) {
                    struct timeval cur_tv;
                    long msecs;

                    gettimeofday (&cur_tv, NULL);
                    msecs = (cur_tv.tv_sec - tv.tv_sec) * 1000 + cur_tv.tv_usec / 1000 - tv.tv_usec / 1000;

                    if ((tv.tv_sec == 0) || (msecs > 755)) {
                        request_service (&service_info, announce_stage);
                        announce_stage ++;
                        tv = cur_tv;
                        cur_tv = *MdnsdGetMaxSleepTime (service_info.mdnsd);
                        polltime = cur_tv.tv_sec * 1000 + cur_tv.tv_usec / 1000;
                        if (polltime >= 756) {
                            polltime = 756;
                        }
                    } else {
                        cur_tv = *MdnsdGetMaxSleepTime (service_info.mdnsd);
                        polltime = cur_tv.tv_sec * 1000 + cur_tv.tv_usec / 1000;
                        if (polltime >= 756 - msecs) {
                            polltime = 756 - msecs;
                        }
                    }
                } else {
                    tv = *MdnsdGetMaxSleepTime (service_info.mdnsd);
                    polltime = tv.tv_sec * 1000 + tv.tv_usec / 1000;

                    service_info.state = MDNSD_RUN;
                }
                break;

            case MDNSD_RUN:
                tv = *MdnsdGetMaxSleepTime (service_info.mdnsd);
                polltime = tv.tv_sec * 1000 + tv.tv_usec / 1000;
                break;

            case MDNSD_SHUTDOWN:
                MdnsdShutdown (service_info.mdnsd);
                break;

            default:
                fprintf (stderr, "in default???\n");
                break;
        }

        if (fds[0].revents) {
            while ((bsize = recvfrom (s, buf, MAX_PACKET_LEN, 0, (struct sockaddr*) &from, &ssize)) > 0)
            {
                bzero (&msg, sizeof (DNSMESSAGE));
                DnsParseMsg (&msg, buf);
                MdnsdInput(service_info.mdnsd, &msg,
                           from.sin_addr,
                           from.sin_port);
            }

            if (bsize < 0 && errno != EAGAIN) {
                fprintf (stderr, "can't read from socket: %s\n", strerror (errno));
            }
        }

        while (MdnsdOutput (service_info.mdnsd, &msg, &remote_ip, &port)) {
            bzero (&to, sizeof (to));
            to.sin_family = AF_INET;
            to.sin_port = port;
            to.sin_addr.s_addr = remote_ip.s_addr;

            if (sendto (s, DnsMsg2Pkt (&msg), DnsMsgLen(&msg), 0, (struct sockaddr *) &to, sizeof (struct sockaddr_in)) != DnsMsgLen(&msg)) {
                fprintf (stderr, "can't write to socket: %s\n", strerror(errno));
            }
        }

        if (service_info.state == MDNSD_SHUTDOWN) {
            break;
        }
    }

    MdnsdShutdown (service_info.mdnsd);
    MdnsdFree (service_info.mdnsd);
    return 0;
}

