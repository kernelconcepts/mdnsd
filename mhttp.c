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
#define FIFO_PATH "/tmp/mdns-fifo"

#define MAX_ANNOUNCE_IP 1

enum {
    MDNSD_STARTUP,
    MDNSD_PROBE,
    MDNSD_ANNOUNCE,
    MDNSD_RUN,
    MDNSD_SHUTDOWN
};

typedef struct _ipcam_ip_info
{
    char          *label;
    char          *ip;
    int            link_id;

    /* service-discovery records */
    TMdnsdRecord  *host_to_ip;
    TMdnsdRecord  *ip_to_host;
    struct in_addr announce_ip;
} IpcamIPInfo;

typedef struct _ipcam_service_info
{
    TMdnsd        *mdnsd;
    char           hostname[HOSTNAMESIZE];
    char          *servicename;

    int            port;

    IpcamIPInfo    ipinfos[MAX_ANNOUNCE_IP];

    SHASH          metadata;

    /* service-discovery records */
    TMdnsdRecord  *srv_to_host;
    TMdnsdRecord  *txt_for_srv;

    TMdnsdRecord  *ptr_to_srv;

    int            state;
} IpcamServiceInfo;

static IpcamServiceInfo ipcam_info;
static int signal_pipe[2];
static int fifo_fd;

void     request_service      (IpcamServiceInfo *info, int stage);
void     request_ip_addresses (IpcamServiceInfo *info);

char *
increment_name (char *name)
{
    int   id = 1;
    char *pos, *end = NULL;
    char *ret = NULL;

    pos = strrchr (name, '-');

    if (pos)
    {
        id = strtol (pos + 1, &end, 10);
        if (*end == '\0')
            *pos = '\0';
        else
            id = 1;
    }

    id += 1;

    asprintf (&ret, "%s-%d", name, id);

    return ret;
}


/* conflict handling */
void
handle_conflict (TMdnsdRecord *r, uint8_t *name, int UNUSED(type), void *arg)
{
    IpcamServiceInfo *info = (IpcamServiceInfo *) arg;
    char *newname;
    int i;

    for (i = 0; i < MAX_ANNOUNCE_IP; i++)
    {
        if (r == info->ipinfos[i].ip_to_host)
        {
            /* can't do anything about a reverse lookup conflict. Just stop
             * announcing it. */
            info->ipinfos[i].ip_to_host = NULL;
            fprintf (stderr, "zeroconf reverse lookup conflict for %s!\n", info->ipinfos[i].label);
            return;
        }
        if (r == info->ipinfos[i].host_to_ip)
        {
            info->ipinfos[i].host_to_ip = NULL;
            info->ipinfos[i].announce_ip.s_addr = 0;
        }
    }

    if (info->servicename == NULL)
    {
        newname = increment_name (info->hostname);
    }
    else
    {
        newname = increment_name (info->servicename);
        free (info->servicename);
    }

    info->servicename = newname;

    if (r == info->srv_to_host)
        info->srv_to_host = NULL;
    if (r == info->txt_for_srv)
        info->txt_for_srv = NULL;

    fprintf (stderr, "conflicting name \"%s\". trying %s\n",
             name, info->servicename);

    info->state = MDNSD_PROBE;
    write (signal_pipe[1], " ", 1);
}


/* quit and updates */
void sighandler (int sig)
{
    if (sig != SIGHUP)
    {
        ipcam_info.state = MDNSD_SHUTDOWN;
    }

    write (signal_pipe[1], " ", 1);
}


/* create multicast 224.0.0.251:5353 socket */
int
msock ()
{
    int s, flag = 1, ittl = 255;
    struct sockaddr_in in;
    struct ip_mreq mc;
    char ttl = 255;

    bzero (&in, sizeof (in));
    in.sin_family = AF_INET;
    in.sin_port = htons (MDNS_PORT);
    in.sin_addr.s_addr = 0;

    if ((s = socket (AF_INET,SOCK_DGRAM,0)) < 0)
        return 0;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*) &flag, sizeof (flag));
    if (bind (s, (struct sockaddr*) &in, sizeof (in)))
    {
        close(s);
        return 0;
    }

    mc.imr_multiaddr.s_addr = inet_addr ("224.0.0.251");
    mc.imr_interface.s_addr = htonl (INADDR_ANY);
    setsockopt (s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mc,   sizeof (mc));
    setsockopt (s, IPPROTO_IP, IP_MULTICAST_TTL,  &ttl,  sizeof (ttl));
    setsockopt (s, IPPROTO_IP, IP_MULTICAST_TTL,  &ittl, sizeof (ittl));

    flag =  fcntl (s, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl (s, F_SETFL, flag);

    return s;
}

void
request_ip_addresses (IpcamServiceInfo *info)
{
    char revlookup[256], hostlocal[256];
    int i;
    struct in_addr ip;
    int num_ips = 0;

    sprintf (hostlocal, "%s.local.",
             info->servicename ? info->servicename : info->hostname);

    for (i = 0; i < MAX_ANNOUNCE_IP; i++)
    {
printf("--> ip --> %s\n", info->ipinfos[i].ip);
        if (info->ipinfos[i].ip)
        {
            ip.s_addr = inet_addr (info->ipinfos[i].ip);

            if (ip.s_addr != info->ipinfos[i].announce_ip.s_addr)
            {
                snprintf (revlookup, 256, "%d.%d.%d.%d.in-addr.arpa.",
                          (ip.s_addr >> 24) & 0xff, (ip.s_addr >> 16) & 0xff, (ip.s_addr >> 8) & 0xff, (ip.s_addr >> 0) & 0xff);
                // TODO: OR
                printf("revlookup %d -> %s\n", i, revlookup);
                if (!info->ipinfos[i].host_to_ip)
                {
                    info->ipinfos[i].host_to_ip  = MdnsdAllocUnique (info->mdnsd, hostlocal,
                                                                 QTYPE_A, 120, handle_conflict, info);
                }
                MdnsdSetRaw (info->mdnsd, info->ipinfos[i].host_to_ip, (uint8_t *) &ip, 4);

                if (!info->ipinfos[i].ip_to_host)
                {
                    info->ipinfos[i].ip_to_host  = MdnsdAllocUnique (info->mdnsd, revlookup,
                                                                 QTYPE_PTR, 120, handle_conflict, info);
                }
                MdnsdSetHost (info->mdnsd, info->ipinfos[i].ip_to_host, hostlocal);

                info->ipinfos[i].announce_ip = ip;
            }

            num_ips++;
        }
        else
        {
            if (info->ipinfos[i].host_to_ip)
                MdnsdDone (ipcam_info.mdnsd, info->ipinfos[i].host_to_ip);
            if (info->ipinfos[i].ip_to_host)
                MdnsdDone (ipcam_info.mdnsd, info->ipinfos[i].ip_to_host);

            info->ipinfos[i].host_to_ip = NULL;
            info->ipinfos[i].ip_to_host = NULL;
            info->ipinfos[i].announce_ip.s_addr = 0;
        }
    }

    if (!num_ips) {
        printf("----> Set state startup\n");
        info->state = MDNSD_STARTUP;
    }
}

void
request_service (IpcamServiceInfo *info, int stage)
{
    uint8_t *packet, servlocal[256], hostlocal[256];
    int i, len = 0;

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
            printf("---> request_service\n");
            request_ip_addresses (info);

            break;

        case 1:
            sprintf (hostlocal, "%s.local.",
                     info->servicename ? info->servicename : info->hostname);

            if (!info->srv_to_host)
        {
            info->srv_to_host = MdnsdAllocUnique (info->mdnsd, servlocal,
                                              QTYPE_SRV, 120, handle_conflict, info);
        }
            MdnsdSetSrv (info->mdnsd, info->srv_to_host, 0, 0,
                           info->port, hostlocal);

            if (!info->txt_for_srv)
        {
            info->txt_for_srv = MdnsdAllocUnique (info->mdnsd, servlocal,
                                              QTYPE_TXT, 4500, handle_conflict, info);
        }
            packet = DnsSd2Txt (info->metadata, &len);
            MdnsdSetRaw (info->mdnsd, info->txt_for_srv, packet, len);
            free(packet);
            break;

        case 2:
            if (!info->ptr_to_srv)
        {
            info->ptr_to_srv  = MdnsdAllocShared (info->mdnsd, "_http._tcp.local.",
                                              QTYPE_PTR, 4500);
        }
            MdnsdSetHost (info->mdnsd, info->ptr_to_srv, servlocal);

            for (i = 0; i < MAX_ANNOUNCE_IP; i++)
        {
            if (info->ipinfos[i].ip)
                fprintf (stderr, "Announcing \"%s.local\" to %s:%d\n",
                         info->servicename ? info->servicename : info->hostname,
                         info->ipinfos[i].ip, info->port);
        }
            break;

        default:
            fprintf (stderr, "announce stage %d is invalid\n", stage);
            break;
    }
}

void
update_port_info (IpcamServiceInfo *info, int port)
{
    uint8_t hostlocal[256];

    if (port == info->port)
        return;

    info->port = port;

    if (!info->srv_to_host)
        return;

    sprintf (hostlocal, "%s.local.",
             info->servicename ? info->servicename : info->hostname);

    fprintf (stderr, "mhttp: updating port info to port %d\n", info->port);
    MdnsdSetSrv (info->mdnsd, info->srv_to_host, 0, 0,
                   info->port, hostlocal);
}

#if 0
void
iface_change_callback (int   link_index,
                       char *label,
                       char *ipaddr,
                       int   add,
                       void *user_data)
{
    IpcamServiceInfo *info = (IpcamServiceInfo *) user_data;
    int i;

    for (i = 0; i < MAX_ANNOUNCE_IP; i++)
    {
        if (strcmp (info->ipinfos[i].label, label) != 0)
            continue;

        if (add && (!info->ipinfos[i].ip ||
                    strcmp (info->ipinfos[i].ip, ipaddr) != 0 ||
                    info->ipinfos[i].link_id != link_index))
        {
            if (info->ipinfos[i].ip)
                free (info->ipinfos[i].ip);
            info->ipinfos[i].ip = strdup (ipaddr);
            info->ipinfos[i].link_id = link_index;
            fprintf (stderr, "new ip address on %s: %s\n", label, ipaddr);
        }

        if (!add && info->ipinfos[i].ip)
        {
            fprintf (stderr, "lost ip address on %s\n", label);
            free (info->ipinfos[i].ip);
            info->ipinfos[i].ip = NULL;
            info->ipinfos[i].link_id = -1;
        }
    }

    if (add && info->state == MDNSD_STARTUP)
    {
        info->state = MDNSD_PROBE;
    }
    else
    {
        printf("---> iface_change_callback\n");
        request_ip_addresses (info);
    }

    write (signal_pipe[1], " ", 1);
}


void
iface_link_callback (int   link_index,
                     int   running,
                     void *user_data)
{
    IpcamServiceInfo *info = (IpcamServiceInfo *) user_data;
    int i;
    int link_changed = 0;

    for (i = 0; i < MAX_ANNOUNCE_IP; i++)
        if (link_index == info->ipinfos[i].link_id)
        link_changed = 1;

    if (!link_changed)
        return;

    info->state = running ? MDNSD_PROBE : MDNSD_STARTUP;
    write (signal_pipe[1], " ", 1);
}
#endif

int main(int argc, char *argv[])
{
    DNSMESSAGE msg;
    uint16_t port;
    struct timeval tv;
    int bsize, ssize = sizeof(struct sockaddr_in);
    uint8_t buf[MAX_PACKET_LEN];
    struct sockaddr_in from, to;
    int i, s;
//  int nlink;
    struct in_addr remote_ip;
    char *value;
    int polltime = 0;
    int announce_stage = 0;
    struct pollfd fds[4];

    if(argc < 4)
    {
        fprintf (stderr, "usage: mhttp <label> <ip> <port> <key1>=<value1> <key2>=<value2> ...\n");
        fprintf (stderr, "   <label1> are the labels of the network interface to be watched\n");
        fprintf (stderr, "   <port> is the port number of the service to be advertized\n");
        fprintf (stderr, "   <key>=<value> are the keys that get embedded into the TXT record.\n");
        fprintf (stderr, "\n   The port later can be changed by writing \"port:8080\" to " FIFO_PATH ".\n");
        return -1;
    }

    ipcam_info.mdnsd = MdnsdNew (1, 1000);

    ipcam_info.state = MDNSD_STARTUP;
    // TODO: OR
    //  gethostname (ipcam_info.hostname, HOSTNAMESIZE);
    strcpy(ipcam_info.hostname, "reinhardt");
    ipcam_info.hostname[HOSTNAMESIZE-1] = '\0';
    if (strchr (ipcam_info.hostname, '.'))
        strchr (ipcam_info.hostname, '.')[0] = '\0';

    ipcam_info.servicename = NULL;

    for (i = 0; i < MAX_ANNOUNCE_IP; i++)
    {
        ipcam_info.ipinfos[i].label       = strdup("ethx");
        ipcam_info.ipinfos[i].label[3] = '0' + i;

        ipcam_info.ipinfos[i].ip          = strdup(argv[i+1]);
        ipcam_info.ipinfos[i].link_id     = -1;
        ipcam_info.ipinfos[i].announce_ip.s_addr = inet_addr(ipcam_info.ipinfos[i].ip);
        ipcam_info.ipinfos[i].host_to_ip  = NULL;
        ipcam_info.ipinfos[i].ip_to_host  = NULL;
    }

    ipcam_info.port = atoi(argv[1 + MAX_ANNOUNCE_IP]);

    ipcam_info.metadata = SHashInit (11);
    for (i = 2 + MAX_ANNOUNCE_IP; i < argc; i++)
    {
        value = index (argv[i], '=');
        if (value)
        {
            value[0] = '\0';
            value++;
            SHashSet (ipcam_info.metadata, argv[i], value);
        }
    }

    ipcam_info.ptr_to_srv     = NULL;
    ipcam_info.srv_to_host    = NULL;
    ipcam_info.txt_for_srv    = NULL;

    pipe (signal_pipe);
    signal(SIGHUP,  sighandler);
    signal(SIGINT,  sighandler);
    signal(SIGQUIT, sighandler);
    signal(SIGTERM, sighandler);

    if ((s = msock()) == 0)
    {
        fprintf (stderr, "can't create socket: %s\n", strerror(errno));
        return -1;
    }

#if 0
    if ((nlink = netwatch_open ()) < 0)
    {
         fprintf (stderr, "can't connect to netlink: %s\n", strerror(errno));
         return -1;
    }

    netwatch_register_callbacks (iface_change_callback,
                                 iface_link_callback,
                                 &ipcam_info);
    netwatch_queue_inforequest (nlink);
#endif

    // TODO: OR Set startup state
    ipcam_info.state = MDNSD_STARTUP;


    if (mkfifo (FIFO_PATH, S_IRWXU) < 0)
    {
        if (errno != EEXIST)
        {
            fprintf (stderr, "can't create named pipe: %s\n", strerror(errno));
            return -1;
        }
    }

    if ((fifo_fd = open (FIFO_PATH, O_RDONLY | O_NONBLOCK)) < 0)
    {
        fprintf (stderr, "can't open named pipe: %s\n", strerror(errno));
        return -1;
    }

    /* we need to open the fifo for writing as well (although we'll never
                                                     * use it for this) to avoid POLLHUP to happen when no client wants
        * something from us. Ugh. */

    if ((i = open (FIFO_PATH, O_WRONLY)) < 0)
    {
        fprintf (stderr, "can't dummy-open write end of pipe: %s\n",
                 strerror(errno));
        return -1;
    }


// TODO: OR
    request_ip_addresses (&ipcam_info);
    write (signal_pipe[1], " ", 1);
ipcam_info.state = MDNSD_PROBE;
//
    while(1)
    {
        fds[0].fd      = signal_pipe[0];
        fds[0].events  = POLLIN;
        fds[0].revents = 0;

        fds[1].fd      = s;
        fds[1].events  = POLLIN;
        fds[1].revents = 0;

        fds[2].fd      = fifo_fd;
        fds[2].events  = POLLIN;
        fds[2].revents = 0;
/*
        fds[3].fd      = nlink;
        fds[3].events  = POLLIN;
        fds[3].revents = 0;
*/
        poll (fds, 4, polltime);

        /* only used when we wake-up from a signal */
        if (fds[0].revents)
        {
            char hostname[HOSTNAMESIZE];

            read (signal_pipe[0], buf, MAX_PACKET_LEN);

            //TODO: OR
            //          gethostname (hostname, HOSTNAMESIZE);
            strcpy(hostname, "reinhardt");
            hostname[HOSTNAMESIZE-1] = '\0';
            if (strchr (hostname, '.'))
                strchr (hostname, '.')[0] = '\0';
            if (strcmp (hostname, ipcam_info.hostname))
            {
                /* hostname changed */
                strcpy (ipcam_info.hostname, hostname);
                free (ipcam_info.servicename);
                ipcam_info.servicename = NULL;

                ipcam_info.state = MDNSD_PROBE;
            }
        }

        if (fds[2].revents)
        {
            char message[1024];
            int ret;

            ret = read (fifo_fd, message, 1023);

            if (ret > 0)
            {
                message[ret] = '\0';

                if (!strncmp ("port:", message, 5))
                {
                    int port = atoi (message + 5);
                    if (port > 0 && port < 65536)
                        update_port_info (&ipcam_info, port);
                }
                else
                {
                    fprintf (stderr, "mdnsd: got unknown fifo message: %s", message);
                }
            }
            else if (ret < 0)
            {
                fprintf (stderr, "mdnsd: can't read from pipe: %s\n", strerror (errno));
            }
        }
/*
        if (fds[3].revents)
        {
            netwatch_dispatch (nlink);
        }
*/
        // TODO: OR
        printf("---> ipcam_info.state = %d\n", ipcam_info.state);
        switch (ipcam_info.state)
        {
            case MDNSD_STARTUP:
printf("--->Startup\n");
                /* we're waiting for a netwatch based statechange */
                /* fprintf (stderr, "in STARTUP\n"); */
                polltime = 5000;
                break;

            case MDNSD_PROBE:
printf("--->Probe\n");
                /* fprintf (stderr, "in PROBE\n"); */
                if (ipcam_info.ptr_to_srv)
                    MdnsdDone (ipcam_info.mdnsd, ipcam_info.ptr_to_srv);
                if (ipcam_info.srv_to_host)
                    MdnsdDone (ipcam_info.mdnsd, ipcam_info.srv_to_host);
                if (ipcam_info.txt_for_srv)
                    MdnsdDone (ipcam_info.mdnsd, ipcam_info.txt_for_srv);

                ipcam_info.ptr_to_srv     = NULL;
                ipcam_info.srv_to_host    = NULL;
                ipcam_info.txt_for_srv    = NULL;

                for (i = 0; i < MAX_ANNOUNCE_IP; i++)
                {
                    if (ipcam_info.ipinfos[i].host_to_ip)
                        MdnsdDone (ipcam_info.mdnsd, ipcam_info.ipinfos[i].host_to_ip);
                    if (ipcam_info.ipinfos[i].ip_to_host)
                        MdnsdDone (ipcam_info.mdnsd, ipcam_info.ipinfos[i].ip_to_host);
                    ipcam_info.ipinfos[i].host_to_ip  = NULL;
                    ipcam_info.ipinfos[i].ip_to_host  = NULL;
                    ipcam_info.ipinfos[i].announce_ip.s_addr = 0;
                }

                ipcam_info.state = MDNSD_ANNOUNCE;
                announce_stage = 0;
                tv.tv_sec = 0;
                tv.tv_usec = 0;
                break;

            case MDNSD_ANNOUNCE:
printf("--->Announce\n");
                /* fprintf (stderr, "in ANNOUNCE\n"); */
                if (announce_stage < 3)
                {
                    struct timeval cur_tv;
                    long msecs;
                    gettimeofday (&cur_tv, NULL);
                    msecs = (cur_tv.tv_sec - tv.tv_sec) * 1000 + cur_tv.tv_usec / 1000 - tv.tv_usec / 1000;

                    if (tv.tv_sec == 0 || msecs > 755)
                    {
                        request_service (&ipcam_info, announce_stage);
                        announce_stage ++;
                        tv = cur_tv;
                        cur_tv = *MdnsdGetMaxSleepTime (ipcam_info.mdnsd);
                        polltime = cur_tv.tv_sec * 1000 + cur_tv.tv_usec / 1000;
                        if (polltime >= 756)
                            polltime = 756;
                    }
                    else
                    {
                        cur_tv = *MdnsdGetMaxSleepTime (ipcam_info.mdnsd);
                        polltime = cur_tv.tv_sec * 1000 + cur_tv.tv_usec / 1000;
                        if (polltime >= 756 - msecs)
                            polltime = 756 - msecs;
                    }
                }
                    else
                {
                    tv = *MdnsdGetMaxSleepTime (ipcam_info.mdnsd);
                    polltime = tv.tv_sec * 1000 + tv.tv_usec / 1000;

                    ipcam_info.state = MDNSD_RUN;
                }
                break;

            case MDNSD_RUN:
printf("--->Run\n");
                tv = *MdnsdGetMaxSleepTime (ipcam_info.mdnsd);
                polltime = tv.tv_sec * 1000 + tv.tv_usec / 1000;
                break;

            case MDNSD_SHUTDOWN:
printf("--->Shutdown\n");
                MdnsdShutdown (ipcam_info.mdnsd);
                break;

            default:
                fprintf (stderr, "in default???\n");
                break;
        }

        if (fds[1].revents)
        {
            while ((bsize = recvfrom (s, buf, MAX_PACKET_LEN, 0,
                                      (struct sockaddr*) &from, &ssize)) > 0)
            {
                bzero (&msg, sizeof (DNSMESSAGE));
                DnsParseMsg (&msg, buf);
                MdnsdInput(ipcam_info.mdnsd, &msg,
                          from.sin_addr,
                          from.sin_port);
            }
            if (bsize < 0 && errno != EAGAIN)
            {
                fprintf (stderr, "can't read from socket: %s\n", strerror (errno));
            }
        }

        while (MdnsdOutput (ipcam_info.mdnsd, &msg, &remote_ip, &port))
        {
            bzero (&to, sizeof (to));
            to.sin_family = AF_INET;
            to.sin_port = port;
            to.sin_addr.s_addr = remote_ip.s_addr;
            if (sendto (s, DnsMsg2Pkt (&msg), DnsMsgLen(&msg),
                        0, (struct sockaddr *) &to,
                        sizeof (struct sockaddr_in)) != DnsMsgLen(&msg))
            {
                fprintf (stderr, "can't write to socket: %s\n", strerror(errno));
            }
        }

        if (ipcam_info.state == MDNSD_SHUTDOWN)
            break;
    }

    MdnsdShutdown (ipcam_info.mdnsd);
    MdnsdFree (ipcam_info.mdnsd);
    return 0;
}

