#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>

#include "netwatch.h"

#define NL_BUFSIZE 8192


/* yeah, these callbacks really shouldn't be global */

static void *user_data = NULL;
static NW_IpChangeCallback   on_ip_change   = NULL;
static NW_LinkChangeCallback on_link_change = NULL;

static void   netwatch_handle_ifaddrmsg (struct nlmsghdr *nl_msg);
static void   netwatch_handle_ifinfomsg (struct nlmsghdr *nl_msg);


int
netwatch_open (void)
{
  int fd;
  struct sockaddr_nl  local;

  /* Create Socket */
  if ((fd = socket (PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    return -1;

  memset (&local, 0, sizeof (local));
  local.nl_family = AF_NETLINK;
  local.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

  if (bind (fd, (struct sockaddr*) &local, sizeof (local)) < 0)
    return -1;

  if (fcntl (fd, F_SETFL, O_NONBLOCK))
    return -1;

  return fd;
}

int
netwatch_queue_inforequest (int fd)
{
  char buf[NLMSG_LENGTH (sizeof (struct ifaddrmsg))];
  struct nlmsghdr    *nl_msg;

  bzero (buf, sizeof(buf));
  nl_msg = (struct nlmsghdr *) buf;

  /* For getting interface addresses */
  nl_msg->nlmsg_len   = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
  nl_msg->nlmsg_type  = RTM_GETADDR;
  nl_msg->nlmsg_flags = NLM_F_ROOT | NLM_F_REQUEST;
  nl_msg->nlmsg_pid   = getpid ();

  return write (fd, nl_msg, nl_msg->nlmsg_len);
}


int
netwatch_dispatch (int fd)
{
  struct nlmsghdr    *nl_msg;
  char buf[NL_BUFSIZE];
  int len, count;

  count = 0;
  if ((len = recv (fd, buf, NL_BUFSIZE, 0)) < 0)
    {
      return (errno == EAGAIN) ? 0 : -1;
    }

  for (nl_msg = (struct nlmsghdr *) buf;
       NLMSG_OK (nl_msg, len);
       nl_msg = NLMSG_NEXT (nl_msg, len))
    {
      switch (nl_msg->nlmsg_type)
        {
          case RTM_NEWADDR:
          case RTM_DELADDR:
            netwatch_handle_ifaddrmsg (nl_msg);
            break;
          case RTM_NEWLINK:
          case RTM_DELLINK:
            netwatch_handle_ifinfomsg (nl_msg);
            break;
          case NLMSG_DONE:
            break;
          default:
            fprintf (stderr, "unhandled message (%d)\n",
                     nl_msg->nlmsg_type);
            break;
        }

      count++;
    }
  return count;
}


void
netwatch_register_callbacks (NW_IpChangeCallback    ip_cb,
                             NW_LinkChangeCallback  link_cb,
                             void                  *userdata)
{
  user_data = userdata;
  on_ip_change = ip_cb;
  on_link_change = link_cb;
}


static void
netwatch_handle_ifaddrmsg (struct nlmsghdr *nl_msg)
{
  struct ifaddrmsg *if_msg;
  struct rtattr    *attrib;
  int len;

  char  address[100];
  char *label = NULL;

  if_msg = (struct ifaddrmsg *) NLMSG_DATA (nl_msg);

  if (if_msg->ifa_family != AF_INET)
    return;

  address[0] = '\0';

  len = IFA_PAYLOAD (nl_msg);
  for (attrib = IFA_RTA (if_msg);
       RTA_OK (attrib, len);
       attrib = RTA_NEXT (attrib, len))
    {
      switch (attrib->rta_type)
        {
          case IFA_LOCAL:
            inet_ntop (AF_INET, RTA_DATA (attrib), address, sizeof (address));
            break;

          case IFA_LABEL:
            label = (char *) RTA_DATA (attrib);
            break;

          default:
            /* ignore all other attributes */
            break;
        }
    }

  /* if we got both a label and an IP address */
  if (on_ip_change && label && address[0] &&
      (nl_msg->nlmsg_type == RTM_NEWADDR || nl_msg->nlmsg_type == RTM_DELADDR))
    {
      on_ip_change (if_msg->ifa_index, label, address,
                    nl_msg->nlmsg_type == RTM_NEWADDR, user_data);
    }

  return;
}


static void
netwatch_handle_ifinfomsg (struct nlmsghdr *nl_msg)
{
  static unsigned long have_state = 0;
  static unsigned long linkstate = 0;
  struct ifinfomsg *ifi;

  ifi = (struct ifinfomsg *) NLMSG_DATA (nl_msg);

  if (on_link_change && ifi->ifi_index < sizeof (unsigned long) * 8)
    {
      if (!((1 << ifi->ifi_index) & have_state) ||
          ((ifi->ifi_flags & IFF_RUNNING) && !((1 << ifi->ifi_index) & linkstate)) ||
          (!(ifi->ifi_flags & IFF_RUNNING) && ((1 << ifi->ifi_index) & linkstate)))
        {
          have_state |= (1 << ifi->ifi_index);
          if (ifi->ifi_flags & IFF_RUNNING)
            linkstate |= (1 << ifi->ifi_index);
          else
            linkstate &= ~(1 << ifi->ifi_index);

          on_link_change (ifi->ifi_index,
                          ifi->ifi_flags & IFF_RUNNING ? 1 : 0,
                          user_data);
        }
    }
}



#ifdef NETWATCH_MAIN
void
print_ip_change (int    link_index,
                 char  *label,
                 char  *ipaddr,
                 int    add,
                 void  *user_data)
{
  fprintf (stdout, "Link No. %d %s address %s (label %s)\n",
           link_index, add ? "got" : "lost", ipaddr, label);
}


void print_link_change (int   link_index,
                        int   running,
                        void *user_data)
{
  fprintf (stdout, "Link No. %d is %sconnected\n",
           link_index, running ? "" : "no longer ");
}


int
main (int argc, char *argv[])
{
  struct pollfd       pollfd;
  int fd;

  netwatch_register_callbacks (print_ip_change, print_link_change, NULL);

  fd = netwatch_open ();
  if (fd < 0)
    {
      perror ("Error opening netlink socket");
      exit (1);
    }

  netwatch_queue_inforequest (fd);

  while (1)
    {
      pollfd.fd = fd;
      pollfd.events = POLLIN;
      pollfd.revents = 0;

      if (poll (&pollfd, 1, 20000))
        netwatch_dispatch (fd);
    }

  close (fd);
  return 0;
}
#endif
