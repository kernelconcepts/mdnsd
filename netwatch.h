#ifndef __NETWATCH_H__
#define __NETWATCH_H__

typedef void (* NW_IpChangeCallback)   (int    link_index,
                                        char  *label,
                                        char  *ipaddr,
                                        int    add,
                                        void  *user_data);

typedef void (* NW_LinkChangeCallback) (int   link_index,
                                        int   running,
                                        void *user_data);

int   netwatch_open               (void);
int   netwatch_queue_inforequest  (int fd);
int   netwatch_dispatch           (int fd);

void  netwatch_register_callbacks (NW_IpChangeCallback    ip_cb,
                                   NW_LinkChangeCallback  link_cb,
                                   void                  *userdata);

#endif /* __NETWATCH_H__ */
