#ifndef _LINUX_ERRQUEUE_H
#define _LINUX_ERRQUEUE_H 1

#include <linux/types.h>

struct sock_extended_err {
	__u32	ee_errno;	
	__u8	ee_origin;
	__u8	ee_type;
	__u8	ee_code;
	__u8	ee_pad;
	__u32   ee_info;
	__u32   ee_data;

	__u8    ee_retry_count; /* ABPS */
};

#define SO_EE_ORIGIN_NONE	0
#define SO_EE_ORIGIN_LOCAL	1
#define SO_EE_ORIGIN_ICMP	2
#define SO_EE_ORIGIN_ICMP6	3
#define SO_EE_ORIGIN_TXSTATUS	4
#define SO_EE_ORIGIN_LOCAL_NOTIFY 5 /* ABPS */

#define SO_EE_ORIGIN_TIMESTAMPING SO_EE_ORIGIN_TXSTATUS

#define SO_EE_OFFENDER(ee)	((struct sockaddr*)((ee)+1))

/* ABPS */
/* TED convenient wrapper APIs for First-hop Transmission Notification. */

/* TED identifier of the datagram whose notification refers to. */
#define ted_msg_id(notification) \
			((struct sock_extended_err *) notification)->ee_info

/* Message status to the first hop.
   Return 1 if the message was successfully delivered to the AP, 0 otherwise. */
#define ted_status(notification) \
			((struct sock_extended_err *) notification)->ee_type

/* Returns the number of times that the packet, 
   associated to the notification provided, was retrasmitted to the AP.  */
#define ted_retry_count(notification) \
			((struct sock_extended_err *) notification)->ee_retry_count

/* Returns the fragment length */
#define ted_fragment_length(notification) \
			(((struct sock_extended_err *) notification)->ee_data >> 16)

/* Returns the offset of the current message 
   associated with the notification from the original message. */
#define ted_fragment_offset(notification) \
			((((struct sock_extended_err *) notification)->ee_data << 16) >> 16)

/* Indicates if there is more fragment with the same TED identifier */
#define ted_more_fragment(notification) \
			((struct sock_extended_err *) notification)->ee_code
/* end ABPS */

#ifdef __KERNEL__

#include <net/ip.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/ipv6.h>
#endif

#define SKB_EXT_ERR(skb) ((struct sock_exterr_skb *) ((skb)->cb))

struct sock_exterr_skb {
	union {
		struct inet_skb_parm	h4;
#if IS_ENABLED(CONFIG_IPV6)
		struct inet6_skb_parm	h6;
#endif
	} header;
	struct sock_extended_err	ee;
	u16				addr_offset;
	__be16				port;
};

#endif

#endif
