
/*
 *	Trasmission Error Detector core functions.
 *
 *	Authors: 
 *	TODO add authors
 *
 *
 *	Fixes:
 *	Matteo Martelli:  Fixed the ipv6 fragment information retrieval
 *	Matteo Martelli:  Refactor and code cleaning
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

/* ted.c */
#include <net/mac80211.h>
#include <net/ieee80211_radiotap.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/wireless.h>
#include <linux/rtnetlink.h>
#include <linux/bitmap.h>
#include <net/net_namespace.h>
#include <net/cfg80211.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/syscalls.h>
#include <linux/time.h>

#include "ieee80211_i.h"
#include "rate.h"
#include "mesh.h"
#include "wep.h"
#include "wme.h"
#include "aes_ccm.h"
#include "led.h"
#include "cfg.h"
#include "debugfs.h"
#include "debugfs_netdev.h"

#define TED_ERROR
#define TED_DEBUG
#define TED_DEBUG_VERBOSE

#ifdef TED_DEBUG_VERBOSE
#define ted_dbgv(fmt, ...) printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#else
#define ted_dbgv(fmt, ...)
#endif

#ifdef TED_DEBUG
#define ted_dbg(fmt, ...) printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#else
#define ted_dbg(fmt, ...)
#endif

#ifdef TED_ERROR
#define ted_err(fmt, ...) printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__) 
#else
#define ted_err(fmt, ...)
#endif

#define WLAN_FC_GET_TYPE(fc) ((fc) & IEEE80211_FCTL_FTYPE)
#define WLAN_FC_GET_STYPE(fc) ((fc) & IEEE80211_FCTL_STYPE)
#define WLAN_GET_SEQ_FRAG(seq) ((seq) & IEEE80211_SCTL_FRAG)

struct ieee80211_hdr_4addr {
	__le16 frame_ctl;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctl;
	u8 addr4[ETH_ALEN];
	u8 payload[0];
} __attribute__ ((packed));


#define FRAG_LAST 0
#define FRAG_NOT_LAST 1

static int ted_info_counter = 0 ;

struct ted_info
{
	__le16 mac_frameid;             /* mac layer (80211) frame id */
	uint32_t transport_pktid;       /* transport layer packet id */

	/* 80211 layer info */
	u8 acked; 
	u8 retry_count; 

	/* network layer fragment info */
	u16 fragment_data_len;
	u16 fragment_offset;
	u8 more_fragment;

	struct timespec tx_time;
	struct timespec rx_time;
	struct ted_info *next;
};


static struct ted_info sentinel = { 0 };
static struct timespec LastCheck_ted_info_list={0,0};

/*
 * print the information saved into the ted_info
*/

/*

 * search into the ted_info list the ted_info with the field id like
 * the param id if it found it, return this ted_info, else return 0

*/

static struct ted_info *ted_info_search(__le16 id)
{
	struct ted_info *aux = &sentinel;
#ifdef TED_DEBUG_VERBOSE
	int debug_counter = 0;
	ted_dbgv("ted: %s: counter %d\n", __FUNCTION__, ted_info_counter);
#endif
	while (aux->next != NULL) {
		if (id == aux->next->mac_frameid) {	
			/* ted_info is found */
			return aux->next;
		}
#ifdef TED_DEBUG_VERBOSE
		debug_counter++;
		if (debug_counter == 100) {
			ted_dbgv("ted: %s: ted_info queue too long\n",
			        __FUNCTION__);
			return 0;
		}
#endif
		aux = aux->next;
	}
	return 0;
}

static void Check_ted_info_list(void)
{
	/* faccio il check ogni 5 secs */
	struct timespec now = CURRENT_TIME;

	if (now.tv_sec > (LastCheck_ted_info_list.tv_sec + 10)) {
		/* elimino i pkt che stanno in lista da troppo tempo */
		struct ted_info *aux = &sentinel;

		ted_dbgv("ted: %s: entered in check block\n", __FUNCTION__);
		
		while (aux->next != NULL) {
			if (now.tv_sec > (aux->next->tx_time.tv_sec + 10)) {
				struct ted_info *temp = aux->next->next;
				kfree(aux->next);
				aux->next = temp;
				ted_info_counter--;
				ted_dbgv("ted: %s: removed one info element\n",
				        __FUNCTION__);
			} else {
				aux = aux->next;
			}
		}

		ted_dbgv("ted: %s: %d info elements remaining\n",
		        __FUNCTION__, ted_info_counter);
		
		LastCheck_ted_info_list = now;
	}
}

/*
 * Add the new element packet_info at the ted_info list
 */
static void ted_info_add(struct ted_info *packet_info)
{
	Check_ted_info_list();

	if (sentinel.next == NULL) { 
		/* empty list */
		sentinel.next = packet_info;
		packet_info->next = NULL;
	} else {
		struct ted_info *aux = &sentinel;
		
		while (aux->next != NULL)
			aux = aux->next;

		aux->next = packet_info;
		packet_info->next = NULL;
	}

	ted_info_counter++;
	ted_dbgv("ted: %s: added element with mac_frameid: %d\n",
	        __FUNCTION__, packet_info->mac_frameid);


	ted_dbgv("ted: %s: %d info elements remaining\n",
	        __FUNCTION__, ted_info_counter);
}

/*
 * Remove the packet_info from the ted_info list
 */
static void ted_info_remove(struct ted_info *packet_info)
{
	struct ted_info *aux = &sentinel;
	while (aux->next != NULL) {
		if (aux->next->mac_frameid == packet_info->mac_frameid) {
			struct ted_info *temp = aux->next->next;
			kfree(aux->next);
			aux->next = temp;
			ted_info_counter--;
			break;
		}
		aux = aux->next;
	}
}


static int __get_frag_info6(struct sk_buff *skb,
                              struct ipv6hdr *ip6hdr,
			      struct ted_info *ted_info)
{
	struct frag_hdr *fh;
	struct frag_hdr _frag;
	unsigned int offset, hdrs_len;
	int target, error;
	u8 nexthdr;
	bool found;

	if(ip6hdr->version != 6) {
		ted_err("ted: %s: no IPv6 header in ipv6_get_udp_info",
			__FUNCTION__);
		return 0;
	}

	/* Variables initialization */
	hdrs_len = error = 0;
	nexthdr = ipv6_hdr(skb)->nexthdr;
	target = NEXTHDR_FRAGMENT;

	/* The offset starts at the beginning of the extended headers */
	offset = skb_network_offset(skb) + sizeof(struct ipv6hdr);

	/* Sanity check lookup (reduced ipv6_find_hdr). 
	 * The fragment hdr should be the first next hdr in a fragmented packet. 
	 * But better we check it. */
	do {
		struct ipv6_opt_hdr _hdr, *hp;
		unsigned int hdrlen;
		found = (nexthdr == target);

		if ((!ipv6_ext_hdr(nexthdr)) || nexthdr == NEXTHDR_NONE) {
			break;
		}

		hp = skb_header_pointer(skb, offset, sizeof(_hdr), &_hdr);
		if (hp == NULL) {
			error = -EBADMSG;
			break;
		}

		if (nexthdr == NEXTHDR_FRAGMENT) {
			hdrlen = 8;
		} else if (nexthdr == NEXTHDR_AUTH) {
			hdrlen = (hp->hdrlen + 2) << 2;
		} else
			hdrlen = ipv6_optlen(hp);

		if (!found) {
			nexthdr = hp->nexthdr;
			offset += hdrlen;
		}

		hdrs_len += hdrlen;
	} while (!found);

	/* Subtract the fragment header size from the ipv6 payload length
	 * as it is located  just before the fragment 
	 * (which is optional remaining ipv6 headers + udp header + msg payload)
	 *  +------------+---------------------+------------+
	 *  |  ipv6 hdr  |  ipv6 fragment hdr  |  fragment  |
	 *  +------------+---------------------+------------+  */
	ted_info->fragment_data_len = ntohs(ip6hdr->payload_len) - hdrs_len;


	if (error) {
		ted_err("ted: %s: error getting fragment hdr with error code %d\n", 
			__FUNCTION__, error);
	} else if (!found) {
		ted_dbgv("ted: %s: non-fragmented notify packet\n", __FUNCTION__);
	} else {
		fh = skb_header_pointer(skb, offset, sizeof(_frag), &_frag);

		if (fh) {
			ted_info->fragment_offset = ntohs(fh->frag_off) & ~0x7;
			ted_info->more_fragment = ((fh->frag_off & htons(IP6_MF)) > 0);
		} else {
			ted_err("ted: %s: failed converting offset to header ptr\n",
			        __FUNCTION__);
		}
	}

	return 1;
}

static int __get_frag_info(struct iphdr *iphdr,
			   int iphdr_len, struct ted_info* ted_info)
{

	if (iphdr_len < sizeof(struct iphdr))
	{
		ted_err("ted: %s: iphdr_len too small\n",
		       __FUNCTION__);
		return(-3);
	}

	/* hearder IP */
	if (iphdr->protocol == IPPROTO_UDP) {
		/*   TCP: 0x06 ; UDP: 0x11 ; ICMP: 0x01   **/
		if (iphdr_len < (4*(iphdr->ihl) + sizeof(struct udphdr))) {
			ted_err("ted: %s: no space for udp hdr\n",
			        __FUNCTION__);
			return(-1);
		}

		ted_dbgv("ted: %s: iphdr->tot_len %d\n", 
		        __FUNCTION__, ntohs(iphdr->tot_len));

		/* the following parameters are used by the client to sort packages */
		/* only data, not header */
		ted_info->fragment_data_len = ntohs(iphdr->tot_len) - (4*(iphdr->ihl));
		ted_dbgv("ted: %s: frag_len %d\n", __FUNCTION__, ted_info->fragment_data_len);

		ted_info->fragment_offset = (ntohs(iphdr->frag_off & htons(IP_OFFSET)))<<3;
		ted_dbgv("ted %s: frag_off %d\n", __FUNCTION__, ted_info->fragment_offset);

		ted_info->more_fragment = (ntohs(iphdr->frag_off & htons(IP_MF)) > 0);
		return(1);
	}
	/* no udp */
	return(0);
}

static int get_frag_info(struct sk_buff *skb, struct ieee80211_hdr_4addr *hdr4,
			 size_t hdrlen, u16 ethertype, struct ted_info *ted_info)
{
	int flen;
	u8 *ipheader;
	
	flen = sizeof(struct udphdr);
	ipheader = ((u8*) hdr4) + hdrlen + 8;

	if (ethertype == ETH_P_IP) {

		flen += sizeof(struct iphdr);

		return __get_frag_info((struct iphdr *)ipheader, flen, ted_info);

	} else if (ethertype == ETH_P_IPV6) {

		flen += sizeof(struct ipv6hdr);

		return __get_frag_info6(skb, (struct ipv6hdr *)ipheader, ted_info);
	}

	return -1;
}

/* Extract some information from the header ieee80211, ip and udp: sequence
 * number frame ieee, id datagram ip, source port udp... and put these in the
 * ted_info list if return 1 all it's ok.
 */

int ted_extract_pkt_info(struct sk_buff *skb, struct ieee80211_hdr *hdr)
{
	struct ted_info *packet_info;
	struct ieee80211_hdr_4addr *hdr4;
	size_t hdrlen;
	u16 fc, stype;
	u8 *header;
	u16 ethertype;
	int ret;

	if (!hdr) {
		ted_err("ted: %s null hdr\n", __FUNCTION__);
		goto info_dropped;
	}

	hdr4 = (struct ieee80211_hdr_4addr *)hdr;
		
	if (!ieee80211_is_data(hdr->frame_control)) {
		ted_dbg("ted: %s: not a data frame\n", __FUNCTION__);
		goto info_dropped;
	}
	
	fc = le16_to_cpu(hdr->frame_control);

	stype = WLAN_FC_GET_STYPE(fc);
	hdrlen = ieee80211_hdrlen(fc);

	stype &= ~IEEE80211_STYPE_QOS_DATA;


	if (stype != IEEE80211_STYPE_DATA && 
	    stype != IEEE80211_STYPE_DATA_CFACK &&
	    stype != IEEE80211_STYPE_DATA_CFPOLL &&
	    stype != IEEE80211_STYPE_DATA_CFACKPOLL)
		goto info_dropped;


	/* Alloc and init ted_info struct */
	packet_info = kmalloc(sizeof(struct ted_info), GFP_ATOMIC);\
	memset(packet_info, 0, sizeof(struct ted_info));
	packet_info->mac_frameid = hdr->seq_ctrl;
	packet_info->transport_pktid = skb->transport_pktid;
	packet_info->tx_time = CURRENT_TIME;

	header = ((u8*) (hdr4)) + hdrlen;
	ethertype = (header[6] << 8) | header[7];

	ret = get_frag_info(skb, hdr4, hdrlen, ethertype, packet_info);
	if (ret > 0) {
		ted_info_add(packet_info);
		goto info_stored;
	}
info_dropped:
	ted_dbg("ted: %s: can't add new 802.11 frame with msg id %d\n",
	        __FUNCTION__, skb->transport_pktid);
	/* TODO: should we free the ted_info structure if kallocated? */
	return 0;

info_stored:
	ted_dbg("ted: %s: added new 802.11 frame with msg id %d\n",
	        __FUNCTION__, skb->transport_pktid);
	return 1;

}

/*
 * Join the information into the hdr with the correct ted_info
 */
int ted_info_response(struct sk_buff *skb, 
                       struct ieee80211_hw *hw,
                       struct ieee80211_hdr *hdr,
                       struct ieee80211_tx_info *info,
		       u8 acked, int retry_count)
{
	struct ted_info *packet_info;

	packet_info = ted_info_search(hdr->seq_ctrl);

	if (packet_info != 0) {
		packet_info->acked = acked;

		/* TODO: check retry count limits */
		packet_info->retry_count = (u8)retry_count;
		
		packet_info->rx_time = CURRENT_TIME;

		ip_local_error_notify(skb->sk,
				      packet_info->transport_pktid,
				      packet_info->fragment_data_len,
				      packet_info->fragment_offset,
				      packet_info->more_fragment,
				      packet_info->acked,
				      packet_info->retry_count);

		ted_info_remove(packet_info);
		return(1);
	}
	ted_err("ted: %s: failed searching a ted info struct in the list\n",	
		  __FUNCTION__);
	return(0);
}
