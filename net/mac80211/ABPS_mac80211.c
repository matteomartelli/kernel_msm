
/*
 *	Trasmission Error Detector core functions.
 *
 *	Authors: 
 *	TODO add authors
 *
 *
 *	Fixes:
 *	Matteo Martelli:  Fixed the ipv6 fragment information retrieval 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

/* ABPS_ieee80211.c */

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
/* ABPS VIC */
#include <net/ip.h>

#include <net/ipv6.h>

#include <linux/syscalls.h>
/* per do_gettimeofday */
#include <linux/time.h>
/* fine ABPS VIC */

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


/* ABPS VIC */
#ifndef ABPS_DEBUG
#define ABPS_DEBUG
#endif

#ifdef ABPS_DEBUG
static unsigned long int DIFFMSEC(long DOPOSEC, long DOPONANOSEC, long PRIMASEC, long PRIMANANOSEC) {
	long long int primamsec,dopomsec,diffmsec;
	dopomsec=(((long long int)DOPOSEC)*1000L)+(((long long int)DOPONANOSEC)/1000L);
	primamsec=(((long long int)PRIMASEC)*1000L)+(((long long int)PRIMANANOSEC)/1000L);
	diffmsec=dopomsec-primamsec;
	return(  (unsigned long int)diffmsec );
}
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


/* forse da mettere in un header a parte */
struct packet {
	u8 acked; /* acked, not acked, no ack requested or ack filtered */
	u8 retry_count; /* retry counter */
	unsigned long filtered_count;
	/* number of times the frame has been filtered */
	u16 fragment_data_len; /* only data, not header */
	u16 fragment_offset;
	u8 more_fragment; /* 0 if the last fragment, 1 otherwise */
	uint32_t ip_id; /* ip packet id */
	__be16 udp_sport; /* source udp port */
};
#define ACK 0
#define ACK_NOT 1
#define ACK_NOT_REQ 2
#define ACK_FILTERED 3
#define ACK_ERROR 5

#define FRAG_LAST 0
#define FRAG_NOT_LAST 1
/* fine forse da mettere in un header a parte */

/* TODO: refactor everything as the following struct seems now useless.
 *       To do so put the fragment integers inside the ABPS_info struct,
 *       delete all the remaining IPdgramInfo stuff as the skb is used instead.
 */
typedef struct
{
	/* the first 5 parameters follow the order of the network */
	__be16 ipdgramid;
	__be32 saddr;
	__be16 sport;
	__be32 daddr;
	__be16 dport;
	/* the following parameters are used to the client to sort packages */
	u16 fragment_data_len; /* only data, not header */
	u16 fragment_offset;
	u8 more_fragment;
} IPdgramInfo;



static int ABPS_info_counter = 0 ;


struct ABPS_info
{
	__le16 id; /* sequence id frame 802.11 */
	struct packet datagram_info ;
	struct timespec tx_time;
	struct timespec rx_time;
	struct ABPS_info *next;
	int is_ipv6;
};


/* WAT the heck is that ?! */

static struct ABPS_info sentinel = { 0, { 0, 0, 0, 0, 0, 0 }, { 0, 0 }, { 0, 0 }, NULL };
static struct timespec LastCheck_ABPS_info_list={0,0};

/*
 * print the information saved into the ABPS_info
*/

/*

 * search into the ABPS_info list the ABPS_info with the field id like
 * the param id if it found it, return this ABPS_info, else return 0

*/

static struct ABPS_info *ABPS_info_search(__le16 id)
{
	struct ABPS_info *aux = &sentinel;
#ifdef ABPS_DEBUG
	int debug_counter = 0;
	printk(KERN_DEBUG "*** ABPS *** COUNTER %d \n", ABPS_info_counter);
#endif
	while (aux->next != NULL) {
		if (id == aux->next->id) {	
			/* ABPS_info is found */
			return aux->next;
		}
#ifdef ABPS_DEBUG
		debug_counter++;
		if (debug_counter == 100) {
			printk(KERN_ERR "*** ABPS *** ABPS_info queue too long\n");
			return 0;
		}
#endif
		aux = aux->next;
	}
	return 0;
}

static void Check_ABPS_info_list(void)
{
	/* faccio il check ogni 5 secs */
	struct timespec now = CURRENT_TIME;

	if (now.tv_sec > (LastCheck_ABPS_info_list.tv_sec + 10)) {
		/* elimino i pkt che stanno in lista da troppo tempo */
		struct ABPS_info *aux = &sentinel;

#ifdef ABPS_DEBUG
		printk(KERN_NOTICE "*** ABPS *** Check_ABPS_info_list\n");
#endif
		while (aux->next != NULL)
		{
			if (now.tv_sec > (aux->next->tx_time.tv_sec + 10)) {
				struct ABPS_info *temp = aux->next->next;
				kfree(aux->next);
				aux->next = temp;
				ABPS_info_counter--;
#ifdef ABPS_DEBUG
				printk(KERN_NOTICE "*** ABPS *** Check_ABPS_info_list rimuove uno\n");
#endif
			}
			else
				aux = aux->next;
		}
#ifdef ABPS_DEBUG
		printk(KERN_NOTICE "*** ABPS *** Check_ABPS_info_list rimasti %d info\n",
		       ABPS_info_counter);
#endif
		LastCheck_ABPS_info_list=now;
	}
}

/*
 *add the new element packet_info at the ABPS_info list
 */
static void ABPS_info_add(struct ABPS_info *packet_info)
{
	Check_ABPS_info_list();
	if (sentinel.next == NULL) { 
		/* empty list */
		sentinel.next = packet_info;
		packet_info->next = NULL;
	} else {
		struct ABPS_info *aux = &sentinel;
		
		while (aux->next != NULL)
			aux = aux->next;

		aux->next = packet_info;
		packet_info->next = NULL;
	}
	ABPS_info_counter++;
#ifdef ABPS_DEBUG
	printk(KERN_NOTICE "*** ABPS *** ABPS_info_add rimasti %d info\n",
	       ABPS_info_counter);
#endif
}

/*
 * remove the packet_info from the ABPS_info list
 */
static void ABPS_info_remove(struct ABPS_info *packet_info)
{
	struct ABPS_info *aux = &sentinel;
	while (aux->next != NULL) {
		if (aux->next->id == packet_info->id) {
			struct ABPS_info *temp = aux->next->next;
			kfree(aux->next);
			aux->next = temp;
			ABPS_info_counter--;
			break;
		}
		aux = aux->next;
	}
}


static int ipv6_get_udp_info(struct sk_buff *skb,
                             unsigned char *payload,
			     int data_length,
			     u16 *fragment_data_length,
			     u16 *fragment_offset,
			     u8 *more_fragment)
{
	struct ipv6hdr *payload_iphdr;
	struct udphdr *payload_udphdr;
	struct frag_hdr *fh;
	struct frag_hdr _frag;
	unsigned int offset, hdrs_len;
	int target, error;
	u8 nexthdr;
	bool found;

	if(data_length < sizeof(struct ipv6hdr)) {
		printk(KERN_ERR "*** ABPS *** get_udp_info: data_len less "
		       "then IPv6 header length\n");
		return(-3);
	}

	payload_iphdr = (struct ipv6hdr *) payload;
	if(payload_iphdr->version != 6) {
		printk(KERN_ERR "*** ABPS *** error: no IPv6 header "
		       "in ipv6_get_udp_info");
		return 0;
	}

	/* Variables initialization */
	*fragment_offset = *more_fragment = hdrs_len = error = 0;
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
	*fragment_data_length = ntohs(payload_iphdr->payload_len) - hdrs_len;


	if (error) {
		printk(KERN_ERR " *** ABPS *** error getting fragment hdr: %d\n", 
				error);
	} else if (!found) {
		printk(KERN_DEBUG " *** ABPS *** non-fragmented notify packet\n");
	} else {
		fh = skb_header_pointer(skb, offset, sizeof(_frag), &_frag);

		if (fh) {
			*fragment_offset = ntohs(fh->frag_off) & ~0x7;
			*more_fragment = ((fh->frag_off & htons(IP6_MF)) > 0);
		} else {
			printk(KERN_ERR " *** ABPS *** failed to convert offest "
			       "to hdr pointer\n");
		}
	}

	return 1;
}

static int get_udp_info(unsigned char *payload,
                        int data_len,
                        __be32 *saddr,
                        __be32 *daddr,
                        __be16 *sport,
                        __be16 *dport,
                        u16 *fragment_data_len,
                        u16 *fragment_offset,
                        u8 *more_fragment)
{
	struct iphdr *piphdr;
	struct udphdr *pudphdr;

	if (data_len < sizeof(struct iphdr))
	{
#ifdef ABPS_DEBUG
		printk(KERN_DEBUG "*** ABPS *** get_udp_info: data_len less"
				" then IP header length\n");
#endif
		return(-3);
	}

	piphdr = (struct iphdr *)payload;

	/* hearder IP */
	if ( piphdr->protocol == IPPROTO_UDP ) {
		/*   TCP: 0x06 ; UDP: 0x11 ; ICMP: 0x01   **/
		if (data_len < (4*(piphdr->ihl)) ) {
#ifdef ABPS_DEBUG
			printk(KERN_DEBUG "*** ABPS *** get_udp_info: data_len "
			       "less then UDP header length\n");
#endif
			return(-2);
		}

		/* header UDP */
		pudphdr = ((struct udphdr *) (payload + 4*(piphdr->ihl)));

		if (data_len < (4*(piphdr->ihl)+sizeof(struct udphdr))) {
#ifdef ABPS_DEBUG
			printk(KERN_DEBUG "*** ABPS *** get_udp_info: data_len "
					"less then UDP datagam length\n");
#endif
			return(-1);
		}

		*saddr = piphdr->saddr;
		*daddr = piphdr->daddr;
		*sport = pudphdr->source;
		*dport = pudphdr->dest;

#ifdef ABPS_DEBUG
		printk(KERN_DEBUG "ABPS get_udp_info IP_tot_len %d\n",ntohs(piphdr->tot_len));
#endif
		/* the following parameters are used by the client to sort packages */
		*fragment_data_len = ntohs(piphdr->tot_len) - (4*(piphdr->ihl));
		/* only data, not header */
#ifdef ABPS_DEBUG
		printk(KERN_DEBUG "ABPS get_udp_info frag_len %d\n", *fragment_data_len);
#endif
		*fragment_offset = (ntohs(piphdr->frag_off & htons(IP_OFFSET)))<<3;
#ifdef ABPS_DEBUG
		printk(KERN_DEBUG "ABPS get_udp_info frag_off %d\n", *fragment_offset);
#endif
		*more_fragment = (ntohs(piphdr->frag_off & htons(IP_MF)) > 0);
		return(1);
	}
	/* no udp */
	return(0);
}

/* Extract some information from the header ieee80211, ip and udp: sequence
 * number frame ieee, id datagram ip, source port udp... and put these in the
 * ABPS_info list if return 1 all it's ok.
 */

int ABPS_extract_pkt_info(struct ieee80211_hdr *hdr, struct sk_buff *skb)
{
	struct ABPS_info *packet_info;
	struct ieee80211_hdr_4addr *hdr4 = (struct ieee80211_hdr_4addr *)hdr;
	size_t hdrlen;
	u16 fc, type, stype, sc;
	unsigned int frag;
	u8 *payload;
	u8 *IPdatagram;
	u16 ethertype;
	int flen, result_from_get_udp_info;
	IPdgramInfo *p_IPDGInfo;

	uint32_t identifier = skb->sk_buff_identifier;

	fc = le16_to_cpu(hdr->frame_control) ;
	stype = WLAN_FC_GET_STYPE(fc);

	switch (WLAN_FC_GET_TYPE(fc)) {
		case IEEE80211_FTYPE_DATA:
			break;
			return 0;
	}
	p_IPDGInfo = kmalloc(sizeof (IPdgramInfo), GFP_ATOMIC);
	packet_info = kmalloc(sizeof(struct ABPS_info), GFP_ATOMIC);

	packet_info->id = hdr->seq_ctrl; /* 802.11 frame id */

	fc = le16_to_cpu(hdr4->frame_ctl);
	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);
	sc = le16_to_cpu(hdr4->seq_ctl);
	frag = WLAN_GET_SEQ_FRAG(sc);
	hdrlen = ieee80211_hdrlen(fc);

	stype &= ~IEEE80211_STYPE_QOS_DATA;

	if (stype != IEEE80211_STYPE_DATA && 
	    stype != IEEE80211_STYPE_DATA_CFACK &&
	    stype != IEEE80211_STYPE_DATA_CFACK &&
	    stype != IEEE80211_STYPE_DATA_CFPOLL &&
	    stype != IEEE80211_STYPE_DATA_CFACKPOLL)
		goto rx_dropped;


	payload = ((u8*) (hdr4)) + hdrlen;
	ethertype = (payload[6] << 8) | payload[7];
	if (ethertype == ETH_P_IP) {
		IPdatagram = ((u8*) hdr4) + hdrlen + 8;
		flen = sizeof(struct iphdr) + sizeof(struct udphdr);
		printk(KERN_NOTICE "ABPS Module Current identifier: %d ", identifier);
		result_from_get_udp_info = get_udp_info(IPdatagram,
				flen,
				&(p_IPDGInfo->saddr),
				&(p_IPDGInfo->daddr),
				&(p_IPDGInfo->sport),
				&(p_IPDGInfo->dport), 
				&(p_IPDGInfo->fragment_data_len),
				/* only data, not header */
				&(p_IPDGInfo->fragment_offset),
				&(p_IPDGInfo->more_fragment));
		
		if (result_from_get_udp_info > 0) {

			/* set the fields of the ABPS_info that will be put in the ABPS_info list */

			packet_info->datagram_info.ip_id = identifier;

			/* maybe ntohs, not sure */

			packet_info->datagram_info.udp_sport = p_IPDGInfo->sport;
			packet_info->datagram_info.fragment_data_len = p_IPDGInfo->fragment_data_len;
			packet_info->datagram_info.fragment_offset = p_IPDGInfo->fragment_offset;
			packet_info->datagram_info.more_fragment = p_IPDGInfo->more_fragment;
			packet_info->is_ipv6 = 0;
			packet_info->tx_time = CURRENT_TIME;
			ABPS_info_add(packet_info);
			return(1);
		}
		return(0);
	} else {
		if(ethertype == ETH_P_IPV6) {
			IPdatagram = ((u8*)hdr4) + hdrlen + 8;
			flen = sizeof(struct ipv6hdr) + sizeof(struct udphdr);

			result_from_get_udp_info = ipv6_get_udp_info(skb,IPdatagram,
					flen,
					&(p_IPDGInfo->fragment_data_len),
					&(p_IPDGInfo->fragment_offset),
					&(p_IPDGInfo->more_fragment));
			if (result_from_get_udp_info > 0) {
				/* set the fields of the ABPS_info that will be put in the ABPS_info list*/
				packet_info->datagram_info.ip_id = identifier;
				packet_info->datagram_info.fragment_data_len = p_IPDGInfo->fragment_data_len;
				packet_info->datagram_info.fragment_offset = p_IPDGInfo->fragment_offset;
				packet_info->datagram_info.more_fragment = p_IPDGInfo->more_fragment;
				packet_info->is_ipv6 = 1;
				packet_info->tx_time = CURRENT_TIME;

				ABPS_info_add(packet_info);

				return(1);
			}
		}
	}
rx_dropped:
	return 0;
}

/*
 * Join the information into the hdr with the correct ABPS_info
 */
int ABPS_info_response(struct sock *sk, 
                       struct ieee80211_hw *hw,
                       struct ieee80211_hdr *hdr,
                       struct ieee80211_tx_info *info,
                       struct  ieee80211_sub_if_data *sdata)
{
	int success = 0;
	u8 acked = -1;
	u8 retry_count = -1;
	unsigned long filtered_count = -1;
	struct ieee80211_local *local = hw_to_local(hw);
	struct ABPS_info *packet_info;
	int i;

	/* se era richiesto l'ack */
	if (!(info->flags & IEEE80211_TX_CTL_NO_ACK)) {
		/* e l'ack e' arrivato */
		if (info->flags & IEEE80211_TX_STAT_ACK)
			success=1;
	}
	/* 

	   VEDERE SE RIMETTERE A POSTO
	   else {
	   if (!(info->excessive_retries))
	   success=2;
	   }
	   */

	if (info->flags & IEEE80211_TX_CTL_NO_ACK) {
		/* ack not required */
		acked = ACK_NOT_REQ;
	} else if (info->flags & IEEE80211_TX_STAT_TX_FILTERED) {
		/* filtered frame */
		acked = ACK_FILTERED;
	} else if (info->flags & IEEE80211_TX_STAT_ACK) {
		/* frame acked */
		struct sta_info *sta;
		acked = ACK;

		retry_count = 0;
		/* modifiche per kernel da 2.6.27 in poi */
		for (i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
			/* the HW cannot have attempted that rate */
			if (i >= hw->max_rates) { ; }
			else
				retry_count += info->status.rates[i].count;
		}

		if (retry_count > 0)
			retry_count--;

		sta = sta_info_get(sdata, hdr->addr1);
		if (sta)
			filtered_count = sta->tx_filtered_count;
		else
			filtered_count = ACK_ERROR ;
	} else {
		/* frame not acked, ack not recieved */
		struct sta_info *sta;
		acked = ACK_NOT;

		retry_count = 0;
		/* modifiche per kernel da 2.6.27 in poi */
		for (i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
			/* the HW cannot have attempted that rate */
			if (i >= hw->max_rates) { ; }
			else
				retry_count += info->status.rates[i].count;
		}
		if (retry_count > 0)
			retry_count--;

		sta = sta_info_get(sdata, hdr->addr1);
		if (sta) 
			filtered_count = sta->tx_filtered_count;
		else 
			filtered_count = ACK_ERROR;
	}

	packet_info = ABPS_info_search(hdr->seq_ctrl);

	if (packet_info != 0) {
		packet_info->datagram_info.acked = acked;
		packet_info->datagram_info.retry_count = retry_count;

		packet_info->rx_time = CURRENT_TIME;
		/* mando la notifica al socket */
		/* NOTA ABPS DIE KURO: adesso estrae solo data_len, offset e more_frags, comunque non potevo
		   estrearre dati da udp in caso di frammentazione, l'indirizzo ip invece non e'
		   invece mai propagato fino all'utente */

		ip_local_error_notify(sk, success,
		                      packet_info->datagram_info.ip_id,
				      packet_info->datagram_info.fragment_data_len,
				      packet_info->datagram_info.fragment_offset,
				      packet_info->datagram_info.more_fragment,
				      packet_info->datagram_info.retry_count);


		ABPS_info_remove(packet_info);
		return(1);
	}
	return(0);
}

/* fine ABPS VIC */

