/**
 * SACD Ripper - http://code.google.com/p/sacd-ripper/
 *
 * Copyright (c) 2010-2011 by respective authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
 
#include <dispmgr.h>
#include <mm.h>
#define HPTE_R_PROT_MASK                0x0000000000000003ULL
#define HV_BASE                                 0x8000000014000000ULL   // where in lv2 to map lv1
#define HV_SIZE                                 0x001000                                // 0x1000 (we need 4k from lv1 only)
#define HV_PAGE_SIZE                    0x0c                                    // 4k = 0x1000 (1 << 0x0c)
#define HV_START_OFFSET                 0x363000                                // remove lv2 protection
#define HV_OFFSET                               0x000a78                                // at address 0x363a78

#ifndef __SYS_STORAGE_H__
#define __SYS_STORAGE_H__

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <lv1_hvcall.h>
#include <ss.h>
#include <vuart.h>
#include <if_vlan.h>
#include <if_ether.h>
#include <system.h>
#include <mm.h>
#include <lv1_map.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BD_DEVICE                           0x0101000000000006ULL
#define HDD_DEVICE                          0x0101000000000007ULL

#define FLASH_DEVICE_NAND                   0x0100000000000001ULL
#define FLASH_DEVICE_NOR                    0x0100000000000004ULL
#define FLASH_FLAGS							0x22ULL

#define VFLASH5_DEV_ID				0x100000500000001ull
#define VFLASH5_SECTOR_SIZE			0x200ull
#define VFLASH5_HEADER_SECTORS		0x2ull

/* The generic packet command opcodes for CD/DVD Logical Units,
 * From Table 57 of the SFF8090 Ver. 3 (Mt. Fuji) draft standard. */
#define GPCMD_GET_CONFIGURATION                0x46
#define GPCMD_GET_EVENT_STATUS_NOTIFICATION    0x4a
#define GPCMD_MODE_SELECT_10                   0x55
#define GPCMD_MODE_SENSE_10                    0x5a
#define GPCMD_READ_CD                          0xbe
#define GPCMD_READ_DVD_STRUCTURE               0xad
#define GPCMD_READ_TRACK_RZONE_INFO            0x52
#define GPCMD_READ_TOC_PMA_ATIP                0x43
#define GPCMD_REPORT_KEY                       0xa4
#define GPCMD_SEND_KEY                         0xa3

#define LV2_STORAGE_SEND_ATAPI_COMMAND         (1)


// QA/PROD/RECOVER Toggles

#define AIM_PACKET_ID_GET_DEV_ID				0x19003
#define AIM_PACKET_ID_GET_CONSOLE_ID			0x19005
/*
#define INDI_INFO_MGR_PACKET_ID_GET_DATA_SIZE_BY_INDEX	0x17001
#define INDI_INFO_MGR_PACKET_ID_GET_DATA_BY_INDEX	0x17002
#define EID0_INDEX					0
*/
#define UPDATE_MGR_PACKET_ID_SET_TOKEN			0x600A
#define UPDATE_MGR_PACKET_ID_READ_EPROM			0x600B
#define UPDATE_MGR_PACKET_ID_WRITE_EPROM		0x600C

#define TOKEN_SIZE								80
#define IDPS_SIZE								16
#define DEBUG_SUPPORT_FLAG_SIZE					16

#define FSELF_FLAG_OFFSET						0x48C06
#define PRODUCT_MODE_FLAG_OFFSET				0x48C07
#define QA_FLAG_OFFSET							0x48C0A
#define DEVICE_TYPE_FLAG_OFFSET					0x48C13
#define ACTIVE_SPE_FLAG_OFFSET					0x48C30
#define HDD_COPY_MODE_FLAG_OFFSET				0x48C42
#define DEBUG_SUPPORT_FLAG_OFFSET				0x48C50
#define UPDATE_STATUS_FLAG_OFFSET				0x48C60
#define RECOVER_MODE_FLAG_OFFSET				0x48C61
#define QA_TOKEN_OFFSET							0x48D3E

#define MM_LOAD_BASE(ptr, offset)			\
	__asm__ __volatile__ (					\
		"li %0, 1\n\t"						\
		"rldicr %0, %0, 63, 0\n\t"			\
		"oris %0, %0, %1\n\t"				\
		"ori %0, %0, %2\n\t" :				\
		"=r"(ptr) :							\
		"g"(((offset) >> 16) & 0xFFFF),		\
		"g"((offset) & 0xFFFF))
		
//gelic
#define GELIC_NET_MAX_MTU						VLAN_ETH_FRAME_LEN

#define GELIC_BUS_ID							1
#define GELIC_DEV_ID							0

#define GELIC_DMA_BASE							0x8000000013380000ULL
#define GELIC_DMA_OFFSET						0x13380000ULL
#define GELIC_DMA_PAGE_SIZE						12
#define GELIC_DMA_SIZE							(1 << GELIC_DMA_PAGE_SIZE)

#define GELIC_PORT_ETHERNET_0					0
#define GELIC_PORT_WIRELESS						1

#define GELIC_LV1_GET_MAC_ADDRESS				1
#define GELIC_LV1_GET_ETH_PORT_STATUS			2
#define GELIC_LV1_SET_NEGOTIATION_MODE			3
#define GELIC_LV1_GET_VLAN_ID					4
#define GELIC_LV1_SET_WOL						5
#define GELIC_LV1_GET_CHANNEL					6
#define GELIC_LV1_POST_WLAN_CMD					9
#define GELIC_LV1_GET_WLAN_CMD_RESULT			10
#define GELIC_LV1_GET_WLAN_EVENT				11

#define GELIC_LV1_VLAN_TX_ETHERNET_0			0x0000000000000002L
#define GELIC_LV1_VLAN_TX_WIRELESS				0x0000000000000003L
#define GELIC_LV1_VLAN_RX_ETHERNET_0			0x0000000000000012L
#define GELIC_LV1_VLAN_RX_WIRELESS				0x0000000000000013L

#define GELIC_DESCR_DMA_COMPLETE				0x00000000
#define GELIC_DESCR_DMA_BUFFER_FULL				0x00000000
#define GELIC_DESCR_DMA_RESPONSE_ERROR			0x10000000
#define GELIC_DESCR_DMA_PROTECTION_ERROR		0x20000000
#define GELIC_DESCR_DMA_FRAME_END				0x40000000
#define GELIC_DESCR_DMA_FORCE_END				0x50000000
#define GELIC_DESCR_DMA_CARDOWNED				0xA0000000
#define GELIC_DESCR_DMA_NOT_IN_USE				0xB0000000

#define GELIC_DESCR_DMA_STAT_MASK				0xF0000000

#define GELIC_DESCR_TX_DMA_IKE					0x00080000
#define GELIC_DESCR_TX_DMA_FRAME_TAIL			0x00040000
#define GELIC_DESCR_TX_DMA_TCP_CHKSUM			0x00020000
#define GELIC_DESCR_TX_DMA_UDP_CHKSUM			0x00030000
#define GELIC_DESCR_TX_DMA_NO_CHKSUM			0x00000000
#define GELIC_DESCR_TX_DMA_CHAIN_END			0x00000002

#define GELIC_DESCR_RXDMADU						0x80000000
#define GELIC_DESCR_RXLSTFBF					0x40000000
#define GELIC_DESCR_RXIPCHK						0x20000000
#define GELIC_DESCR_RXTCPCHK					0x10000000
#define GELIC_DESCR_RXWTPKT						0x00C00000
#define GELIC_DESCR_RXVLNPKT					0x00200000
#define GELIC_DESCR_RXRRECNUM					0x0000ff00

#define GELIC_DESCR_RXALNERR					0x40000000
#define GELIC_DESCR_RXOVERERR					0x20000000
#define GELIC_DESCR_RXRNTERR					0x10000000
#define GELIC_DESCR_RXIPCHKERR					0x08000000
#define GELIC_DESCR_RXTCPCHKERR					0x04000000
#define GELIC_DESCR_RXDRPPKT					0x00100000
#define GELIC_DESCR_RXIPFMTERR					0x00080000
#define GELIC_DESCR_RXDATAERR					0x00020000
#define GELIC_DESCR_RXCALERR					0x00010000
#define GELIC_DESCR_RXCREXERR					0x00008000
#define GELIC_DESCR_RXMLTCST					0x00004000

#define PKT_HDR_SIZE							16
#define PKT_MAGIC								0x0FACE0FF
#define PKT_FLAG_LAST							0x00000001

int mm_insert_htab_entry1(u64 va_addr, u64 lpar_addr, u64 prot, u64 * index)
{
        u64 hpte_group, hpte_index =
            0, hpte_v, hpte_r, hpte_evicted_v, hpte_evicted_r;

        hpte_group =
            (((va_addr >> 28) ^ ((va_addr & 0xFFFFFFFULL) >> 12)) & 0x7FF) << 3;
        hpte_v = ((va_addr >> 23) << 7) | HPTE_V_VALID;
        hpte_r = lpar_addr | 0x38 | (prot & HPTE_R_PROT_MASK);

        int result =
            lv1_insert_htab_entry(0, hpte_group, hpte_v, hpte_r, HPTE_V_BOLTED,
                                  0,
                                  &hpte_index, &hpte_evicted_v,
                                  &hpte_evicted_r);


        if ((result == 0) && (index != 0))
                *index = hpte_index;

        return (int)result;
}

int mm_map_lpar_memory_region1(u64 lpar_start_addr, u64 ea_start_addr, u64 size,
                              u64 page_shift, u64 prot)
{
        int result;
        u64 i;
        for (i = 0; i < size >> page_shift; i++) {
                result =
                    mm_insert_htab_entry1(MM_EA2VA(ea_start_addr),
                                         lpar_start_addr, prot, 0);
                if (result != 0)
                        return result;

                lpar_start_addr += (1 << page_shift);
                ea_start_addr += (1 << page_shift);
        }

        return 0;
}

int vuart_wait_for_rx_data(u64 port)
{
	u64 val;
	int result;

	for (;;)
	{
		result = lv1_get_virtual_uart_param(port, VUART_PARAM_RX_BYTES, &val);
		if (result < 0)
			return result;

		if (val != 0)
			break;
	}

	return val;
}

const u8 gelic_bcast_mac_addr[VLAN_ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

struct gelic_var
{
	u64 dma_lpar_addr;
	u32 dma_bus_addr;
	u8 mac_addr[VLAN_ETH_ALEN];
	u64 vlan_id;
};

struct gelic_descr
{
	u32 buf_addr;
	u32 buf_size;
	u32 next_descr_addr;
	u32 dmac_cmd_status;
	u32 result_size;
	u32 valid_size;
	u32 data_status;
	u32 data_error;
};

struct pkt_hdr
{
	u32 magic;
	u32 offset;
	u32 size;
	u32 flags;
};

static struct gelic_var gelic_var;


int gelic_xmit(const u8 dest_mac_addr[VLAN_ETH_ALEN], u16 proto, const void *data, u64 size)
{
	volatile struct gelic_descr *descr;
	struct vlan_eth_hdr *vlan_eth_hdr;
	int result;

	if (size > VLAN_ETH_DATA_LEN)
		return -1;

	MM_LOAD_BASE(descr, GELIC_DMA_OFFSET);

	descr->dmac_cmd_status = GELIC_DESCR_DMA_CARDOWNED |
		GELIC_DESCR_TX_DMA_IKE |
		GELIC_DESCR_TX_DMA_NO_CHKSUM |
		GELIC_DESCR_TX_DMA_FRAME_TAIL;
	descr->next_descr_addr = 0;
	descr->result_size = 0;
	descr->valid_size = 0;
	descr->data_status = 0;
	descr->data_error = 0;
	descr->buf_addr = gelic_var.dma_bus_addr + 0x100;
	descr->buf_size = VLAN_ETH_HLEN + size;

	vlan_eth_hdr = (struct vlan_eth_hdr *) ((u8 *) descr + 0x100);
	memcpy(vlan_eth_hdr->dest, dest_mac_addr, VLAN_ETH_ALEN);
	memcpy(vlan_eth_hdr->src, gelic_var.mac_addr, VLAN_ETH_ALEN);
	vlan_eth_hdr->proto = ETH_P_8021Q;
	vlan_eth_hdr->tci = gelic_var.vlan_id & VLAN_VID_MASK;
	vlan_eth_hdr->encap_proto = proto;
	memcpy((u8 *) vlan_eth_hdr + VLAN_ETH_HLEN, data, size);

	wmb();

	result = lv1_net_start_tx_dma(GELIC_BUS_ID, GELIC_DEV_ID, gelic_var.dma_bus_addr, 0);
	if (result != 0)
		return result;

	for (;;)
	{
		if (!((descr->dmac_cmd_status & GELIC_DESCR_DMA_STAT_MASK) == GELIC_DESCR_DMA_CARDOWNED))
			break;
	}

	return 0;
}

int gelic_xmit_data(const u8 dest_mac_addr[VLAN_ETH_ALEN], u16 proto, const void *data, u64 size)
{
#define MIN(a, b)	((a) <= (b) ? (a) : (b))

	u64 offset, pkt_size;
	int i, result;

	offset = 0;

	while (offset < size)
	{
		pkt_size = MIN(size - offset, ETH_DATA_LEN);

		result = gelic_xmit(dest_mac_addr, proto, (u8 *) data + offset, pkt_size);
		if (result != 0)
			return result;

		offset += pkt_size;

		for (i = 0; i < 100000; i++)
			__asm__ __volatile__ ("nop");
	}

	return 0;

#undef MIN
}


//gelic

// QA FLAG
#include "sha1.h"
#include "aes.h"

uint8_t idps[IDPS_SIZE];
uint8_t seed[TOKEN_SIZE];
uint8_t token[TOKEN_SIZE];
AES_KEY aes_ctx;

static uint8_t erk[] = {
	0x34, 0x18, 0x12, 0x37, 0x62, 0x91, 0x37, 0x1c,
	0x8b, 0xc7, 0x56, 0xff, 0xfc, 0x61, 0x15, 0x25,
	0x40, 0x3f, 0x95, 0xa8, 0xef, 0x9d, 0x0c, 0x99,
	0x64, 0x82, 0xee, 0xc2, 0x16, 0xb5, 0x62, 0xed
};

static uint8_t iv[] = {
	0xe8, 0x66, 0x3a, 0x69, 0xcd, 0x1a, 0x5c, 0x45,
	0x4a, 0x76, 0x1e, 0x72, 0x8c, 0x7c, 0x25, 0x4e
};

static uint8_t hmac[] = {
	0xcc, 0x30, 0xc4, 0x22, 0x91, 0x13, 0xdb, 0x25,
	0x73, 0x35, 0x53, 0xaf, 0xd0, 0x6e, 0x87, 0x62,
	0xb3, 0x72, 0x9d, 0x9e, 0xfa, 0xa6, 0xd5, 0xf3,
	0x5a, 0x6f, 0x58, 0xbf, 0x38, 0xff, 0x8b, 0x5f,
	0x58, 0xa2, 0x5b, 0xd9, 0xc9, 0xb5, 0x0b, 0x01,
	0xd1, 0xab, 0x40, 0x28, 0x67, 0x69, 0x68, 0xea,
	0xc7, 0xf8, 0x88, 0x33, 0xb6, 0x62, 0x93, 0x5d,
	0x75, 0x06, 0xa6, 0xb5, 0xe0, 0xf9, 0xd9, 0x7a
};

// READ QA FLAG
u8 read_qa_flag()
{
	u64 value=0;
	lv2_ss_update_mgr_if(UPDATE_MGR_PACKET_ID_READ_EPROM,
		QA_FLAG_OFFSET, (uint64_t) &value, 0, 0, 0, 0);
	return (value==0x00);	
}	

int is_firm_355(void)
{
    // TOC 3.55
   u64 toc;
   toc =lv2_peek(0x8000000000003000ULL);
   if(toc == 0x8000000000330540ULL)
   {
      return 1;
   }
   else
   {
      return 0;
   }
}

static inline void lv2_new_poke(uint64_t addr, uint64_t val)
{
	lv2syscall2(10, addr, val);
}

#define NEW_POKE_SYSCALL_ADDR	0x800000000000175cULL

void install_new_poke()
{
        lv2_poke(NEW_POKE_SYSCALL_ADDR, 0xF88300007C001FACULL);
        lv2_poke(NEW_POKE_SYSCALL_ADDR + 8, 0x4C00012C4E800020ULL);
}

void remove_new_poke()
{
        lv2_poke(NEW_POKE_SYSCALL_ADDR, 0x7C0802A6F8010010ULL);
        lv2_poke(NEW_POKE_SYSCALL_ADDR + 8, 0x7D4B537844000022ULL);
}


// SET QA FLAG AND TOKEN
void set_qa_flag()
{
	int result = lv2_ss_aim_if(AIM_PACKET_ID_GET_DEV_ID, (uint64_t) &idps);
	if(result) return;

	memset(seed, 0, TOKEN_SIZE);
	memcpy(seed + 4, idps, IDPS_SIZE);
	seed[3] = 1;

/************************************************************************************************************************/
	
	seed[39] |= 0x1; /* QA_FLAG_EXAM_API_ENABLE */
	seed[39] |= 0x2; /* QA_FLAG_QA_MODE_ENABLE */
	seed[47] |= 0x2;
	seed[47] |= 0x4; /* checked by lv2_kernel.self and sys_init_osd.self */
			 /* can run sys_init_osd.self from /app_home ? */
	seed[51] |= 0x1; /* QA_FLAG_ALLOW_NON_QA */
	seed[51] |= 0x2; /* QA_FLAG_FORCE_UPDATE */
	
/************************************************************************************************************************/

	hmac_sha1(hmac, sizeof(hmac), seed, 60, seed + 60);

	result = AES_set_encrypt_key(erk, 256, &aes_ctx);
	
	if(result) return;

	AES_cbc_encrypt(iv, seed, token, TOKEN_SIZE, &aes_ctx);

	if(is_firm_355())
	{
	result = lv2_ss_update_mgr_if(UPDATE_MGR_PACKET_ID_SET_TOKEN,
		(uint64_t) token, TOKEN_SIZE, 0, 0, 0, 0);
	if(result) return;
	}
else
{
//token start
#include <ps3dm_msg.h>
//install_new_poke();
struct ps3dm_scm_write_eeprom write_eeprom;
u8*p=(u8*)&write_eeprom;
u64 laid, paid, vuart_lpar_addr, muid, nwritten;
int len;
result = lv1_allocate_memory(4096, 0x0C, 0, 0, &vuart_lpar_addr, &muid);
if(result!=0) return;
result = mm_map_lpar_memory_region1(vuart_lpar_addr, HV_BASE, HV_SIZE, HV_PAGE_SIZE, 0);
if(result!=0) return;

laid=0x1070000002000001;
paid=0x1070000033000001;
memset(&write_eeprom, 0, sizeof(write_eeprom));
ps3dm_init_header(&write_eeprom.dm_hdr, 1, PS3DM_FID_SCM,
	sizeof(write_eeprom)	-	sizeof(struct ps3dm_header),
	sizeof(write_eeprom)	-	sizeof(struct ps3dm_header));
ps3dm_init_ss_header(&write_eeprom.ss_hdr, PS3DM_PID_SCM_WRITE_EEPROM, laid, paid);
write_eeprom.offset=0x48D3E;
write_eeprom.nwrite=0x50;
write_eeprom.buf_size=0x50;
memset(write_eeprom.buf, 0, sizeof(write_eeprom.buf));
memcpy(write_eeprom.buf, token, 0x50);
len=sizeof(write_eeprom);
for(u16 n =0;n<len;n+=8)
{
static u64 value;
memcpy(&value, &p[n], 8);
lv1_poke((u64) n, value);
__asm__("sync");
value =  lv2_peek(0x8000000000000000ULL);
}
result = lv1_write_virtual_uart(DISPMGR_VUART_PORT, vuart_lpar_addr, len, &nwritten);
if(result!=0) return;
if(nwritten>len) nwritten=len;
//{remove_new_poke();}

//token end
}	
	result = lv2_ss_update_mgr_if(UPDATE_MGR_PACKET_ID_WRITE_EPROM,
		QA_FLAG_OFFSET, 0x00, 0, 0, 0, 0);
		
}

/*void read_eeprom_dump()
{
#include <ps3dm_msg.h>
#include <ps3dm_msg.h>
install_new_poke();
struct ps3dm_scm_read_eeprom write_eeprom;
u8*p=(u8*)&write_eeprom;
u64 laid, paid, vuart_lpar_addr, muid, nwritten, nread;
int len;
lv1_allocate_memory(4096, 0x0C, 0, &vuart_lpar_addr, &muid);
mm_map_lpar_memory_region1(vuart_lpar_addr, HV_BASE, HV_SIZE, HV_PAGE_SIZE, 0);

laid=0x1070000002000001;
paid=0x1070000033000001;
memset(&write_eeprom, 0, sizeof(write_eeprom));
ps3dm_init_header(&write_eeprom.dm_hdr, 1, PS3DM_FID_SCM,
	sizeof(write_eeprom)	-	sizeof(struct ps3dm_header),
	sizeof(write_eeprom)	-	sizeof(struct ps3dm_header));
ps3dm_init_ss_header(&write_eeprom.ss_hdr, PS3DM_PID_SCM_READ_EEPROM, laid, paid);
write_eeprom.offset=0x2f00;
write_eeprom.nread=0x100;
write_eeprom.buf_size=0x100;
len=sizeof(write_eeprom);
for(u16 n =0;n<len;n+=8)
{
static u64 value;
memcpy(&value, &p[n], 8);
lv2_new_poke(HV_BASE + (u64) n, value);
__asm__("sync");
value =  lv2_peek(0x8000000000000000ULL);
}
lv1_write_virtual_uart(DISPMGR_VUART_PORT, vuart_lpar_addr, len, &nwritten);
    vuart_wait_for_rx_data(DISPMGR_VUART_PORT);

    lv1_read_virtual_uart(DISPMGR_VUART_PORT, vuart_lpar_addr, 4096, &nread);
	if(nread>len) nread=len;*/
/*	    for(u16 n = 0; n < len; n += 8)
    {
        static u64 value;
        value=lv2_peek(HV_BASE + (u64) n);
        memcpy(&p[n], &value, 8);
    }*/
/*	u8 *buf;
	memcpy(&buf, &p[nread-72], 0x100);
	FILE *output;
	output=fopen("/dev_usb000/eeprom_2f00", "wb");

		fwrite (&buf, sizeof(buf), 1, output);
	
{remove_new_poke();}
}*/

// RESET QA FLAG AND TOKEN
void reset_qa_flag()
{
	int result = lv2_ss_aim_if(AIM_PACKET_ID_GET_DEV_ID, (uint64_t) &idps);
	if(result) return;

	memset(seed, 0, TOKEN_SIZE);
	memcpy(seed + 4, idps, IDPS_SIZE);
	seed[3] = 1;

	hmac_sha1(hmac, sizeof(hmac), seed, 60, seed + 60);

	result = AES_set_encrypt_key(erk, 256, &aes_ctx);
	if(result) return;

	AES_cbc_encrypt(iv, seed, token, TOKEN_SIZE, &aes_ctx);
	
	if(is_firm_355())
	{
	result = lv2_ss_update_mgr_if(UPDATE_MGR_PACKET_ID_SET_TOKEN,
		(uint64_t) token, TOKEN_SIZE, 0, 0, 0, 0);
	if(result) return;
	}
else
{
//token start
#include <ps3dm_msg.h>
//install_new_poke();
struct ps3dm_scm_write_eeprom write_eeprom;
u8*p=(u8*)&write_eeprom;
u64 laid, paid, vuart_lpar_addr, muid, nwritten;
int len;
result = lv1_allocate_memory(4096, 0x0C, 0, 0, &vuart_lpar_addr, &muid);
if(result!=0) return;
result = mm_map_lpar_memory_region1(vuart_lpar_addr, HV_BASE, HV_SIZE, HV_PAGE_SIZE, 0);
if(result!=0) return;

laid=0x1070000002000001;
paid=0x1070000033000001;
memset(&write_eeprom, 0, sizeof(write_eeprom));
ps3dm_init_header(&write_eeprom.dm_hdr, 1, PS3DM_FID_SCM,
	sizeof(write_eeprom)	-	sizeof(struct ps3dm_header),
	sizeof(write_eeprom)	-	sizeof(struct ps3dm_header));
ps3dm_init_ss_header(&write_eeprom.ss_hdr, PS3DM_PID_SCM_WRITE_EEPROM, laid, paid);
write_eeprom.offset=0x48D3E;
write_eeprom.nwrite=0x50;
write_eeprom.buf_size=0x50;
memset(write_eeprom.buf, 0, sizeof(write_eeprom.buf));
memcpy(write_eeprom.buf, token, 0x50);
len=sizeof(write_eeprom);
for(u16 n =0;n<len;n+=8)
{
static u64 value;
memcpy(&value, &p[n], 8);
lv1_poke((u64) n, value);
__asm__("sync");
value =  lv2_peek(0x8000000000000000ULL);
}
result = lv1_write_virtual_uart(DISPMGR_VUART_PORT, vuart_lpar_addr, len, &nwritten);
if(result!=0) return;
if(nwritten>len) nwritten=len;
//{remove_new_poke();}

//token end
}

	lv2_ss_update_mgr_if(UPDATE_MGR_PACKET_ID_WRITE_EPROM,
		QA_FLAG_OFFSET, 0xff, 0, 0, 0, 0);
}

void toggle_qa_flag()
{
	if(!read_qa_flag())
		set_qa_flag();
	else
		reset_qa_flag();
}

#ifdef __cplusplus
};
#endif
#endif /* _SYS_STORAGE_H__ */
