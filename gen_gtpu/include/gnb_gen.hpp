/* 
 * Copyright (c) 2021, NVIDIA CORPORATION. All rights reserved. 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GNB_GEN_HPP_
#define GNB_GEN_HPP_

#include "gnb.hpp"

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

#define GTPU_PAYLOAD_LENGTH             1024
#define GTPU_PAYLOAD_IN_IP_LENGTH       1024
#define GTPU_PAYLOAD_IN_UDP_LENGTH      1004

struct gtpu_hdr {
    uint8_t   version_flags;
    uint8_t   type;
    uint16_t  length;
    uint32_t  teid;
} __attribute__((packed));

struct gtpu_ext_hdr {
    uint16_t  seq_num;
    uint8_t   npdu_num;
    uint8_t   nxt_ext_hdr;
} __attribute__((packed));

struct gtpu_pdu_sess_ctr {
    uint8_t length;
    uint8_t type;
    uint8_t qfi;
    uint8_t nxt_ext_hdr;
} __attribute__((packed));

struct pkt_hdr_template
{
    struct rte_ether_hdr        eth;
    struct rte_ipv4_hdr         ipv4;
    struct rte_udp_hdr          udp;
    struct gtpu_hdr             gtpu;
    struct gtpu_ext_hdr         gtpu_ext;
    struct gtpu_pdu_sess_ctr    pdu_sess_ctr;
    struct rte_ipv4_hdr         in_ipv4;
    struct rte_udp_hdr          in_udp;

} __attribute__((packed));

class GNBGen : public GNB {

    public:
        GNBGen(int _index, struct rte_ether_addr &_eth_addr, 
                uint16_t _ap0, uint16_t _ap1, uint16_t _ap2, uint16_t _ap3, 
                uint16_t _vlan_tci, uint8_t _port_id,  uint16_t _rxd, uint16_t _txd,
                struct rte_mempool * _mpool, struct rte_ether_addr &_dst_eth_addr, 
                int _mu, int _tx_offset_pkts_ns, int _tx_interval_pkts)
                : GNB(_index, _eth_addr, _ap0, _ap1, _ap2, _ap3, _vlan_tci, _port_id, _rxd, _txd, _mpool)
        {
            rte_ether_addr_copy(&_dst_eth_addr, &dst_eth_addr);

            for (int ihdr = 0; ihdr < NUM_AP; ihdr++) {
                rte_ether_addr_copy(&dst_eth_addr, &pkt_hdr[ihdr].eth.d_addr);
                rte_ether_addr_copy(&eth_addr, &pkt_hdr[ihdr].eth.s_addr);
                pkt_hdr[ihdr].eth.ether_type 			= rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

                pkt_hdr[ihdr].ipv4.version_ihl = IP_VHL_DEF;
                pkt_hdr[ihdr].ipv4.type_of_service = 0;   
                pkt_hdr[ihdr].ipv4.total_length = rte_cpu_to_be_16(GTPU_PAYLOAD_LENGTH + 44);      
                pkt_hdr[ihdr].ipv4.packet_id = 0;     
                pkt_hdr[ihdr].ipv4.fragment_offset = 0;   
                pkt_hdr[ihdr].ipv4.time_to_live = IP_DEFTTL;      
                pkt_hdr[ihdr].ipv4.next_proto_id = IPPROTO_UDP;     
                pkt_hdr[ihdr].ipv4.hdr_checksum = 0;      
                pkt_hdr[ihdr].ipv4.src_addr = rte_cpu_to_be_32(0x1e1e0002);      
                pkt_hdr[ihdr].ipv4.dst_addr = rte_cpu_to_be_32(0x1e1e0003);

                pkt_hdr[ihdr].udp.src_port = rte_cpu_to_be_16(2152);
                pkt_hdr[ihdr].udp.dst_port = rte_cpu_to_be_16(2152);
                pkt_hdr[ihdr].udp.dgram_len = rte_cpu_to_be_16(GTPU_PAYLOAD_LENGTH + 24);

                pkt_hdr[ihdr].gtpu.version_flags = 0x34;
                pkt_hdr[ihdr].gtpu.type = 0xff;
                pkt_hdr[ihdr].gtpu.length = rte_cpu_to_be_16(GTPU_PAYLOAD_LENGTH + 8);
                pkt_hdr[ihdr].gtpu.teid = rte_cpu_to_be_32(0x01);
                pkt_hdr[ihdr].gtpu_ext.seq_num = rte_cpu_to_be_16(0);
                pkt_hdr[ihdr].gtpu_ext.npdu_num = 0;
                pkt_hdr[ihdr].gtpu_ext.nxt_ext_hdr = 0x85;
                pkt_hdr[ihdr].pdu_sess_ctr.length = 1;
                pkt_hdr[ihdr].pdu_sess_ctr.type = 0x10;
                pkt_hdr[ihdr].pdu_sess_ctr.qfi = 0x09;
                pkt_hdr[ihdr].pdu_sess_ctr.nxt_ext_hdr = 0;

                pkt_hdr[ihdr].in_ipv4.version_ihl = IP_VHL_DEF;
                pkt_hdr[ihdr].in_ipv4.type_of_service = 0;   
                pkt_hdr[ihdr].in_ipv4.total_length = rte_cpu_to_be_16(GTPU_PAYLOAD_IN_IP_LENGTH);      
                pkt_hdr[ihdr].in_ipv4.packet_id = 0;     
                pkt_hdr[ihdr].in_ipv4.fragment_offset = 0;   
                pkt_hdr[ihdr].in_ipv4.time_to_live = IP_DEFTTL;      
                pkt_hdr[ihdr].in_ipv4.next_proto_id = IPPROTO_UDP;     
                pkt_hdr[ihdr].in_ipv4.hdr_checksum = 0;      
                pkt_hdr[ihdr].in_ipv4.src_addr = rte_cpu_to_be_32(0x0a3c0001);      
                pkt_hdr[ihdr].in_ipv4.dst_addr = rte_cpu_to_be_32(0x0a3c00fe); 

                pkt_hdr[ihdr].in_udp.src_port = rte_cpu_to_be_16(1234);
                pkt_hdr[ihdr].in_udp.dst_port = rte_cpu_to_be_16(4321);
                pkt_hdr[ihdr].in_udp.dgram_len = rte_cpu_to_be_16(GTPU_PAYLOAD_IN_UDP_LENGTH);
            }

            mu = _mu;
            tx_offset_pkts_ns = _tx_offset_pkts_ns;
            tx_interval_pkts = _tx_interval_pkts; //128;

            if (mu == 0)  {
                //1ms 15kHZ SCS
                tx_interval_step = 10;
                tx_interval_ns = tx_interval_step * 100 * 1000;
                tx_interval_s = (float) tx_interval_step * 0.0001;
            } else {
                //by default 500us 30kHZ SCS
                tx_interval_step = 5;
                tx_interval_ns = tx_interval_step * 100 * 1000;
                tx_interval_s = (float) tx_interval_step * 0.0001;
            }
        }

        ~GNBGen();

        int                     mu;
        int                     tx_interval_step;
        int                     tx_interval_ns;
        int                     tx_offset_pkts_ns;
        float                   tx_interval_s;
        int                     tx_interval_pkts;
        pkt_hdr_template        pkt_hdr[NUM_AP];
        struct rte_ether_addr   dst_eth_addr;        
};

#endif
