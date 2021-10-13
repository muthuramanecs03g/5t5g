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

#include "gnb.hpp"

struct rte_ether_addr ru0_addr = {
    .addr_bytes = {0x00, 0x00, 0x1e, 0x1e, 0x00, 0x02}
};
uint16_t ru0_ap[NUM_AP] = {0, 4, 6, 9};
uint16_t ru0_vlan = 0;

struct rte_ether_addr ru1_addr = {
    .addr_bytes = {0x00, 0x00, 0x1e, 0x1e, 0x00, 0x02}
};
uint16_t ru1_ap[NUM_AP] = {1, 3, 5, 7};
uint16_t ru1_vlan = 0;

GNB::GNB(int _index, struct rte_ether_addr &_eth_addr, 
        uint16_t _ap0, uint16_t _ap1, uint16_t _ap2, uint16_t _ap3,
        uint16_t _vlan_tci, uint8_t _port_id, uint16_t _rxd, uint16_t _txd,
        struct rte_mempool *_mpool1,  struct rte_mempool *_mpool2)
{
    index = _index;
    vlan_tci = _vlan_tci;
    port_id = _port_id;
    rxd = _rxd;
    txd = _txd;
    mpool1 = _mpool1;
    mpool2 = _mpool2;

    snprintf(name, RU_NAME_LEN, "GNB #%d", index);

    rte_ether_addr_copy(&_eth_addr, &eth_addr);
    
    for (int iloop = 0; iloop < NUM_AP; iloop++) {
        rxq_list[iloop] = (NUM_AP * index) + iloop;
        txq_list[iloop] = rxq_list[iloop];
    }

    eAxC_list[0] = _ap0;
    eAxC_list[1] = _ap1;
    eAxC_list[2] = _ap2;
    eAxC_list[3] = _ap3;
}

GNB::~GNB() {}

void GNB::setupQueues() {
    int ret = 0;
    uint8_t socketid = (uint8_t) rte_lcore_to_socket_id(rte_lcore_id());
    struct rte_mempool *mpool;

    for (int iqueue = 0; iqueue < NUM_AP; iqueue++) {
        mpool = mpool1;
        if (iqueue % 2 != 0) {
            mpool = mpool2;
        }
        ret = rte_eth_rx_queue_setup(port_id, rxq_list[iqueue], rxd, socketid, NULL, mpool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%u\n", ret, port_id);

        ret = rte_eth_tx_queue_setup(port_id, txq_list[iqueue], txd, socketid, NULL);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%u\n", ret, port_id);
    }
}

/*
// Ref: https://doc.dpdk.org/api/rte__ethdev_8h.html#a36ba70a5a6fce2c2c1f774828ba78f8d
        // port_id: Identifier of the Ethernet Device
        // rx_queue_id: The index of the rcv queue to setup
        // nb_rx_desc: Number of rcv descriptors to allocate for the rcv ring
        // socket_id: Socket identifier in case of NUMA, otherwise NULL, ANY
        // rx_conf: pointer to the configuration data to be used for the rcv queue
        // mb_pool:	pointer to the memory pool from which to allocate rte_mbuf network memory 
        //          buffers to populate each descriptor of the rcv ring
        // Return Values:
        //      0 : On Success,
int rte_eth_rx_queue_setup(
    uint16_t 	port_id,
    uint16_t 	rx_queue_id,
    uint16_t 	nb_rx_desc,
    unsigned int 	socket_id,
    const struct rte_eth_rxconf *rx_conf,
    struct rte_mempool *mb_pool 
)	

int rte_eth_tx_queue_setup(
    uint16_t port_id,
    uint16_t 	tx_queue_id,
    uint16_t 	nb_tx_desc,
    unsigned int 	socket_id,
    const struct rte_eth_txconf *tx_conf 
)	

*/