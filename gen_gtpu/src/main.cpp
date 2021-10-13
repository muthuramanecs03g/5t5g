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

#include <execinfo.h>

#include "utils.hpp"
#include "gnb_gen.hpp"

////////////////////////////////////
//// Command line config params
////////////////////////////////////
static uint32_t conf_enabled_port_mask  = 0;
static int conf_gpu_device_id           = 0;
static int conf_port_id                 = 0;
static int conf_packet_size             = 1080; // Default, packet size
static int conf_traffic                 = 0;    // Default, Uplink
static uint32_t conf_data_room_size     = DEF_DATA_ROOM_SIZE; // TODO: Adjust to proper value
static int conf_pkt_burst_size          = MAX_MBUFS_BURST;
static int conf_num_pipelines           = NUM_RU;
static int conf_nvprofiler              = 0;
static int conf_num_rx_queue            = (NUM_AP * NUM_GNB);
static int conf_num_tx_queue            = (NUM_AP * NUM_GNB);
static int conf_mempool_cache           = RTE_MEMPOOL_CACHE_MAX_SIZE;
static int conf_nb_mbufs                = DEF_NB_MBUF;
static int conf_nb_rxd                  = DEF_RX_DESC;
static int conf_nb_txd                  = DEF_TX_DESC;
static int conf_iterations              = 1000;

static int acc_send_sched_dynfield_offset = 0;
static int acc_send_sched_dynfield_bitnum = 0;

static uint64_t tx_offset_pkts_ns = 2 * 100 * 1000;
//static uint64_t tx_interval_pkts = MAX_MBUFS_BURST/2;
static uint64_t tx_interval_pkts = MAX_MBUFS_BURST;

static const char short_options[] = 
    "d:" /* Dst Eth Addr */
    "h"	 /* Help */
    "i:" /* Num of Iterations */
    "p:" /* Port Id */
    "b:" /* Size of the packet */
    "t:" /* Traffic either Uplink or Downlink */
;

///////////////////
//// DPDK config
///////////////////
struct rte_ether_addr conf_ports_eth_addr[RTE_MAX_ETHPORTS];
struct rte_ether_addr conf_dst_eth_addr;
struct rte_mempool *cpu_pool_0 = NULL;
struct rte_mempool *cpu_pool_1 = NULL;
struct rte_eth_conf port_eth_conf;

/////////////////////////////////////
//// Inter-threads communication
/////////////////////////////////////
volatile bool force_quit;

///////////////////
//// GNB Objects
///////////////////
GNBGen *ru0;
GNBGen *ru1;

static void setup_accurate_send_scheduling()
{
    static const struct rte_mbuf_dynfield dynfield_desc = {
        RTE_MBUF_DYNFIELD_TIMESTAMP_NAME,
        sizeof(uint64_t),
        .align = __alignof__(uint64_t),
    };

    static const struct rte_mbuf_dynflag dynflag_desc = {
        RTE_MBUF_DYNFLAG_TX_TIMESTAMP_NAME,
    };

    acc_send_sched_dynfield_offset = rte_mbuf_dynfield_register(&dynfield_desc);
    if (acc_send_sched_dynfield_offset < 0 && rte_errno != EEXIST)
        rte_panic("Dynfield registration error: %s\n", rte_strerror(rte_errno));

    acc_send_sched_dynfield_bitnum = rte_mbuf_dynflag_register(&dynflag_desc);
    if (acc_send_sched_dynfield_bitnum < 0 && rte_errno != EEXIST)
        rte_panic("Dynflag registration error: %s\n", rte_strerror(rte_errno));

    printf("Setting accurate send scheduling..\n");
}

///////////////////////
//// Signal Handler
///////////////////////
#define MAX_BACKTRACE 12

static void signal_handler(int signum)
{
    void *array[MAX_BACKTRACE];
    size_t size;
    char **strings;
    size_t i;
    if (signum == SIGINT || signum == SIGTERM || signum == SIGUSR1 ||
        signum == SIGSEGV || signum == SIGHUP || signum == SIGPIPE) {
        printf("\n\nValid signal %d received, preparing to exit...\n", signum);
        size = backtrace(array, MAX_BACKTRACE);
        strings = backtrace_symbols(array, size);
        printf ("Obtained %zd stack frames.\n", size);
        for (i = 0; i < size; i++)
            printf ("%s\n", strings[i]);
        free (strings);

        ACCESS_ONCE(force_quit) = 1;
        abort();
    }
}

////////////////////
//// DPDK TX Cores
////////////////////
static int tx_core(void *arg)
{
    long pipeline_idx = (long)arg;
    GNBGen *ru = ru0;
    int nb_tx = 0, tx_queue = 0;
    struct rte_mbuf *tx_mbufs[MAX_MBUFS_BURST];
    uint64_t start_tx;
    int itxq = 0, prb_size = 48, local_iterations = 0;
    bool infinite_loop = false;

    // if (pipeline_idx == 0)
    //     ru = ru0;
    // else
    //     ru = ru1;

    printf("\n=======> TX CORE %d on RU %ld: %s\n", rte_lcore_id(), pipeline_idx, ru->name);

    start_tx = get_timestamp_ns();

    // Infinite loop with conf_iterations == 0
    if (conf_iterations == 0)
        infinite_loop = true;

    while (ACCESS_ONCE(force_quit) == 0 && ((local_iterations < conf_iterations) || (infinite_loop == true)))
    {
        start_tx += ru->tx_interval_ns;

        if (unlikely(0 != rte_pktmbuf_alloc_bulk(ru->mpool, tx_mbufs, ru->tx_interval_pkts)))
            rte_panic("Ran out of mbufs");

        while (get_timestamp_ns() < start_tx);

        for (int ipkt = 0, iap = 0; ipkt < ru->tx_interval_pkts; ipkt++, iap=(iap + 1) % NUM_AP) {
            struct rte_mbuf *mbuf_pkt = tx_mbufs[ipkt];
            mbuf_pkt->ol_flags = acc_send_sched_dynfield_bitnum;
            *RTE_MBUF_DYNFIELD(mbuf_pkt, acc_send_sched_dynfield_offset, uint64_t *) = start_tx + ru->tx_offset_pkts_ns;
            if (conf_traffic) {
                pkt_hdr_dl_template *data = rte_pktmbuf_mtod(mbuf_pkt, pkt_hdr_dl_template *);
                rte_memcpy(data, &ru->pkt_hdr_dl[iap], sizeof(struct pkt_hdr_dl_template));
                mbuf_pkt->data_len = sizeof(struct pkt_hdr_dl_template);
            } else {
                pkt_hdr_ul_template *data = rte_pktmbuf_mtod(mbuf_pkt, pkt_hdr_ul_template *);
                rte_memcpy(data, &ru->pkt_hdr_ul[iap], sizeof(struct pkt_hdr_ul_template));
                mbuf_pkt->data_len = sizeof(struct pkt_hdr_ul_template);
            }
            mbuf_pkt->pkt_len  = mbuf_pkt->data_len;
        }

        nb_tx = 0;
        while (ACCESS_ONCE(force_quit) == 0 && nb_tx < ru->tx_interval_pkts) {
            nb_tx += rte_eth_tx_burst(ru->port_id, 
                ru->txq_list[tx_queue], 
                &(tx_mbufs[nb_tx]),
                ru->tx_interval_pkts - nb_tx);
        }

        tx_queue = (tx_queue + 1) % NUM_AP;

        // Infinite loop with conf_iterations == 0
        if (infinite_loop == false)
            local_iterations++;
    }

    return 0;
}

/////////////////
//// Input args
/////////////////
unsigned int conf_parse_dst_addr(const char *q_arg)
{
    int index=0;
    char *token, *ctx = NULL, *pEnd, *string = const_cast<char*>(q_arg);
    
    token = strtok_r(string, ":", &ctx);
    while (token != NULL && index < RTE_ETHER_ADDR_LEN) {
        conf_dst_eth_addr.addr_bytes[index] = strtol(token, &pEnd,16);
        pEnd = NULL;
        token = strtok_r(NULL, ":", &ctx);
        index++;
    }

    return 0;
}

unsigned int conf_parse_iterations(const char *q_arg)
{
    char *end = NULL;
    unsigned long n;

    n = strtoul(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return 0;

    return n;
}

unsigned int conf_parse_port_id(const char *q_arg)
{
    char *end = NULL;
    unsigned long n;

    n = strtoul(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return 0;

    return n;
}

unsigned int conf_parse_packet_size(const char *q_arg)
{
    char *end = NULL;
    unsigned long n;

    n = strtoul(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return 1080;

    return n;
}

unsigned int conf_parse_traffic(const char *q_arg)
{
    char *end = NULL;
    unsigned long n;

    n = strtoul(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return 0;

    return n;
}

static int parse_args(int argc, char **argv)
{
    int opt, ret = 0;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    int totDevs;

    argvopt = argv;

    // MAC address of UPF's N3 interface
    conf_dst_eth_addr.addr_bytes[0] = 0x00;
    conf_dst_eth_addr.addr_bytes[1] = 0x00;
    conf_dst_eth_addr.addr_bytes[2] = 0x1e;
    conf_dst_eth_addr.addr_bytes[3] = 0x1e;
    conf_dst_eth_addr.addr_bytes[4] = 0x00;
    conf_dst_eth_addr.addr_bytes[5] = 0x03;

    while ((opt = getopt_long(argc, argvopt, short_options, NULL, &option_index)) != EOF) {
        switch (opt) {
        case 'd':
            conf_parse_dst_addr(optarg);
            break;
        case 'h': 
            usage(prgname);
            return -2;
        case 'i':
            conf_iterations = conf_parse_iterations(optarg);
            break;
        case 0:
            break;
        case 'p':
            conf_port_id = conf_parse_port_id(optarg);
            break;
        case 'b':
            conf_packet_size = conf_parse_packet_size(optarg);
            break;
        case 't':
            conf_traffic = conf_parse_traffic(optarg);
            break;
        default:
            usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 1;

    return ret;
}

////////////
//// Stats
////////////
static void print_stats(void)
{
    struct rte_eth_stats stats;
    int index_queue = 0;

    rte_eth_stats_get(conf_port_id, &stats);

    fflush(stdout);
    printf("TX QUEUES:\n");
    for (index_queue = 0; index_queue < conf_num_tx_queue; index_queue++) {
        printf("\t\tQueue %d: packets = %ld bytes = %ld dropped = %ld\n",
             index_queue, stats.q_opackets[index_queue],
             stats.q_obytes[index_queue], stats.q_errors[index_queue]);
    }
    printf("\nTot TX packets: %lu, Tot Tx bytes: %ld\n", stats.opackets, stats.obytes);
    printf("Total number of failed transmitted packets=%" PRIu64 "\n", stats.oerrors);
    printf("\n====================================================\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct rte_eth_dev_info dev_info;
    uint8_t socketid;
    int ret = 0, index_q, index_queue = 0, secondary_id = 0;
    uint16_t nb_ports;
    unsigned lcore_id;
    long icore = 0;
    uint16_t nb_rxd = DEF_RX_DESC;
    uint16_t nb_txd = DEF_TX_DESC;

    memset(&port_eth_conf, 0, sizeof(struct rte_eth_conf));
    port_eth_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_eth_conf.rxmode.max_rx_pkt_len = conf_data_room_size;
    port_eth_conf.rxmode.split_hdr_size = 0;
    port_eth_conf.rxmode.offloads = 0;
           
    port_eth_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
    port_eth_conf.txmode.offloads = DEV_TX_OFFLOAD_SEND_ON_TIMESTAMP;
          
    port_eth_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_eth_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
    port_eth_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP;

    printf("************ GTP-U - 5G Generator ************\n\n");

    /* ================ PARSE ARGS and INIT PORT ================ */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret == -2)
        rte_exit(EXIT_SUCCESS, "\n");
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid arguments\n");

    /* ================ FORCE QUIT HANDLER ================ */
    ACCESS_ONCE(force_quit) = 0;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGUSR1, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGPIPE, signal_handler);

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    rte_eth_dev_info_get(conf_port_id, &dev_info);
    printf("\nDevice driver name in use: %s... \n", dev_info.driver_name);

    if (strcmp(dev_info.driver_name, "mlx5_pci") != 0)
        rte_exit(EXIT_FAILURE, "Non-Mellanox NICs have not been validated with GTP-U 5G\n");

    //////////////////////////
    //// CPU MEMORY MEMPOOL
    //////////////////////////
    cpu_pool_0 = rte_pktmbuf_pool_create("mbuf_pool_0", 
        conf_nb_mbufs, 
        conf_mempool_cache, 
        0, 
        conf_data_room_size + RTE_PKTMBUF_HEADROOM, 
        rte_socket_id());
    if (cpu_pool_0 == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool 0\n");
    
    // cpu_pool_1 = rte_pktmbuf_pool_create("mbuf_pool_1", 
    //     conf_nb_mbufs, 
    //     conf_mempool_cache, 
    //     0, 
    //     conf_data_room_size + RTE_PKTMBUF_HEADROOM,
    //     rte_socket_id());
    // if (cpu_pool_1 == NULL)
    //     rte_exit(EXIT_FAILURE, "Cannot init mbuf pool 1\n");

    ////////////////////
    //// PORT SETUP
    ////////////////////
    printf("Initializing port %u with %d RX queues and %d TX queues...\n", 
        conf_port_id, conf_num_rx_queue, conf_num_tx_queue);

    ret = rte_eth_dev_configure(conf_port_id, 
        conf_num_rx_queue, 
        conf_num_tx_queue, 
        &port_eth_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
            ret, conf_port_id);

    printf("Port RX offloads: ");
    print_rx_offloads(port_eth_conf.rxmode.offloads);
    printf("\n");
    printf("Port TX offloads: ");
    print_tx_offloads(port_eth_conf.txmode.offloads);
    printf("\n");

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(conf_port_id, &nb_rxd, &nb_txd);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot adjust number of descriptors: err=%d, port=%u\n",
            ret, conf_port_id);
    printf("Number of RX/TX descriptors: %u-%u\n", nb_rxd, nb_txd);

    rte_eth_macaddr_get(conf_port_id, &conf_ports_eth_addr[conf_port_id]);
    printf("Port %d, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
        conf_port_id,
        conf_ports_eth_addr[conf_port_id].addr_bytes[0],
        conf_ports_eth_addr[conf_port_id].addr_bytes[1],
        conf_ports_eth_addr[conf_port_id].addr_bytes[2],
        conf_ports_eth_addr[conf_port_id].addr_bytes[3],
        conf_ports_eth_addr[conf_port_id].addr_bytes[4],
        conf_ports_eth_addr[conf_port_id].addr_bytes[5]
    );

    ///////////////////////////////////////
    //// Accurate Send Scheduling setup
    ///////////////////////////////////////
    setup_accurate_send_scheduling();

    /////////////////////
    //// Configure GNBs
    /////////////////////
    ru0 = new GNBGen(0, 
                    ru0_addr, 
                    ru0_ap[0], 
                    ru0_ap[1], 
                    ru0_ap[2], 
                    ru0_ap[3], 
                    ru0_vlan, 
                    conf_port_id, 
                    nb_rxd, 
                    nb_txd, 
                    cpu_pool_0, 
                    conf_dst_eth_addr, 
                    0, 
                    tx_offset_pkts_ns, 
                    tx_interval_pkts);
    ru0->setupQueues();

    // ru1 = new GNBGen(1, 
    //                 ru1_addr, 
    //                 ru1_ap[0], 
    //                 ru1_ap[1],
    //                 ru1_ap[2], 
    //                 ru1_ap[3], 
    //                 ru1_vlan, 
    //                 conf_port_id, 
    //                 nb_rxd, nb_txd, 
    //                 cpu_pool_1, 
    //                 conf_dst_eth_addr, 
    //                 1, 
    //                 tx_offset_pkts_ns, 
    //                 tx_interval_pkts);
    // ru1->setupQueues();

    ////////////////////
    //// START DEVICE
    ////////////////////
    ret = rte_eth_dev_start(conf_port_id);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, conf_port_id);

    check_all_ports_link_status(conf_enabled_port_mask);

    printf("Size of the Packet: %u\n", conf_packet_size);
    uint32_t bytes_per_pkt = conf_packet_size;
    uint32_t bytes_per_interval_0 = ru0->tx_interval_pkts * bytes_per_pkt;
    float mbytes_per_sec_0 = ((float) bytes_per_interval_0) / ru0->tx_interval_s / 1000000.0;
    float gbits_per_sec_0 = mbytes_per_sec_0 * 8 / 1000.0;
    printf("%s Estimated pkts %d data %dB Interval S %f data rate %f MB/s -> %f Gbps\n",
        ru0->name,
        ru0->tx_interval_pkts,
        bytes_per_pkt,
        ru0->tx_interval_s,
        mbytes_per_sec_0,
        gbits_per_sec_0);

    // uint32_t bytes_per_interval_1 = ru1->tx_interval_pkts * bytes_per_pkt;
    // float mbytes_per_sec_1 = ((float)bytes_per_interval_1) / ru1->tx_interval_s / 1000000.0;
    // float gbits_per_sec_1 = mbytes_per_sec_1 * 8 / 1000.0;
    // printf("%s Estimated pkts %d data %dB Interval S %f data rate %f MB/s -> %f Gbps\n", 	
    //     ru1->name,
    //     ru1->tx_interval_pkts,
    //     bytes_per_pkt,
    //     ru1->tx_interval_s,
    //     mbytes_per_sec_1,
    //     gbits_per_sec_1);

    /////////////////////////
    //// START RX/TX CORES
    /////////////////////////
    for (icore = 0; icore < conf_num_pipelines; icore++) {
        secondary_id = rte_get_next_lcore(secondary_id, 1, 0);
        rte_eal_remote_launch(tx_core, (void *)icore, secondary_id);
    }

    ///////////////////////
    //// WAIT RX/TX CORES
    ///////////////////////
    icore = 0;
    RTE_LCORE_FOREACH_WORKER(icore) {
        if (rte_eal_wait_lcore(icore) < 0) {
            fprintf(stderr, "bad exit for coreid: %ld\n",
                icore);
            break;
        }
    }

    ///////////////////
    //// Print stats
    ///////////////////
    print_stats();

    ////////////////////////////////
    //// Close network device
    ////////////////////////////////
    printf("Closing port %d...", conf_port_id);
    rte_eth_dev_stop(conf_port_id);
    rte_eth_dev_close(conf_port_id);
    printf(" Done. Bye!\n");

    return 0;
}
