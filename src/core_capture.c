#include "core_capture.h"

#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_version.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <regex.h>

#include "pcap.h"
#include "timestamp.h"

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

struct packet_info {
    char src_mac[18];
    char dst_mac[18];
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t protocol_l3;
    uint16_t protocol_l4;
};

void extract_packet_info(struct rte_mbuf *mbuf, struct packet_info *info);
int check_rules(struct packet_info *info);

int compile_regex(regex_t *regex, const char *pattern);
int match_with_precompiled_regex(const regex_t *regex, const char *str);
void free_regex(regex_t *regex);

uint32_t wait_link_up(const struct core_capture_config *config, bool wait) {
    struct rte_eth_link link;

    if (wait) {
        rte_eth_link_get(config->port, &link);
    } else {
        rte_eth_link_get_nowait(config->port, &link);
    }
    if (link.link_status != RTE_ETH_LINK_UP) {
        while (link.link_status != RTE_ETH_LINK_UP) {
            RTE_LOG(INFO, DPDKCAP, "Capture core %u waiting for port %u to come up\n",
                    rte_lcore_id(), config->port);
            rte_eth_link_get(config->port, &link);
        }

        RTE_LOG(INFO, DPDKCAP, "Core %u is capturing packets for port %u at %u Mbps\n",
                rte_lcore_id(), config->port, link.link_speed);
    }
    return (link.link_speed);
}

/*
 * Capture the traffic from the given port/queue tuple
 */
int capture_core(const struct core_capture_config *config) {
    struct rte_mbuf *bufs[DPDKCAP_CAPTURE_BURST_SIZE];
    uint16_t nb_rx;
    long int total_nb_rx = 0;
    uint32_t linkspeed = 0;
    struct timeval tv;
    uint64_t tvns;
    int nb_rx_enqueued;
    long int total_nb_rx_enqueued = 0;
    int i;

    /* Init stats */
    *(config->stats) = (struct core_capture_stats){
        .core_id = rte_lcore_id(),
        .packets = 0,
        .missed_packets = 0,
    };

    linkspeed = wait_link_up(config, true);

    /* Run until the application is quit or killed. */
    for (;;) {
        /* Stop condition */
        if (unlikely(*(config->stop_condition))) {
            break;
        }

        /* get timestamp, convert to ns */
        // gettimeofday(&tv, NULL);
        // tvns = (tv.tv_sec * NSEC_PER_SEC) + (tv.tv_usec * 1000);

        /* Retrieve packets and put them into the ring */
        nb_rx = rte_eth_rx_burst(config->port, config->queue, bufs, DPDKCAP_CAPTURE_BURST_SIZE);

        if (unlikely(nb_rx == 0)) {
            rte_delay_us(1);
            continue;
        }

        // Checkpoint 1: only calculate received packets number.
        // total_nb_rx = total_nb_rx + nb_rx;
        rte_pktmbuf_free_bulk(bufs, nb_rx);
        continue;

        if (unlikely(nb_rx == 0)) {
            rte_delay_us(2);
            linkspeed = wait_link_up(config, false);
            continue;
        } else {
            /* add timestamps to mbufs */
            for (i = 0; i < nb_rx; i++) {
                *timestamp_field(bufs[i]) = tvns;
            }
#if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 16)
            nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (void *)bufs, nb_rx, NULL);
#else
            nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (void *)bufs, nb_rx);
#endif

            total_nb_rx_enqueued += nb_rx_enqueued;

            /* Update stats */
            if (nb_rx_enqueued == nb_rx) {
                config->stats->packets += nb_rx;
            } else {
                printf("ERROR: Cannot enqueue!\n");
                config->stats->missed_packets += nb_rx;
                /* Free whatever we can't put in the write ring */
                for (i = nb_rx_enqueued; i < nb_rx; i++) {
                    rte_pktmbuf_free(bufs[i]);
                }
            }
        }
    }

    printf("total_nb_rx-%d:%ld\n", rte_lcore_id(), total_nb_rx);
    printf("total_nb_rx_enqueued-%d:%ld\n", rte_lcore_id(), total_nb_rx_enqueued);

    RTE_LOG(INFO, DPDKCAP, "Closed capture core %d (port %d)\n", rte_lcore_id(), config->port);

    return 0;
}

/*
 * Write into a pcap file
 */
static int write_file2(FILE *file, void *src, size_t len) {
    size_t retval = 0;
    return retval;
}

static FILE *open_file(char *output_file) {
    FILE *file;
    // Open file
    file = fopen(output_file, "w");
    if (unlikely(!file)) {
        RTE_LOG(ERR, DPDKCAP, "Core %d could not open '%s' in write mode: %d (%s)\n",
                rte_lcore_id(), output_file, errno, strerror(errno));
    }

    return file;
}

static int write_file(FILE *file, void *src, size_t len) {
    size_t retval;
    // Write file
    retval = fwrite(src, 1, len, file);
    if (unlikely(retval != len)) {
        RTE_LOG(ERR, DPDKCAP, "Could not write into file: %d (%s)\n", errno, strerror(errno));
        return -1;
    }
    return retval;
}

static int close_file(FILE *file) {
    int retval;
    // Close file
    retval = fclose(file);
    if (unlikely(retval)) {
        RTE_LOG(ERR, DPDKCAP, "Could not close file: %d (%s)\n", errno, strerror(errno));
    }
    return retval;
}

/*
 * Capture the traffic from the given port/queue tuple
 */
int capture_core2(const struct core_capture_config *config) {
    struct rte_mbuf *bufs[DPDKCAP_CAPTURE_BURST_SIZE];
    uint16_t nb_rx = 0;
    long int total_nb_rx = 0;
    uint32_t linkspeed = 0;
    struct timeval tv;
    struct timeval pcap_pre_tv;
    uint64_t tvns;
    int i;
    int written;
    int retval = 0;
    unsigned int packet_length, wire_packet_length, compressed_length, remaining_bytes;
    int packet_header_length = 0;
    int bytes_to_write;
    long int pcap_offset = 0;
    long int pcap_file_size = 0;

    void *(*file_open_pcap_func)(char *);
    int (*file_write_pcap_func)(void *, void *, int);
    int (*file_close_pcap_func)(void *);

    void *(*file_open_metadata_func)(char *);
    int (*file_write_metadata_func)(void *, void *, int);
    int (*file_close_metadata_func)(void *);

    void *output_buffer = NULL;
    struct pcap_packet_header header;
    void *metadata_buffer;

    struct rte_mbuf *bufptr;
    struct pcap_header pcp;

    char output_filename[1024];
    char metadata_filename[1024];

    regex_t src_mac_regex;
    regex_t dst_mac_regex;
    regex_t src_ip_regex;
    regex_t dst_ip_regex;

    /* Init stats */
    *(config->stats) = (struct core_capture_stats){
        .core_id = rte_lcore_id(),
        .packets = 0,
        .missed_packets = 0,
    };

    linkspeed = wait_link_up(config, true);

    RTE_LOG(INFO, DPDKCAP, "Config queue id is: %d (lcore: %d)\n", config->queue, rte_lcore_id());

    // If not delay, may cause below issue.
    // ETHDEV: lcore 56 called rx_pkt_burst for not ready port 0
    // DPDKCAP: Config queue id is: 6 (lcore: 62)
    // 0: /usr/local/lib/x86_64-linux-gnu/librte_eal.so.24 (rte_dump_stack+0x42) [7f7563bc93f2]
    // 1: /usr/local/lib/x86_64-linux-gnu/librte_ethdev.so.24 (7f7563cb5000+0xc407) [7f7563cc1407]
    // 2: ./build/dpdkcap-shared (55a74ea51000+0x7081) [55a74ea58081]
    // 3: /usr/local/lib/x86_64-linux-gnu/librte_eal.so.24 (7f7563b91000+0x27be6) [7f7563bb8be6]
    // 4: /usr/local/lib/x86_64-linux-gnu/librte_eal.so.24 (7f7563b91000+0x39c4f) [7f7563bcac4f]
    // 5: /lib/x86_64-linux-gnu/libc.so.6 (7f7563912000+0x94ac3) [7f75639a6ac3]
    // 6: /lib/x86_64-linux-gnu/libc.so.6 (7f7563912000+0x126850) [7f7563a38850]
    // DPDKCAP: After delay 5s (lcore: 61)

    // Delay what?
    // rte_delay_us(10000);
    usleep(2000000);  // 2s

    // Compile src_mac_regex
    // if (compile_regex(&src_mac_regex, "^50:a6:b7:97:23:.*")) {
    if (compile_regex(&src_mac_regex, ".*")) {
        RTE_LOG(WARNING, DPDKCAP, "Failed to compile src_mac_regex (lcore: %d)\n", rte_lcore_id());
    }

    RTE_LOG(INFO, DPDKCAP, "After delay 2s (lcore: %d)\n", rte_lcore_id());

    /* Run until the application is quit or killed. */
    for (;;) {
        /* Stop condition */
        if (unlikely(*(config->stop_condition))) {
            break;
        }

        nb_rx = rte_eth_rx_burst(config->port, config->queue, bufs, DPDKCAP_CAPTURE_BURST_SIZE);

        if (unlikely(nb_rx == 0)) {
            // Note: If delay here, may increase drop rate. But if not delay here, may cause line
            // 226 issue above. ETHDEV: lcore 56 called rx_pkt_burst for not ready port 0
            // rte_delay_us(1);
            // linkspeed = wait_link_up(config, false);
            continue;
        }

        // Checkpoint 1: only calculate received packets number.
        total_nb_rx = total_nb_rx + (long int)nb_rx;
        // rte_pktmbuf_free_bulk(bufs, nb_rx);
        // continue;

        /* get timestamp, convert to ns */
        // gettimeofday(&tv, NULL);
        // tvns = (tv.tv_sec * NSEC_PER_SEC) + (tv.tv_usec * 1000);

        /* add timestamps to mbufs */
        // for (i = 0; i < nb_rx; i++) {
        //    *timestamp_field(bufs[i]) = tvns;
        // }

        // Not invoke fwrite to write packet.
        // file_write_pcap_func =
        //	(int (*)(void *, void *, int))write_file2;

        file_open_pcap_func = (void *(*)(char *))open_file;
        file_write_pcap_func = (int (*)(void *, void *, int))write_file;
        file_close_pcap_func = (int (*)(void *))close_file;

        file_open_metadata_func = (void *(*)(char *))open_file;
        file_write_metadata_func = (int (*)(void *, void *, int))write_file;
        file_close_metadata_func = (int (*)(void *))close_file;

        for (i = 0; i < nb_rx; i++) {
            bufptr = bufs[i];

            // 1: Extract pkt
            struct packet_info pkt_info;
            extract_packet_info(bufptr, &pkt_info);

            // 2: Check rule, continue if not match
            int result = check_rules(&pkt_info);
            if (result != 0) {
                continue;  // Not match rule, ignore this packet
            }

            gettimeofday(&tv, NULL);
            tvns = (tv.tv_sec * NSEC_PER_SEC) + (tv.tv_usec * 1000);
            *timestamp_field(bufptr) = tvns;

            // PCAP rotate by time
            if (output_buffer != NULL && (tv.tv_sec - pcap_pre_tv.tv_sec) >= 60 * 5) {
                close_file(output_buffer);
                output_buffer = NULL;
            }

            // // PCAP rotete by file size
            if (output_buffer != NULL && pcap_file_size >= 1073741824L * 64) {
                file_close_pcap_func(output_buffer);
                output_buffer = NULL;
            }

            // Open new file
            if (output_buffer == NULL) {
                pcap_pre_tv.tv_sec = tv.tv_sec;
                sprintf(output_filename, "/mnt/test/output_file_%d_%ld.pcap", rte_lcore_id(),
                        tv.tv_sec);

                // Reopen a file
                output_buffer = file_open_pcap_func(output_filename);
                if (unlikely(!output_buffer)) {
                    RTE_LOG(WARNING, DPDKCAP, "Core %d open(%s) failed.\n", rte_lcore_id(),
                            output_filename);
                    break;
                } else {
                    RTE_LOG(WARNING, DPDKCAP, "Core %d open(%s) succeed.\n", rte_lcore_id(),
                            output_filename);
                }
                // Init the common pcap header
                pcap_header_init(&pcp, PCAP_SNAPLEN_DEFAULT);

                // Write pcap header
                written = file_write_pcap_func(output_buffer, &pcp, sizeof(struct pcap_header));
                if (unlikely(written < 0)) {
                    retval = -1;
                    goto cleanup;
                }
                pcap_offset = written;
                pcap_file_size = written;
            }

            if (metadata_buffer == NULL) {
                sprintf(metadata_filename, "/mnt/test/output_file_%d.csv", rte_lcore_id());
                metadata_buffer = file_open_metadata_func(metadata_filename);
                if (unlikely(!metadata_buffer)) {
                    RTE_LOG(WARNING, DPDKCAP, "Core %d open(%s) failed.\n", rte_lcore_id(),
                            metadata_filename);
                    break;
                } else {
                    RTE_LOG(WARNING, DPDKCAP, "Core %d open(%s) succeed.\n", rte_lcore_id(),
                            metadata_filename);
                }
            }

            wire_packet_length = rte_pktmbuf_pkt_len(bufptr);
            packet_length = wire_packet_length;

            // Write block header
            // TODO get better packet timestamps
            header.timestamp = (int32_t)tv.tv_sec;
            header.microseconds = (int32_t)tv.tv_usec;
            header.packet_length = packet_length;
            header.packet_length_wire = wire_packet_length;
            packet_header_length =
                file_write_pcap_func(output_buffer, &header, sizeof(struct pcap_packet_header));
            if (unlikely(packet_header_length < 0)) {
                retval = -1;
                goto cleanup;
            }
            pcap_file_size += packet_header_length;

            // Write content
            remaining_bytes = packet_length;
            compressed_length = 0;
            while (bufptr != NULL && remaining_bytes > 0) {
                bytes_to_write = MIN(rte_pktmbuf_data_len(bufptr), remaining_bytes);
                written = file_write_pcap_func(output_buffer, rte_pktmbuf_mtod(bufptr, void *),
                                               bytes_to_write);
                if (unlikely(written < 0)) {
                    retval = -1;
                    goto cleanup;
                }
                bufptr = bufptr->next;
                remaining_bytes -= bytes_to_write;
                compressed_length += written;
            }
            pcap_file_size += packet_length;

            // Write metadata
            // uuid_t packet_uuid;
            // char uuid_str[37];
            // uuid_generate_random(packet_uuid);
            // uuid_unparse(packet_uuid, uuid_str);

            fprintf(metadata_buffer, "%ld.%ld,%s,%s,%s,%s,%u,%u,%d,%d,%d,%ld\n", tv.tv_sec,
                    tv.tv_usec, pkt_info.src_mac, pkt_info.dst_mac, pkt_info.src_ip,
                    pkt_info.dst_ip, pkt_info.src_port, pkt_info.dst_port, pkt_info.protocol_l3,
                    pkt_info.protocol_l4, packet_length, pcap_offset);

            // char buffer[256];
            // int len =
            //     snprintf(buffer, sizeof(buffer), "%ld.%ld,%s,%s,%s,%s,%u,%u,%d,%d,%ld\n",
            //              tv.tv_sec, tv.tv_usec, pkt_info.src_mac, pkt_info.dst_mac, pkt_info.src_ip,
            //              pkt_info.dst_ip, pkt_info.src_port, pkt_info.dst_port,
            //              pkt_info.protocol_l3, pkt_info.protocol_l4, pcap_offset);
            //ssize_t written = file_write_metadata_func(metadata_buffer, buffer, len);
            // if (written < 0) {
            //     perror("write");
            //     close(fd);
            //     return 1;
            // }

            //fprintf(metadata_buffer, "1721916374.774767,50:a6:b7:97:23:53,40:a6:b7:97:23:53,192.168.1.44,192.168.2.44,30043,40043,2048,6,7674\n");

            pcap_offset += (packet_header_length + packet_length);
        }

        rte_pktmbuf_free_bulk(bufs, nb_rx);
    }

cleanup:
    // Close pcap file
    if (output_buffer) {
        // file_close_pcap_func = (int (*)(void *))close_file;
        file_close_pcap_func(output_buffer);
        output_buffer = NULL;
    }
    // Close metadata file
    if (metadata_buffer) {
        // file_close_metadata_func = (int (*)(void *))close_file;
        file_close_metadata_func(metadata_buffer);
        metadata_buffer = NULL;
    }

    free_regex(&src_mac_regex);

    printf("total_nb_rx-%d:%ld\n", rte_lcore_id(), total_nb_rx);

    RTE_LOG(INFO, DPDKCAP, "Closed capture core %d (port %d)\n", rte_lcore_id(), config->port);

    return 0;
}

void extract_packet_info(struct rte_mbuf *mbuf, struct packet_info *info) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;

    info->src_port = 0;
    info->dst_port = 0;
    info->protocol_l3 = 0;
    info->protocol_l4 = 0;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    info->protocol_l3 = rte_be_to_cpu_16(eth_hdr->ether_type);
    // rte_memcpy(info->src_mac, eth_hdr->src_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
    // rte_memcpy(info->dst_mac, eth_hdr->dst_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

    snprintf(info->src_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->src_addr.addr_bytes[0],
             eth_hdr->src_addr.addr_bytes[1], eth_hdr->src_addr.addr_bytes[2],
             eth_hdr->src_addr.addr_bytes[3], eth_hdr->src_addr.addr_bytes[4],
             eth_hdr->src_addr.addr_bytes[5]);
    snprintf(info->dst_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->dst_addr.addr_bytes[0],
             eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2],
             eth_hdr->dst_addr.addr_bytes[3], eth_hdr->dst_addr.addr_bytes[4],
             eth_hdr->dst_addr.addr_bytes[5]);

    if (info->protocol_l3 == RTE_ETHER_TYPE_IPV4) {
        ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

        inet_ntop(AF_INET, &ipv4_hdr->src_addr, info->src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ipv4_hdr->dst_addr, info->dst_ip, INET_ADDRSTRLEN);

        info->protocol_l4 = ipv4_hdr->next_proto_id;

        if (info->protocol_l4 == IPPROTO_TCP) {
            tcp_hdr =
                (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr +
                                       ((ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) << 2));
            info->src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
            info->dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        } else if (info->protocol_l4 == IPPROTO_UDP) {
            udp_hdr =
                (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr +
                                       ((ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) << 2));
            info->src_port = rte_be_to_cpu_16(udp_hdr->src_port);
            info->dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
        }
    }
}

int check_rules(struct packet_info *info) {
    // if (info->dst_port != 40000) {
    //     return -1;
    // }

    // Check src MAC address
    // if (match_with_precompiled_regex(&src_mac_regex, info->src_mac)) {
    //    return -1;
    // }

    return 0; 
}

// 对于端口和协议，你需要将它们转换为字符串，然后再进行匹配
// int match_src_port(struct packet_info* packet, const char* pattern) {
//     char port_str[6]; // 端口号最大为65535，所以5个字符足够了
//     sprintf(port_str, "%u", ntohs(packet->src_port));
//     return match_regex(port_str, pattern);
// }

// Based on POSIX
int compile_regex(regex_t *regex, const char *pattern) {
    return regcomp(regex, pattern, REG_EXTENDED);
}

int match_with_precompiled_regex(const regex_t *regex, const char *string) {
    return regexec(regex, string, 0, NULL, 0);
}

void free_regex(regex_t *regex) {
    regfree(regex);
}