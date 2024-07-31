#ifndef DPDKCAP_CORE_CAPTURE_H
#define DPDKCAP_CORE_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>

// #define DPDKCAP_CAPTURE_BURST_SIZE 256
#define DPDKCAP_CAPTURE_BURST_SIZE 4096

/* Core configuration structures */
struct core_capture_config {
	struct rte_ring *ring;
	bool volatile *stop_condition;
	struct core_capture_stats *stats;
	uint8_t port;
	uint8_t queue;
    uint8_t queues;
};

/* Statistics structure */
struct core_capture_stats {
	int core_id;
	uint64_t packets;	//Packets successfully enqueued
	uint64_t missed_packets;	//Packets core could not enqueue
};

/* Launches a capture task */
int capture_core(const struct core_capture_config *config);

/* Launches a capture task */
int capture_core2(const struct core_capture_config *config);

int capture_core3(const struct core_capture_config *config);

#endif
