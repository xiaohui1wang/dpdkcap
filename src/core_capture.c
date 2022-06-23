#include <stdbool.h>
#include <signal.h>
#include <string.h>

#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_version.h>

#include "core_capture.h"

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

uint32_t wait_link_up(const struct core_capture_config * config, bool wait) {
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
  return(link.link_speed);
}


/*
 * Capture the traffic from the given port/queue tuple
 */
int capture_core(const struct core_capture_config * config) {
  struct rte_mbuf *bufs[DPDKCAP_CAPTURE_BURST_SIZE];
  uint16_t nb_rx;
  uint32_t linkspeed = 0;
  int nb_rx_enqueued;
  int i;

  /* Init stats */
  *(config->stats) = (struct core_capture_stats) {
    .core_id=rte_lcore_id(),
    .packets = 0,
    .missed_packets = 0,
  };

  linkspeed = wait_link_up(config, false);

  /* Run until the application is quit or killed. */
  for (;;) {
    /* Stop condition */
    if (unlikely(*(config->stop_condition))) {
      break;
    }

    /* Retrieve packets and put them into the ring */
    nb_rx = rte_eth_rx_burst(config->port, config->queue,
        bufs, DPDKCAP_CAPTURE_BURST_SIZE);
    if (unlikely(nb_rx == 0)) {
      rte_delay_us(2);
      linkspeed = wait_link_up(config, true);
      continue;
    } else {
      // TODO add timestamps
#if RTE_VERSION >= RTE_VERSION_NUM(17,5,0,16)
      nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (void*) bufs,
          nb_rx, NULL);
#else
      nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (void*) bufs,
          nb_rx);
#endif

      /* Update stats */
      if(nb_rx_enqueued == nb_rx) {
        config->stats->packets+=nb_rx;
      } else {
        config->stats->missed_packets+=nb_rx;
        /* Free whatever we can't put in the write ring */
        for (i=nb_rx_enqueued; i < nb_rx; i++) {
          rte_pktmbuf_free(bufs[i]);
        }
      }
    }
  }

  RTE_LOG(INFO, DPDKCAP, "Closed capture core %d (port %d)\n",
      rte_lcore_id(), config->port);

  return 0;
}
