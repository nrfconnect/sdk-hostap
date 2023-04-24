/*
 * Driver interaction with Zephyr WLAN device drivers.
 * Copyright (c) 2022, Nordic Semiconductor
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DRIVER_ZEPHYR_H
#define DRIVER_ZEPHYR_H

#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/ethernet.h>

#include "driver.h"
#include "wpa_supplicant_i.h"
#include "bss.h"

#define __WPA_SUPP_PKD __attribute__((__packed__))

struct wpa_supp_event_channel {
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_IR (1 << 0)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_IBSS (1 << 1)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_RADAR (1 << 2)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_HT40_MINUS (1 << 3)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_HT40_PLUS (1 << 4)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_80MHZ (1 << 5)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_160MHZ (1 << 6)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_INDOOR_ONLY (1 << 7)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_GO_CONCURRENT (1 << 8)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_20MHZ (1 << 9)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_10MHZ (1 << 10)
#define WPA_SUPP_CHAN_FLAG_FREQUENCY_DISABLED (1 << 11)

#define WPA_SUPP_CHAN_DFS_VALID (1 << 12)
#define WPA_SUPP_CHAN_DFS_CAC_TIME_VALID (1 << 13)
	unsigned short wpa_supp_flags;
	signed int wpa_supp_max_power;
	unsigned int wpa_supp_time;
	unsigned int dfs_cac_msec;
	signed char ch_valid;
	unsigned short center_frequency;
	signed char dfs_state;
} __WPA_SUPP_PKD;

struct wpa_supp_event_rate {
#define WPA_SUPP_EVENT_GET_WIPHY_FLAG_RATE_SHORT_PREAMBLE (1 << 0)
	unsigned short wpa_supp_flags;
	unsigned short wpa_supp_bitrate;
} __WPA_SUPP_PKD;

struct wpa_supp_event_mcs_info {
#define WPA_SUPP_HT_MCS_MASK_LEN 10
#define WPA_SUPP_HT_MCS_RES_LEN 3
	unsigned short wpa_supp_rx_highest;
	unsigned char wpa_supp_rx_mask[WPA_SUPP_HT_MCS_MASK_LEN];
	unsigned char wpa_supp_tx_params;
	unsigned char wpa_supp_reserved[WPA_SUPP_HT_MCS_RES_LEN];
} __WPA_SUPP_PKD;

struct wpa_supp_event_sta_ht_cap {
	signed int wpa_supp_ht_supported;
	unsigned short wpa_supp_cap;
	struct wpa_supp_event_mcs_info mcs;
#define WPA_SUPP_AMPDU_FACTOR_MASK 0x03
#define WPA_SUPP_AMPDU_DENSITY_SHIFT 2
	unsigned char wpa_supp_ampdu_factor;
	unsigned char wpa_supp_ampdu_density;
} __WPA_SUPP_PKD;

struct wpa_supp_event_vht_mcs_info {
	unsigned short rx_mcs_map;
	unsigned short rx_highest;
	unsigned short tx_mcs_map;
	unsigned short tx_highest;
} __WPA_SUPP_PKD;

struct wpa_supp_event_sta_vht_cap {
	signed char wpa_supp_vht_supported;
	unsigned int wpa_supp_cap;
	struct wpa_supp_event_vht_mcs_info vht_mcs;
} __WPA_SUPP_PKD;

struct wpa_supp_event_supported_band {
	unsigned short wpa_supp_n_channels;
	unsigned short wpa_supp_n_bitrates;
#define WPA_SUPP_SBAND_MAX_CHANNELS 29
#define WPA_SUPP_SBAND_MAX_RATES 13
	struct wpa_supp_event_channel channels[WPA_SUPP_SBAND_MAX_CHANNELS];
	struct wpa_supp_event_rate bitrates[WPA_SUPP_SBAND_MAX_RATES];
	struct wpa_supp_event_sta_ht_cap ht_cap;
	struct wpa_supp_event_sta_vht_cap vht_cap;
	signed char band;
} __WPA_SUPP_PKD;

struct wpa_bss;

struct zep_wpa_supp_mbox_msg_data {
	void *ctx;
	enum wpa_event_type event;
	void *data;
};


struct zep_drv_ctx {
	void *supp_ctx;
};


struct zep_drv_if_ctx {
	struct zep_drv_ctx *drv_ctx;
	void *supp_if_ctx;
	const struct device *dev_ctx;
	void *dev_priv;
	struct k_sem drv_resp_sem;

	struct wpa_scan_results *scan_res2;
	bool scan_res2_get_in_prog;

	unsigned int assoc_freq;
	unsigned char ssid[SSID_MAX_LEN];
	size_t ssid_len;
	unsigned char bssid[6];
	bool associated;

	void *phy_info_arg;
	struct wpa_driver_capa capa;

	unsigned char prev_bssid[6];
	unsigned char auth_bssid[6];
	unsigned char auth_attempt_bssid[6];
};


struct zep_wpa_supp_dev_callbk_fns {
	void (*scan_start)(struct zep_drv_if_ctx *if_ctx);

	void (*scan_done)(struct zep_drv_if_ctx *if_ctx,
			  union wpa_event_data *event);

	void (*scan_res)(struct zep_drv_if_ctx *if_ctx, struct wpa_scan_res *r,
			 bool more_res);

	void (*auth_resp)(struct zep_drv_if_ctx *if_ctx,
			  union wpa_event_data *event);

	void (*assoc_resp)(struct zep_drv_if_ctx *if_ctx,
			   union wpa_event_data *event, unsigned int status);

	void (*deauth)(struct zep_drv_if_ctx *if_ctx,
		       union wpa_event_data *event, const struct ieee80211_mgmt *mgmt);

	void (*disassoc)(struct zep_drv_if_ctx *if_ctx,
			 union wpa_event_data *event);

	void (*mgmt_tx_status)(struct zep_drv_if_ctx *if_ctx,
			const u8 *frame, size_t len, bool ack);

	void (*unprot_deauth)(struct zep_drv_if_ctx *if_ctx,
			      union wpa_event_data *event);

	void (*unprot_disassoc)(struct zep_drv_if_ctx *if_ctx,
				union wpa_event_data *event);

	void (*get_wiphy_res)(struct zep_drv_if_ctx *if_ctx,
				void *band);

	void (*mgmt_rx)(struct zep_drv_if_ctx *if_ctx,
			char *frame, int frame_len, int frequency, int rx_signal_dbm);

	void (*mac_changed)(struct zep_drv_if_ctx *if_ctx);
};


struct zep_wpa_supp_dev_ops {
	void *(*init)(void *supp_drv_if_ctx,
		      const char *iface_name,
		      struct zep_wpa_supp_dev_callbk_fns *callbk_fns);
	void (*deinit)(void *if_priv);
	int (*scan2)(void *if_priv,
		     struct wpa_driver_scan_params *params);
	int (*scan_abort)(void *if_priv);
	int (*get_scan_results2)(void *if_priv);
	int (*deauthenticate)(void *if_priv,
			      const char *addr,
			      unsigned short reason_code);
	int (*authenticate)(void *if_priv,
			    struct wpa_driver_auth_params *params,
			    struct wpa_bss *curr_bss);
	int (*associate)(void *if_priv,
			 struct wpa_driver_associate_params *params);
	int (*set_key)(void *if_priv,
		       const unsigned char *ifname,
		       enum wpa_alg alg,
		       const unsigned char *addr,
		       int key_idx,
		       int set_tx,
		       const unsigned char *seq,
		       size_t seq_len,
		       const unsigned char *key,
		       size_t key_len);
	int (*set_supp_port)(void *if_priv,
			     int authorized,
			     char *bssid);
	int (*signal_poll)(void *if_priv, struct wpa_signal_info *si,
			   unsigned char *bssid);
	int (*send_mlme)(void *if_priv, const u8 *data,
			size_t data_len, int noack,
			unsigned int freq, int no_cck,
			int offchanok,
			unsigned int wait_time,
			int cookie);
	int (*get_wiphy)(void *if_priv);

	int (*register_frame)(void *if_priv,
			u16 type, const u8 *match, size_t match_len,
			bool multicast);

	int (*get_capa)(void *if_priv,
			struct wpa_driver_capa *capa);

	int (*get_conn_info)(void *if_priv,
			struct wpa_conn_info *info);
};

#endif /* DRIVER_ZEPHYR_H */
