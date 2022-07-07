/*
 * Driver interaction with Zephyr WLAN device drivers.
 * Copyright (c) 2022, Nordic Semiconductor
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DRIVER_ZEPHYR_H
#define DRIVER_ZEPHYR_H

#include <net/wifi_mgmt.h>
#include <net/ethernet.h>
#include "driver.h"

struct zep_wpa_supp_mbox_msg_data {
	void *ctx;
	void *data;
	void (*cb)(void *ctx,
		   void *data,
		   int flags);
};


struct zep_drv_ctx {
	void *supp_ctx;
};


struct zep_drv_if_ctx {
	struct zep_drv_ctx *drv_ctx;
	void *supp_if_ctx;
	const struct device *dev_ctx;
	void *dev_priv;

	struct wpa_scan_results *scan_res2;
	bool scan_res2_get_in_prog;

	unsigned int assoc_freq;
	unsigned char ssid[SSID_MAX_LEN];
	size_t ssid_len;
	unsigned char bssid[6];
	bool associated;
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
		       union wpa_event_data *event);

	void (*disassoc)(struct zep_drv_if_ctx *if_ctx,
			 union wpa_event_data *event);
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
			    struct wpa_driver_auth_params *params);
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
};


void wpa_supp_event_handler(void *ctx,
			    void *data,
			    void *cb);
#endif /* DRIVER_ZEPHYR_H */
