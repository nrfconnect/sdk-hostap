/*
 * Driver interaction with Zephyr WLAN device drivers.
 * Copyright (c) 2022, Nordic Semiconductor
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "includes.h"
#include "utils/common.h"
#include "eloop.h"
#include "driver_zephyr.h"

K_MBOX_DEFINE(wpa_supp_mbox);
#define SCAN_TIMEOUT 30

static void wpa_supp_drv_mbox_msg_handler(void *eloop_ctx,
					  void *timeout_ctx)
{
	struct k_mbox_msg msg;
	struct zep_wpa_supp_mbox_msg_data mbox_msg_data;

	/* Prepare to receive message */
	msg.size = sizeof(mbox_msg_data);
	msg.rx_source_thread = K_ANY;

	k_mbox_get(&wpa_supp_mbox,
		   &msg,
		   &mbox_msg_data,
		   K_FOREVER);

	mbox_msg_data.cb(mbox_msg_data.ctx,
			 mbox_msg_data.data,
			 0);
}


void wpa_supp_event_handler(void *ctx,
			    void *data,
			    void *cb)
{
	struct k_mbox_msg send_msg;
	struct zep_wpa_supp_mbox_msg_data mbox_msg_data;

	mbox_msg_data.ctx = ctx;
	mbox_msg_data.data = data;
	mbox_msg_data.cb = cb;

	/* Prepare to send message */
	send_msg.size = sizeof(mbox_msg_data);
	send_msg.tx_data = &mbox_msg_data;
	send_msg.tx_block.data = NULL;
	send_msg.tx_target_thread = K_ANY;

	eloop_register_timeout(0,
			       500,
			       wpa_supp_drv_mbox_msg_handler,
			       NULL,
			       NULL);

	k_mbox_put(&wpa_supp_mbox,
		   &send_msg,
		   K_FOREVER);
}


static int wpa_drv_zep_abort_scan(void *priv,
				  u64 scan_cookie)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->scan_abort) {
		wpa_printf(MSG_ERROR,
			   "%s: No op registered for scan_abort\n",
			   __func__);
		goto out;
	}

	ret = dev_ops->scan_abort(if_ctx->dev_priv);
out:
	return ret;
}


/**
 * wpa_drv_zep_scan_timeout - Scan timeout to report scan completion
 * @eloop_ctx: Driver private data
 * @timeout_ctx: ctx argument given to wpa_drv_zep_init()
 *
 * This function can be used as registered timeout when starting a scan to
 * generate a scan completed event if the driver does not report this.
 */
void wpa_drv_zep_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct zep_drv_if_ctx *if_ctx = NULL;

	if_ctx = eloop_ctx;

	wpa_printf(MSG_ERROR,
		   "%s: Scan timeout - try to abort it\n",
		   __func__);

	if (wpa_drv_zep_abort_scan(if_ctx, 0) == 0) {
		return;
	}
}


void wpa_drv_zep_event_proc_scan_start(struct zep_drv_if_ctx *if_ctx)
{
	wpa_supplicant_event(if_ctx->supp_if_ctx,
			     EVENT_SCAN_STARTED,
			     NULL);
}


void wpa_drv_zep_event_proc_scan_done(struct zep_drv_if_ctx *if_ctx,
				      union wpa_event_data *event)
{
	eloop_cancel_timeout(wpa_drv_zep_scan_timeout,
			     if_ctx,
			     if_ctx->supp_if_ctx);

	wpa_supplicant_event(if_ctx->supp_if_ctx,
			     EVENT_SCAN_RESULTS,
			     event);
}


void wpa_drv_zep_event_proc_scan_res(struct zep_drv_if_ctx *if_ctx,
				     struct wpa_scan_res *r,
				     bool more_res)
{
	struct wpa_scan_res **tmp = NULL;

	tmp = os_realloc_array(if_ctx->scan_res2->res,
			       if_ctx->scan_res2->num + 1,
			       sizeof(struct wpa_scan_res *));

	if (!tmp) {
		os_free(r);
		return;
	}

	tmp[if_ctx->scan_res2->num++] = r;

	if_ctx->scan_res2->res = tmp;

	if_ctx->scan_res2_get_in_prog = more_res;
}


void wpa_drv_zep_event_proc_auth_resp(struct zep_drv_if_ctx *if_ctx,
				      union wpa_event_data *event)
{
	wpa_supplicant_event(if_ctx->supp_if_ctx,
			     EVENT_AUTH,
			     event);
}


void wpa_drv_zep_event_proc_assoc_resp(struct zep_drv_if_ctx *if_ctx,
				       union wpa_event_data *event,
				       unsigned int status)
{
	if (status != WLAN_STATUS_SUCCESS) {
		wpa_supplicant_event(if_ctx->supp_if_ctx,
				     EVENT_ASSOC_REJECT,
				     event);
	} else {
		if_ctx->associated = true;

		os_memcpy(if_ctx->bssid,
			  event->assoc_info.addr,
			  ETH_ALEN);

		wpa_supplicant_event(if_ctx->supp_if_ctx,
				     EVENT_ASSOC,
				     event);
	}
}


void wpa_drv_zep_event_proc_deauth(struct zep_drv_if_ctx *if_ctx,
				   union wpa_event_data *event)
{
	wpa_supplicant_event(if_ctx->supp_if_ctx,
			     EVENT_DEAUTH,
			     event);
}


void wpa_drv_zep_event_proc_disassoc(struct zep_drv_if_ctx *if_ctx,
				     union wpa_event_data *event)
{
	wpa_supplicant_event(if_ctx->supp_if_ctx,
			     EVENT_DISASSOC,
			     event);
}


static void *wpa_drv_zep_global_init(void *ctx)
{
	struct zep_drv_ctx *drv_ctx = NULL;

	drv_ctx = os_zalloc(sizeof(*drv_ctx));

	if (!drv_ctx) {
		return NULL;
	}

	drv_ctx->supp_ctx = ctx;

	return drv_ctx;
}


static void wpa_drv_zep_global_deinit(void *priv)
{
	struct zep_drv_ctx *drv_ctx = priv;

	if (!drv_ctx) {
		return;
	}

	os_free(drv_ctx);
}


/**
 * wpa_driver_zep_init - Initialize Zephyr driver interface
 * @ctx: Context to be used when calling wpa_supplicant functions,
 *       e.g., wpa_supplicant_event()
 * @ifname: Interface name, e.g., wlan0
 * @global_priv: private driver global data from global_init()
 *
 * Returns: Pointer to private data, %NULL on failure
 */
static void *wpa_drv_zep_init(void *ctx,
			      const char *ifname,
			      void *global_priv)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	const struct device *device = NULL;
	struct zep_wpa_supp_dev_callbk_fns callbk_fns;

	device = device_get_binding(ifname);

	if (!device) {
		wpa_printf(MSG_ERROR, "%s: Interface %s not found\n", __func__, ifname);
		goto out;
	}

	if_ctx = os_zalloc(sizeof(*if_ctx));

	if (if_ctx == NULL) {
		goto out;
	}

	if_ctx->supp_if_ctx = ctx;

	if_ctx->dev_ctx = device;
	if_ctx->drv_ctx = global_priv;

	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->init) {
		wpa_printf(MSG_ERROR,
			   "%s: No op registered for init\n",
			   __func__);
		os_free(if_ctx);
		if_ctx = NULL;
		goto out;
	}

	os_memset(&callbk_fns,
		  0,
		  sizeof(callbk_fns));

	callbk_fns.scan_start = wpa_drv_zep_event_proc_scan_start;
	callbk_fns.scan_done = wpa_drv_zep_event_proc_scan_done;
	callbk_fns.scan_res = wpa_drv_zep_event_proc_scan_res;
	callbk_fns.auth_resp = wpa_drv_zep_event_proc_auth_resp;
	callbk_fns.assoc_resp = wpa_drv_zep_event_proc_assoc_resp;
	callbk_fns.deauth = wpa_drv_zep_event_proc_deauth;
	callbk_fns.disassoc = wpa_drv_zep_event_proc_disassoc;

	if_ctx->dev_priv = dev_ops->init(if_ctx,
					 ifname,
					 &callbk_fns);

	if (!if_ctx->dev_priv) {
		wpa_printf(MSG_ERROR,
			   "%s: Failed to initialize the interface\n",
			   __func__);
		os_free(if_ctx);
		if_ctx = NULL;
		goto out;
	}

out:
	return if_ctx;
}


static void wpa_drv_zep_deinit(void *priv)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->deinit) {
		wpa_printf(MSG_ERROR, "%s: No op registered for deinit\n", __func__);
		return;
	}

	dev_ops->deinit(if_ctx->dev_priv);

	os_free(if_ctx);
}


static int wpa_drv_zep_scan2(void *priv, struct wpa_driver_scan_params *params)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int timeout = 0;
	int ret = -1;

	if (!priv || !params) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	if_ctx = priv;

	if (if_ctx->scan_res2_get_in_prog) {
		wpa_printf(MSG_ERROR, "%s: Scan is already in progress\n", __func__);
		goto out;
	}

	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->scan2) {
		wpa_printf(MSG_ERROR, "%s: No op registered for scan2\n", __func__);
		goto out;
	}

	ret = dev_ops->scan2(if_ctx->dev_priv, params);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: scan2 op failed\n", __func__);
		goto out;
	}

	/* The driver delivers events to notify when scan is
	 * complete, so use longer timeout to avoid race conditions
	 * with scanning and following association request.
	 */
	timeout = SCAN_TIMEOUT;

	wpa_printf(MSG_DEBUG,
		   "%s: Scan requested - scan timeout %d seconds\n",
		   __func__,
		   timeout);

	eloop_cancel_timeout(wpa_drv_zep_scan_timeout,
			     if_ctx,
			     if_ctx->supp_if_ctx);

	eloop_register_timeout(timeout,
			       0,
			       wpa_drv_zep_scan_timeout,
			       if_ctx,
			       if_ctx->supp_if_ctx);

	ret = 0;

out:
	return ret;
}


/**
 * wpa_drv_zep_get_scan_results2 - Fetch the latest scan results
 * @priv: Pointer to private data from wpa_drv_zep_init()
 * Returns: Scan results on success, -1 on failure
 */
struct wpa_scan_results *wpa_drv_zep_get_scan_results2(void *priv)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	unsigned int i = 0;
	int ret = -1;

	if (!priv) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->get_scan_results2) {
		wpa_printf(MSG_ERROR,
			   "%s: No op registered for scan2\n",
			   __func__);
		goto out;
	}

	if_ctx->scan_res2 = os_zalloc(sizeof(*if_ctx->scan_res2));

	if (!if_ctx->scan_res2) {
		goto out;
	}

	ret = dev_ops->get_scan_results2(if_ctx->dev_priv);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: get_scan_results2 op failed\n", __func__);
		goto out;
	}

	if_ctx->scan_res2_get_in_prog = true;

	/* Wait for the device to populate the scan results */
	while ((if_ctx->scan_res2_get_in_prog) && (i < SCAN_TIMEOUT)) {
		k_yield();
		os_sleep(1, 0);
		i++;
	}

	if (i == SCAN_TIMEOUT) {
		wpa_printf(MSG_ERROR, "%s: Timed out waiting for scan results\n", __func__);
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	if (ret == -1) {
		if (if_ctx->scan_res2) {
			wpa_scan_results_free(if_ctx->scan_res2);
			if_ctx->scan_res2 = NULL;
		}
	}

	return if_ctx->scan_res2;
}


static int wpa_drv_zep_deauthenticate(void *priv, const u8 *addr,
				      u16 reason_code)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;

	if ((!priv) || (!addr)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	ret = dev_ops->deauthenticate(if_ctx->dev_priv, addr, reason_code);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: deauthenticate op failed\n", __func__);
		goto out;
	}

	ret = 0;
out:
	return ret;
}


static int wpa_drv_zep_authenticate(void *priv,
				    struct wpa_driver_auth_params *params)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;

	if ((!priv) || (!params)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	os_memcpy(if_ctx->ssid,
		  params->ssid,
		  params->ssid_len);
	
	if_ctx->ssid_len = params->ssid_len;

	ret = dev_ops->authenticate(if_ctx->dev_priv,
				    params);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: authenticate op failed\n", __func__);
		goto out;
	}

	ret = 0;
out:
	return ret;
}


static int wpa_drv_zep_associate(void *priv,
				 struct wpa_driver_associate_params *params)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;

	if ((!priv) || (!params)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	ret = dev_ops->associate(if_ctx->dev_priv,
				 params);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: associate op failed\n", __func__);
		goto out;
	}

	ret = 0;
out:
	return ret;
}


static int _wpa_drv_zep_set_key(void *priv,
				const char *ifname,
				enum wpa_alg alg,
				const u8 *addr,
				int key_idx,
				int set_tx,
				const u8 *seq,
				size_t seq_len,
				const u8 *key,
				size_t key_len)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;

	if (!priv) {
		wpa_printf(MSG_ERROR, "%s: Invalid handle\n", __func__);
		goto out;
	}
	if ((alg != WPA_ALG_NONE) &&
	    ((!seq) || (!key))) {
		wpa_printf(MSG_ERROR,
			   "%s: Missing mandatory params\n",
			   __func__);
		goto out;
	}

	if_ctx = priv;
	dev_ops = if_ctx->dev_ctx->config;	

	wpa_printf(MSG_DEBUG, "%s: priv:%p alg %d addr %p key_idx %d set_tx %d seq %p "
		   "seq_len %d key %p key_len %d\n",
		   __func__,
		   if_ctx->dev_priv,
		   alg, addr,
		   key_idx,
		   set_tx,
		   seq,
		   seq_len,
		   key,
		   key_len);

	ret = dev_ops->set_key(if_ctx->dev_priv,
			       ifname,
			       alg,
			       addr,
			       key_idx,
			       set_tx,
			       seq,
			       seq_len,
			       key,
			       key_len);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: set_key op failed\n", __func__);
		goto out;
	}
out:
	return ret;
}


static int wpa_drv_zep_set_key(void* priv,
			       struct wpa_driver_set_key_params *params)
{
	return _wpa_drv_zep_set_key(priv,
				    params->ifname,
				    params->alg,
				    params->addr,
				    params->key_idx,
				    params->set_tx,
				    params->seq,
				    params->seq_len,
				    params->key,
				    params->key_len);
}


static int wpa_drv_zep_get_capa(void *priv,
			       	struct wpa_driver_capa *capa)
{
	/* Use SME */
	capa->flags = 0;
	capa->flags |= WPA_DRIVER_FLAGS_SME;
	capa->flags |= WPA_DRIVER_FLAGS_SAE;

	return 0;
}


static int wpa_drv_zep_get_bssid(void *priv,
				 u8 *bssid)
{
	struct zep_drv_if_ctx *if_ctx = NULL;

	if_ctx = priv;

	os_memcpy(bssid,
		  if_ctx->bssid,
		  ETH_ALEN);

	return 0;
}


static int wpa_drv_zep_get_ssid(void *priv,
			       	u8 *ssid)
{
	struct zep_drv_if_ctx *if_ctx = NULL;

	if_ctx = priv;

	if (!if_ctx->ssid) {
		return 0;
	}

	wpa_printf(MSG_INFO,
		   "%s: SSID size: %d\n",
		   __func__,
		   if_ctx->ssid_len);

	os_memcpy(ssid,
		  if_ctx->ssid,
		  if_ctx->ssid_len);

	return if_ctx->ssid_len;
}


static int wpa_drv_zep_set_supp_port(void *priv,
				     int authorized)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	struct net_if *iface = NULL;

	int ret;

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	iface = net_if_lookup_by_dev(if_ctx->dev_ctx);

	ret = dev_ops->set_supp_port(if_ctx->dev_priv,
				     authorized,
				     if_ctx->bssid);

#ifdef CONFIG_NET_DHCPV4
	if (authorized) {
		net_dhcpv4_stop(iface);
		k_msleep(500);
		net_dhcpv4_start(iface);
    }
#endif

	return ret;
}


const struct wpa_driver_ops wpa_driver_zep_ops = {
	.name = "zephyr",
	.desc = "Zephyr wpa_supplicant driver",
	.global_init = wpa_drv_zep_global_init,
	.global_deinit = wpa_drv_zep_global_deinit,
	.init2 = wpa_drv_zep_init,
	.deinit = wpa_drv_zep_deinit,
	.scan2 = wpa_drv_zep_scan2,
	.abort_scan = wpa_drv_zep_abort_scan,
	.get_scan_results2 = wpa_drv_zep_get_scan_results2,
	.authenticate = wpa_drv_zep_authenticate,
	.associate = wpa_drv_zep_associate,
	.get_capa = wpa_drv_zep_get_capa,
	.get_bssid = wpa_drv_zep_get_bssid,
	.get_ssid = wpa_drv_zep_get_ssid,
	.set_supp_port = wpa_drv_zep_set_supp_port,
	.deauthenticate = wpa_drv_zep_deauthenticate,
	.set_key = wpa_drv_zep_set_key,
};
