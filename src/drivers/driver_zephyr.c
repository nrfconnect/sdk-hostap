/*
 * Driver interaction with Zephyr WLAN device drivers.
 * Copyright (c) 2022, Nordic Semiconductor
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <zephyr/kernel.h>

#include "includes.h"
#include "utils/common.h"
#include "eloop.h"
#include "driver_zephyr.h"
#include "supp_main.h"
#include "common/ieee802_11_common.h"

#ifdef CONFIG_AP
#include "l2_packet/l2_packet.h"
#endif /* CONFIG_AP */

/* Zephyr drivers have a timeout of 30s wait for them to handle the cleanup */
/* TODO: The timeout should be retrieved from the driver to keep it generic */
#define SCAN_TIMEOUT 35
#define GET_WIPHY_TIMEOUT 10

void wpa_supplicant_event_wrapper(void *ctx,
				enum wpa_event_type event,
				union wpa_event_data *data)
{
	struct wpa_supplicant_event_msg msg = { 0 };

	msg.ctx = ctx;
	msg.event = event;
	if (data) {
		msg.data = os_zalloc(sizeof(*data));
		if (!msg.data) {
			wpa_printf(MSG_ERROR, "Failed to allocated for event: %d", event);
			return;
		}
		os_memcpy(msg.data, data, sizeof(*data));
		/* Handle deep copy for some event data */
		if (event == EVENT_AUTH) {
			union wpa_event_data *data_tmp = msg.data;

			if (data->auth.ies) {
				char *ies = os_zalloc(data->auth.ies_len);

				if (!ies) {
					wpa_printf(MSG_ERROR, "%s: Failed to alloc ies\n", __func__);
					return;
				}

				os_memcpy(ies, data->auth.ies, data->auth.ies_len);
				data_tmp->auth.ies = ies;
			}
		} else if (event == EVENT_RX_MGMT) {
			union wpa_event_data *data_tmp = msg.data;

			if (data->rx_mgmt.frame) {
				char *frame = os_zalloc(data->rx_mgmt.frame_len);

				if (!frame) {
					wpa_printf(MSG_ERROR, "%s: Failed to alloc frame\n",
					  __func__);
					return;
				}

				os_memcpy(frame, data->rx_mgmt.frame, data->rx_mgmt.frame_len);
				data_tmp->rx_mgmt.frame = frame;
			}
		}
	}
	z_wpas_send_event(&msg);
}

void wpa_drv_zep_event_mac_changed(struct zep_drv_if_ctx *if_ctx)
{
	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
			EVENT_INTERFACE_MAC_CHANGED,
			NULL);
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
	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
			EVENT_SCAN_STARTED,
			NULL);
}


void wpa_drv_zep_event_proc_scan_done(struct zep_drv_if_ctx *if_ctx,
				      union wpa_event_data *event)
{
	eloop_cancel_timeout(wpa_drv_zep_scan_timeout,
			     if_ctx,
			     if_ctx->supp_if_ctx);

	if_ctx->scan_res2_get_in_prog = false;
	k_sem_give(&if_ctx->drv_resp_sem);

	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
			EVENT_SCAN_RESULTS,
			event);
}


void wpa_drv_zep_event_proc_scan_res(struct zep_drv_if_ctx *if_ctx,
				     struct wpa_scan_res *r,
				     bool more_res)
{
	struct wpa_scan_res **tmp = NULL;
	size_t scan_res_len  = sizeof(struct wpa_scan_res) + r->ie_len + r->beacon_ie_len;

	if (!if_ctx->scan_res2)
		return;

	tmp = os_realloc_array(if_ctx->scan_res2->res,
			       if_ctx->scan_res2->num + 1,
			       sizeof(struct wpa_scan_res *));

	if (!tmp) {
		wpa_printf(MSG_ERROR, "%s: Failed to realloc scan result array\n", __func__);
		goto err;
	}

	struct wpa_scan_res *sr = os_zalloc(scan_res_len);
	if (!sr) {
		wpa_printf(MSG_ERROR, "%s: Failed to alloc scan results(%d bytes)\n", __func__, scan_res_len);
		goto err;
	}

	os_memcpy(sr, r, scan_res_len);

	tmp[if_ctx->scan_res2->num++] = sr;

	if_ctx->scan_res2->res = tmp;

err:
	if (!more_res) {
		if_ctx->scan_res2_get_in_prog = false;
		k_sem_give(&if_ctx->drv_resp_sem);
	}
}


void wpa_drv_zep_event_proc_auth_resp(struct zep_drv_if_ctx *if_ctx,
				      union wpa_event_data *event)
{
	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
			     EVENT_AUTH,
			     event);
}


void wpa_drv_zep_event_proc_assoc_resp(struct zep_drv_if_ctx *if_ctx,
				       union wpa_event_data *event,
				       unsigned int status)
{
	if (status != WLAN_STATUS_SUCCESS) {
		wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
				EVENT_ASSOC_REJECT,
				event);
	} else {
		if_ctx->associated = true;

		os_memcpy(if_ctx->bssid,
			  event->assoc_info.addr,
			  ETH_ALEN);

		wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
				EVENT_ASSOC,
				event);
	}
}


void wpa_drv_zep_event_proc_deauth(struct zep_drv_if_ctx *if_ctx,
				union wpa_event_data *event, const struct ieee80211_mgmt *mgmt)
{
	const u8 *bssid = NULL;

	bssid = mgmt->bssid;

	if ((if_ctx->capa.flags & WPA_DRIVER_FLAGS_SME) &&
		!if_ctx->associated &&
		os_memcmp(bssid, if_ctx->auth_bssid, ETH_ALEN) != 0 &&
		os_memcmp(bssid, if_ctx->auth_attempt_bssid, ETH_ALEN) != 0 &&
		os_memcmp(bssid, if_ctx->prev_bssid, ETH_ALEN) == 0)
	{
		/*
		 * Avoid issues with some roaming cases where
		 * disconnection event for the old AP may show up after
		 * we have started connection with the new AP.
		 * In case of locally generated event clear
		 * ignore_next_local_deauth as well, to avoid next local
		 * deauth event be wrongly ignored.
		 */
		wpa_printf(MSG_DEBUG,
				   "nl80211: Ignore deauth/disassoc event from old AP " MACSTR " when already authenticating with " MACSTR,
				   MAC2STR(bssid),
				   MAC2STR(if_ctx->auth_attempt_bssid));
		return;
	}
	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
			EVENT_DEAUTH,
			event);
}


void wpa_drv_zep_event_proc_disassoc(struct zep_drv_if_ctx *if_ctx,
				     union wpa_event_data *event)
{
	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
			EVENT_DISASSOC,
			event);
}

static void wpa_drv_zep_event_mgmt_tx_status(struct zep_drv_if_ctx *if_ctx,
		const u8 *frame, size_t len, bool ack)
{
	union wpa_event_data event;
	const struct ieee80211_hdr *hdr;
	u16 fc;

	wpa_printf(MSG_DEBUG, "wpa_supp: Frame TX status event");

	hdr = (const struct ieee80211_hdr *) frame;
	fc = le_to_host16(hdr->frame_control);

	os_memset(&event, 0, sizeof(event));
	event.tx_status.type = WLAN_FC_GET_TYPE(fc);
	event.tx_status.stype = WLAN_FC_GET_STYPE(fc);
	event.tx_status.dst = hdr->addr1;
	event.tx_status.data = frame;
	event.tx_status.data_len = len;
	event.tx_status.ack = ack;

	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
			EVENT_TX_STATUS,
			&event);
}

static void wpa_drv_zep_event_proc_unprot_deauth(struct zep_drv_if_ctx *if_ctx,
						 union wpa_event_data *event)
{
	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
			EVENT_UNPROT_DEAUTH,
			event);
}

static void wpa_drv_zep_event_proc_unprot_disassoc(struct zep_drv_if_ctx *if_ctx,
						   union wpa_event_data *event)
{
	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx,
			EVENT_UNPROT_DISASSOC,
			event);
}

struct phy_info_arg {
	u16 *num_modes;
	struct hostapd_hw_modes *modes;
	int last_mode, last_chan_idx;
	int failed;
	u8 dfs_domain;
};

static void phy_info_freq_cfg(struct hostapd_hw_modes *mode,
		struct hostapd_channel_data *chan,
		struct wpa_supp_event_channel *chnl_info)
{
	u8 channel = 0;

	chan->freq = chnl_info->center_frequency;
	chan->flag = 0;
	chan->allowed_bw = ~0;
	chan->dfs_cac_ms = 0;

	if (ieee80211_freq_to_chan(chan->freq, &channel) != NUM_HOSTAPD_MODES) {
		chan->chan = channel;
	}
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_DISABLED)
		chan->flag |= HOSTAPD_CHAN_DISABLED;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_IR)
		chan->flag |= HOSTAPD_CHAN_NO_IR;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_RADAR)
		chan->flag |= HOSTAPD_CHAN_RADAR;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_INDOOR_ONLY)
		chan->flag |= HOSTAPD_CHAN_INDOOR_ONLY;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_GO_CONCURRENT)
		chan->flag |= HOSTAPD_CHAN_GO_CONCURRENT;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_10MHZ)
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_10;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_20MHZ)
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_20;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_HT40_PLUS)
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40P;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_HT40_MINUS)
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40M;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_80MHZ)
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_80;
	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_FLAG_FREQUENCY_ATTR_NO_160MHZ)
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_160;

	if (chnl_info->wpa_supp_flags & WPA_SUPP_CHAN_DFS_CAC_TIME_VALID) {
		chan->dfs_cac_ms = (chnl_info->wpa_supp_time);
	}

	/* Other elements are not present */
	chan->wmm_rules_valid = 0;
	chan->wmm_rules_valid = 0;
}


static int phy_info_freqs_cfg(struct phy_info_arg *phy_info,
		struct hostapd_hw_modes *mode,
		struct wpa_supp_event_supported_band *band_info)
{
	int new_channels = 0;
	struct hostapd_channel_data *channel = NULL;
	int idx;

	if (!phy_info || !mode || !band_info)
		return -1;

	new_channels = band_info->wpa_supp_n_channels;

	if (!new_channels)
		return 0;

	channel = os_realloc_array(mode->channels,
			mode->num_channels + new_channels,
			sizeof(struct hostapd_channel_data));

	if (!channel)
		return -1;

	mode->channels = channel;
	mode->num_channels += new_channels;

	idx = phy_info->last_chan_idx;

	for (int i = 0; i < new_channels; i++) {
		phy_info_freq_cfg(mode, &mode->channels[idx], &band_info->channels[i]);
		idx++;
	}

	phy_info->last_chan_idx = idx;

	return 0;
}

static int phy_info_rates_cfg(struct hostapd_hw_modes *mode,
		struct wpa_supp_event_supported_band *band_info)
{
	int idx;

	if (!mode || !band_info)
		return -1;

	mode->num_rates = band_info->wpa_supp_n_bitrates;

	if (!mode->num_rates)
		return 0;

	mode->rates = os_calloc(mode->num_rates, sizeof(int));

	if (!mode->rates)
		return -1;

	idx = 0;

	for (int i = 0; i < mode->num_rates; i++) {
		if (!band_info->bitrates[i].wpa_supp_bitrate)
			continue;
		mode->rates[idx] = band_info->bitrates[i].wpa_supp_bitrate;
		idx++;
	}

	return 0;
}



static void phy_info_ht_capa_cfg(struct hostapd_hw_modes *mode, u16 capa,
		u8 ampdu_factor,
		u8 ampdu_density,
		struct wpa_supp_event_mcs_info *mcs_set)
{
	if (capa)
		mode->ht_capab = (capa);

	if (ampdu_factor)
		mode->a_mpdu_params |= (ampdu_factor) & WPA_SUPP_AMPDU_FACTOR_MASK;

	if (ampdu_density)
		mode->a_mpdu_params |= (ampdu_density) << WPA_SUPP_AMPDU_DENSITY_SHIFT;

	if (mcs_set) {
		os_memcpy(mode->mcs_set, mcs_set, sizeof(*mcs_set));
	}

}

static void phy_info_vht_capa_cfg(struct hostapd_hw_modes *mode,
		unsigned int capa,
		struct wpa_supp_event_vht_mcs_info *vht_mcs_set)
{
	if (capa)
		mode->vht_capab = (capa);

	if (vht_mcs_set) {
		os_memcpy(mode->vht_mcs_set, vht_mcs_set, 8);
	}
}

static int phy_info_band_cfg(struct phy_info_arg *phy_info,
		struct wpa_supp_event_supported_band *band_info)
{
	struct hostapd_hw_modes *mode;
	int ret;

	if (phy_info->last_mode != band_info->band) {
		mode = os_realloc_array(phy_info->modes,
				*phy_info->num_modes + 1,
				sizeof(*mode));

		if (!mode) {
			phy_info->failed = 1;
			return -1;
		}

		phy_info->modes = mode;

		mode = &phy_info->modes[*(phy_info->num_modes)];

		os_memset(mode, 0, sizeof(*mode));

		mode->mode = NUM_HOSTAPD_MODES;
		mode->flags = HOSTAPD_MODE_FLAG_HT_INFO_KNOWN |
			HOSTAPD_MODE_FLAG_VHT_INFO_KNOWN;

		/*
		 * Unsupported VHT MCS stream is defined as value 3, so the VHT
		 * MCS RX/TX map must be initialized with 0xffff to mark all 8
		 * possible streams as unsupported. This will be overridden if
		 * driver advertises VHT support.
		 */
		mode->vht_mcs_set[0] = 0xff;
		mode->vht_mcs_set[1] = 0xff;
		mode->vht_mcs_set[4] = 0xff;
		mode->vht_mcs_set[5] = 0xff;

		*(phy_info->num_modes) += 1;

		phy_info->last_mode = band_info->band;
		phy_info->last_chan_idx = 0;
	}
	else
		mode = &phy_info->modes[*(phy_info->num_modes) - 1];

	phy_info_ht_capa_cfg(mode, band_info->ht_cap.wpa_supp_cap,
			band_info->ht_cap.wpa_supp_ampdu_factor,
			band_info->ht_cap.wpa_supp_ampdu_density,
			&band_info->ht_cap.mcs);

	phy_info_vht_capa_cfg(mode, band_info->vht_cap.wpa_supp_cap,
			&band_info->vht_cap.vht_mcs);

	ret = phy_info_freqs_cfg(phy_info, mode, band_info);

	if (ret == 0)
		ret = phy_info_rates_cfg(mode, band_info);

	if (ret != 0) {
		phy_info->failed = 1;
		return ret;
	}

	return 0;
}

static void wpa_drv_zep_event_get_wiphy(struct zep_drv_if_ctx *if_ctx, void *band_info)
{
	if (!band_info) {
		/* Done with all bands */
		k_sem_give(&if_ctx->drv_resp_sem);
		return;
	}

	phy_info_band_cfg(if_ctx->phy_info_arg, band_info);
}

static int wpa_drv_register_frame(struct zep_drv_if_ctx *if_ctx,
		u16 type, const u8 *match, size_t match_len,
		bool multicast)
{
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;

	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->register_frame)
		return -1;

	return dev_ops->register_frame(if_ctx->dev_priv, type, match, match_len, false);
}

static int wpa_drv_register_action_frame(struct zep_drv_if_ctx *if_ctx,
		const u8 *match, size_t match_len)
{
	u16 type = (WLAN_FC_TYPE_MGMT << 2) | (WLAN_FC_STYPE_ACTION << 4);

	return wpa_drv_register_frame(if_ctx, type, match, match_len, false);
}

static int wpa_drv_mgmt_subscribe_non_ap(struct zep_drv_if_ctx *if_ctx)
{
	int ret = 0;

	/* WNM - BSS Transition Management Request */
	if (wpa_drv_register_action_frame(if_ctx, (u8 *)"\x0a\x07", 2) < 0)
		ret = -1;

	/* Radio Measurement - Neighbor Report Response */
	if (wpa_drv_register_action_frame(if_ctx, (u8 *)"\x05\x05", 2) < 0)
		ret = -1;

	/* Radio Measurement - Radio Measurement Request */
	if (wpa_drv_register_action_frame(if_ctx, (u8 *)"\x05\x00", 2) < 0)
		ret = -1;

	return ret;
}

static void wpa_drv_zep_event_mgmt_rx(struct zep_drv_if_ctx *if_ctx,
		char *frame, int frame_len,
		int frequency, int rx_signal_dbm)
{
	const struct ieee80211_mgmt *mgmt;

	union wpa_event_data event;
	u16 fc, stype;
	int rx_freq = 0;

	wpa_printf(MSG_MSGDUMP, "wpa_supp: Frame event");
	mgmt = (const struct ieee80211_mgmt *)frame;

	if (frame_len < 24) {
		wpa_printf(MSG_DEBUG, "wpa_supp: Too short management frame");
		return;
	}

	fc = le_to_host16(mgmt->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);

	os_memset(&event, 0, sizeof(event));

	if (frequency) {
		event.rx_mgmt.freq = frequency;
		rx_freq = event.rx_mgmt.freq;
	}

	event.rx_mgmt.frame = frame;
	event.rx_mgmt.frame_len = frame_len;
	event.rx_mgmt.ssi_signal = rx_signal_dbm;

	wpa_supplicant_event_wrapper(if_ctx->supp_if_ctx, EVENT_RX_MGMT, &event);
}

static struct hostapd_hw_modes *
wpa_driver_wpa_supp_postprocess_modes(struct hostapd_hw_modes *modes,
		u16 *num_modes)
{
	u16 m;
	struct hostapd_hw_modes *mode11g = NULL, *nmodes, *mode;
	int i, mode11g_idx = -1;

	/* heuristic to set up modes */
	for (m = 0; m < *num_modes; m++) {
		if (!modes[m].num_channels)
			continue;
		if (modes[m].channels[0].freq < 4000) {
			modes[m].mode = HOSTAPD_MODE_IEEE80211B;
			for (i = 0; i < modes[m].num_rates; i++) {
				if (modes[m].rates[i] > 200) {
					modes[m].mode = HOSTAPD_MODE_IEEE80211G;
					break;
				}
			}
		} else if (modes[m].channels[0].freq > 50000)
			modes[m].mode = HOSTAPD_MODE_IEEE80211AD;
		else
			modes[m].mode = HOSTAPD_MODE_IEEE80211A;
	}

	/* If only 802.11g mode is included, use it to construct matching
	 * 802.11b mode data. */

	for (m = 0; m < *num_modes; m++) {
		if (modes[m].mode == HOSTAPD_MODE_IEEE80211B)
			return modes; /* 802.11b already included */
		if (modes[m].mode == HOSTAPD_MODE_IEEE80211G)
			mode11g_idx = m;
	}

	if (mode11g_idx < 0)
		return modes; /* 2.4 GHz band not supported at all */

	nmodes = os_realloc_array(modes, *num_modes + 1, sizeof(*nmodes));
	if (nmodes == NULL)
		return modes; /* Could not add 802.11b mode */

	mode = &nmodes[*num_modes];
	os_memset(mode, 0, sizeof(*mode));
	(*num_modes)++;
	modes = nmodes;

	mode->mode = HOSTAPD_MODE_IEEE80211B;
	mode11g = &modes[mode11g_idx];
	mode->num_channels = mode11g->num_channels;
	mode->channels = os_memdup(mode11g->channels,
			mode11g->num_channels *
			sizeof(struct hostapd_channel_data));
	if (mode->channels == NULL) {
		(*num_modes)--;
		return modes; /* Could not add 802.11b mode */
	}

	mode->num_rates = 0;
	mode->rates = os_malloc(4 * sizeof(int));
	if (mode->rates == NULL) {
		os_free(mode->channels);
		(*num_modes)--;
		return modes; /* Could not add 802.11b mode */
	}

	for (i = 0; i < mode11g->num_rates; i++) {
		if (mode11g->rates[i] != 10 && mode11g->rates[i] != 20 &&
				mode11g->rates[i] != 55 && mode11g->rates[i] != 110)
			continue;
		mode->rates[mode->num_rates] = mode11g->rates[i];
		mode->num_rates++;
		if (mode->num_rates == 4)
			break;
	}

	if (mode->num_rates == 0) {
		os_free(mode->channels);
		os_free(mode->rates);
		(*num_modes)--;
		return modes; /* No 802.11b rates */
	}

	wpa_printf(MSG_DEBUG, "wpa_supp: Added 802.11b mode based on 802.11g "
			"information");

	return modes;
}

struct hostapd_hw_modes *wpa_drv_get_hw_feature_data(void *priv,
		u16 *num_modes,
		u16 *flags, u8 *dfs_domain)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	struct phy_info_arg result = {
		.num_modes = num_modes,
		.modes = NULL,
		.last_mode = -1,
		.failed = 0,
		.dfs_domain = 0,
	};

	*num_modes = 0;
	*flags = 0;
	*dfs_domain = 0;

	if_ctx->phy_info_arg = &result;

	ret = dev_ops->get_wiphy(if_ctx->dev_priv);
	if (ret < 0) {
		return NULL;
	}

	k_sem_reset(&if_ctx->drv_resp_sem);
	k_sem_take(&if_ctx->drv_resp_sem, K_SECONDS(GET_WIPHY_TIMEOUT));

	if (!result.modes) {
		return NULL;
	}

	struct hostapd_hw_modes *modes;

	*dfs_domain = result.dfs_domain;

	modes = wpa_driver_wpa_supp_postprocess_modes(result.modes,
			num_modes);

	return modes;
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
 *       e.g., wpa_supplicant_event_wrapper()
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
	callbk_fns.mgmt_tx_status = wpa_drv_zep_event_mgmt_tx_status;
	callbk_fns.unprot_deauth = wpa_drv_zep_event_proc_unprot_deauth;
	callbk_fns.unprot_disassoc = wpa_drv_zep_event_proc_unprot_disassoc;
	callbk_fns.get_wiphy_res = wpa_drv_zep_event_get_wiphy;
	callbk_fns.mgmt_rx = wpa_drv_zep_event_mgmt_rx;
	callbk_fns.mac_changed = wpa_drv_zep_event_mac_changed;

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

	k_sem_init(&if_ctx->drv_resp_sem, 0, 1);

	wpa_drv_mgmt_subscribe_non_ap(if_ctx);

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
		wpa_printf(MSG_ERROR, "%s: Failed to alloc memory for scan results\n", __func__);
		goto out;
	}

	if_ctx->scan_res2_get_in_prog = true;

	ret = dev_ops->get_scan_results2(if_ctx->dev_priv);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: get_scan_results2 op failed\n", __func__);
		if_ctx->scan_res2_get_in_prog = false;
		goto out;
	}

	k_sem_reset(&if_ctx->drv_resp_sem);
	k_sem_take(&if_ctx->drv_resp_sem, K_SECONDS(SCAN_TIMEOUT));

	if (if_ctx->scan_res2_get_in_prog) {
		wpa_printf(MSG_ERROR, "%s: Timed out waiting for scan results\n", __func__);
		/* If this is a temporary issue, then we can allow subsequent scans */
		if_ctx->scan_res2_get_in_prog = false;
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
	struct wpa_bss *curr_bss;
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

	curr_bss = wpa_bss_get(if_ctx->supp_if_ctx, params->bssid, params->ssid, params->ssid_len);

	if (!curr_bss) {
		wpa_printf(MSG_ERROR, "%s: Failed to get BSS", __func__);
		ret = -1;
		goto out;
	}

	if (params->bssid)
		os_memcpy(if_ctx->auth_attempt_bssid, params->bssid, ETH_ALEN);

	if (if_ctx->associated)
		os_memcpy(if_ctx->prev_bssid, if_ctx->bssid, ETH_ALEN);

	os_memset(if_ctx->auth_bssid, 0, ETH_ALEN);

	if_ctx->associated = false;

	ret = dev_ops->authenticate(if_ctx->dev_priv,
			    params,
			    curr_bss);

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

	if (IS_ENABLED(CONFIG_AP) && params->mode == IEEE80211_MODE_AP) {
		ret = dev_ops->init_ap(if_ctx->dev_priv,
				  params);
	} else if (params->mode == IEEE80211_MODE_INFRA) {
		ret = dev_ops->associate(if_ctx->dev_priv,
				   params);
	} else {
		wpa_printf(MSG_ERROR, "%s: Unsupported mode\n", __func__);
		goto out;
	}

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
	struct net_if *iface = NULL;
	int ret = -1;

	if (!priv) {
		wpa_printf(MSG_ERROR, "%s: Invalid handle\n", __func__);
		goto out;
	}
	if ((alg != WPA_ALG_NONE) && !key) {
		wpa_printf(MSG_ERROR,
			   "%s: Missing mandatory params\n",
			   __func__);
		goto out;
	}

	if_ctx = priv;
	dev_ops = if_ctx->dev_ctx->config;

	iface = net_if_lookup_by_dev(if_ctx->dev_ctx);

	if (!iface) {
		wpa_printf(MSG_ERROR, "%s: Failed to get iface\n", __func__);
		goto out;
	}

	if (!net_if_is_up(iface)) {
		goto out;
	}

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
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;

	if ((!priv) || (!capa)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	if_ctx = priv;
	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->get_capa) {
		wpa_printf(MSG_ERROR, "%s: get_capa op not supported\n", __func__);
		goto out;
	}

	ret = dev_ops->get_capa(if_ctx->dev_priv,
				capa);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: get_capa op failed\n", __func__);
		goto out;
	}

	ret = 0;

	if_ctx->capa = *capa;

out:
	return ret;
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

	wpa_printf(MSG_DEBUG,
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
		net_dhcpv4_restart(iface);
    }
#endif

	return ret;
}


static int wpa_drv_zep_signal_poll(void *priv, struct wpa_signal_info *si)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;

	if (!priv) {
		wpa_printf(MSG_ERROR, "%s: Invalid handle\n", __func__);
		goto out;
	}

	if (!si) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	if_ctx = priv;
	dev_ops = if_ctx->dev_ctx->config;

	os_memset(si, 0, sizeof(*si));

	if (dev_ops && dev_ops->signal_poll) {
		ret = dev_ops->signal_poll(if_ctx->dev_priv, si, if_ctx->bssid);
		if (ret) {
			wpa_printf(MSG_ERROR, "%s: Signal polling failed: %d\n", __func__, ret);
			goto out;
		}
	} else {
		wpa_printf(MSG_ERROR, "%s: Signal polling not supported\n", __func__);
		goto out;
	}

out:
	return ret;
}

static int wpa_drv_zep_send_action(void *priv, unsigned int freq,
		unsigned int wait_time,
		const u8 *dst, const u8 *src,
		const u8 *bssid,
		const u8 *data, size_t data_len,
		int no_cck)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;
	u8 *buf;
	struct ieee80211_hdr *hdr;

	if_ctx = priv;
	dev_ops = if_ctx->dev_ctx->config;

	wpa_printf(MSG_DEBUG, "wpa_supp: Send Action frame ("
			"freq=%u MHz wait=%d ms no_cck=%d)",
			freq, wait_time, no_cck);

	buf = os_zalloc(24 + data_len);
	if (buf == NULL)
		return ret;
	os_memcpy(buf + 24, data, data_len);
	hdr = (struct ieee80211_hdr *)buf;
	hdr->frame_control =
		IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ACTION);
	os_memcpy(hdr->addr1, dst, ETH_ALEN);
	os_memcpy(hdr->addr2, src, ETH_ALEN);
	os_memcpy(hdr->addr3, bssid, ETH_ALEN);


	return dev_ops->send_mlme(if_ctx->dev_priv, buf, 24 + data_len,
			0, freq, no_cck, 1,
			wait_time, 0);
}

static int nl80211_get_ext_capab(void *priv, enum wpa_driver_if_type type,
			const u8 **ext_capa, const u8 **ext_capa_mask,
			unsigned int *ext_capa_len)
{
	struct wpa_driver_capa capa;

	wpa_drv_zep_get_capa(priv, &capa);

	/* By default, use the per-radio values */
	*ext_capa = capa.extended_capa;
	*ext_capa_mask = capa.extended_capa_mask;
	*ext_capa_len = capa.extended_capa_len;

	return 0;
}

static int wpa_drv_zep_get_conn_info(void *priv, struct wpa_conn_info *ci)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops = NULL;
	int ret = -1;

	if (!priv) {
		wpa_printf(MSG_ERROR, "%s: Invalid handle\n", __func__);
		goto out;
	}

	if (!ci) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	if_ctx = priv;
	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops) {
		wpa_printf(MSG_ERROR, "%s:Failed to get config handle\n", __func__);
		goto out;
	}

	if (dev_ops->get_conn_info) {
		ret = dev_ops->get_conn_info(if_ctx->dev_priv, ci);
		if (ret) {
			wpa_printf(MSG_ERROR, "%s: Failed to get connection info: %d\n", __func__, ret);
			goto out;
		}
	} else {
		wpa_printf(MSG_ERROR, "%s: Getting connection info is not supported\n", __func__);
		goto out;
	}

out:
	return ret;
}

#ifdef CONFIG_AP
static int register_mgmt_frames_ap(struct zep_drv_if_ctx *if_ctx)
{
	const struct zep_wpa_supp_dev_ops *dev_ops;
	static const int stypes[] = {
		WLAN_FC_STYPE_AUTH,
		WLAN_FC_STYPE_ASSOC_REQ,
		WLAN_FC_STYPE_REASSOC_REQ,
		WLAN_FC_STYPE_DISASSOC,
		WLAN_FC_STYPE_DEAUTH,
		WLAN_FC_STYPE_PROBE_REQ,
	};
	int i, ret = -1;

	if (!if_ctx) {
		wpa_printf(MSG_ERROR, "%s: Invalid handle\n", __func__);
		goto out;
	}

	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->register_mgmt_frame) {
		wpa_printf(MSG_ERROR, "%s: register_mgmt_frame op not supported\n", __func__);
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(stypes); i++) {
		ret = dev_ops->register_mgmt_frame(if_ctx->dev_priv,
						   stypes[i] << 4,
						   0,
						   NULL);
		if (ret) {
			wpa_printf(MSG_ERROR, "%s: register_mgmt_frame op failed\n", __func__);
			goto out;
		}
	}

out:
	return ret;
}

static int wpa_drv_zep_set_ap(void *priv,
			      struct wpa_driver_ap_params *params)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;

	if ((!priv) || (!params)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	if (!if_ctx->beacon_set && !dev_ops->start_ap) {
		wpa_printf(MSG_ERROR, "%s: start_ap op not supported\n", __func__);
		goto out;
	} else if (if_ctx->beacon_set && !dev_ops->change_beacon) {
		wpa_printf(MSG_ERROR, "%s: change_beacon op not supported\n", __func__);
		goto out;
	}

	if (!if_ctx->beacon_set) {
		ret = register_mgmt_frames_ap(if_ctx);
		if (ret) {
			wpa_printf(MSG_ERROR, "%s: register_mgmt_frames_ap failed\n", __func__);
			goto out;
		}
		ret = dev_ops->start_ap(if_ctx->dev_priv,
					params);
		if (ret) {
			wpa_printf(MSG_ERROR, "%s: start_ap op failed: %d\n", __func__, ret);
			goto out;
		}
	} else {
		ret = dev_ops->change_beacon(if_ctx->dev_priv,
					     params);
		if (ret) {
			wpa_printf(MSG_ERROR, "%s: change_beacon op failed: %d\n", __func__, ret);
			goto out;
		}
	}

	if (!if_ctx->beacon_set) {
		if_ctx->beacon_set = true;
	}

	if_ctx->freq = params->freq->freq;
out:
	return ret;
}

int wpa_drv_zep_stop_ap(void *priv)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;

	if (!priv) {
		wpa_printf(MSG_ERROR, "%s: Invalid handle\n", __func__);
		goto out;
	}

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->stop_ap) {
		wpa_printf(MSG_ERROR, "%s: stop_ap op not supported\n", __func__);
		goto out;
	}

	ret = dev_ops->stop_ap(if_ctx->dev_priv);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: stop_ap op failed: %d\n", __func__, ret);
		goto out;
	}

	if_ctx->freq = 0;
out:
	return ret;
}

int wpa_drv_zep_deinit_ap(void *priv)
{
	struct zep_drv_if_ctx *if_ctx = NULL;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;

	if (!priv) {
		wpa_printf(MSG_ERROR, "%s: Invalid handle\n", __func__);
		goto out;
	}

	if_ctx = priv;

	dev_ops = if_ctx->dev_ctx->config;

	if (!dev_ops->deinit_ap) {
		wpa_printf(MSG_ERROR, "%s: deinit_ap op not supported\n", __func__);
		goto out;
	}

	ret = dev_ops->deinit_ap(if_ctx->dev_priv);

	if (ret) {
		wpa_printf(MSG_ERROR, "%s: deinit_ap op failed: %d\n", __func__, ret);
		goto out;
	}

out:
	return ret;
}

int wpa_drv_zep_sta_add(void *priv, struct hostapd_sta_add_params *params)
{
	struct zep_drv_if_ctx *if_ctx = priv;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;

	if ((!priv) || (!params)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	dev_ops = if_ctx->dev_ctx->config;
	if (!dev_ops->sta_add) {
		wpa_printf(MSG_ERROR, "%s: sta_add op not supported\n", __func__);
		goto out;
	}

	ret = dev_ops->sta_add(if_ctx->dev_priv, params);
	if (ret) {
		wpa_printf(MSG_ERROR, "%s: sta_add op failed: %d\n", __func__, ret);
		goto out;
	}

out:
	return ret;
}

int wpa_drv_zep_sta_set_flags(void *priv, const u8 *addr, u32 total_flags,
	u32 flags_or, u32 flags_and)
{
	struct zep_drv_if_ctx *if_ctx = priv;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;

	if ((!priv) || (!addr)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	dev_ops = if_ctx->dev_ctx->config;
	if (!dev_ops->sta_set_flags) {
		wpa_printf(MSG_ERROR, "%s: sta_set_flags op not supported\n",
			   __func__);
		goto out;
	}

	ret = dev_ops->sta_set_flags(if_ctx->dev_priv, addr, total_flags, flags_or, flags_and);
	if (ret) {
		wpa_printf(MSG_ERROR, "%s: sta_set_flags op failed: %d\n", __func__, ret);
		goto out;
	}

out:
	return ret;
}

int wpa_drv_zep_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, u16 reason_code)
{
	struct zep_drv_if_ctx *if_ctx = priv;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;

	if ((!priv) || (!addr)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	dev_ops = if_ctx->dev_ctx->config;
	if (!dev_ops->sta_deauth) {
		wpa_printf(MSG_ERROR, "%s: sta_deauth op not supported\n",
			   __func__);
		goto out;
	}

	ret = dev_ops->sta_deauth(if_ctx->dev_priv, own_addr, addr, reason_code);
	if (ret) {
		wpa_printf(MSG_ERROR, "%s: sta_deauth op failed: %d\n", __func__, ret);
		goto out;
	}

out:
	return ret;
}

int wpa_drv_zep_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, u16 reason_code)
{
	struct zep_drv_if_ctx *if_ctx = priv;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;

	if ((!priv) || (!addr)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	dev_ops = if_ctx->dev_ctx->config;
	if (!dev_ops->sta_disassoc) {
		wpa_printf(MSG_ERROR, "%s: sta_disassoc op not supported\n",
			   __func__);
		goto out;
	}

	ret = dev_ops->sta_disassoc(if_ctx->dev_priv, own_addr, addr, reason_code);
	if (ret) {
		wpa_printf(MSG_ERROR, "%s: sta_disassoc op failed: %d\n", __func__, ret);
		goto out;
	}

out:
	return ret;
}

int wpa_drv_zep_sta_remove(void *priv, const u8 *addr)
{
	struct zep_drv_if_ctx *if_ctx = priv;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;

	if ((!priv) || (!addr)) {
		wpa_printf(MSG_ERROR, "%s: Invalid params\n", __func__);
		goto out;
	}

	dev_ops = if_ctx->dev_ctx->config;
	if (!dev_ops->sta_remove) {
		wpa_printf(MSG_ERROR, "%s: sta_remove op not supported\n",
			   __func__);
		goto out;
	}

	ret = dev_ops->sta_remove(if_ctx->dev_priv, addr);
	if (ret) {
		wpa_printf(MSG_ERROR, "%s: sta_remove op failed: %d\n", __func__, ret);
		goto out;
	}

out:
	return ret;
}

int wpa_drv_zep_send_mlme(void *priv, const u8 *data, size_t data_len, int noack,
	unsigned int freq, const u16 *csa_offs, size_t csa_offs_len, int no_encrypt,
	unsigned int wait)
{
	struct zep_drv_if_ctx *if_ctx = priv;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;

	dev_ops = if_ctx->dev_ctx->config;
	if (!dev_ops->send_mlme) {
		wpa_printf(MSG_ERROR, "%s: send_mlme op not supported\n",
			   __func__);
		goto out;
	}

	if (freq == 0) {
		freq = if_ctx->freq;
	}

	ret = dev_ops->send_mlme(if_ctx->dev_priv, data, data_len, noack, freq, 0, 0, wait, 0);
	if (ret) {
		wpa_printf(MSG_ERROR, "%s: send_mlme op failed: %d\n", __func__, ret);
		goto out;
	}
	ret = 0;
out:
	return ret;
}

int wpa_drv_hapd_send_eapol(void *priv, const u8 *addr, const u8 *data, size_t data_len,
	int encrypt, const u8 *own_addr, u32 flags)
{
	struct zep_drv_if_ctx *if_ctx = priv;
	const struct zep_wpa_supp_dev_ops *dev_ops;
	int ret = -1;
	struct wpa_supplicant *wpa_s = NULL;

	/* TODO: Unused for now, but might need for rekeying */
	(void)own_addr;
	(void)flags;
	(void)encrypt;

	wpa_s = if_ctx->supp_if_ctx;
	dev_ops = if_ctx->dev_ctx->config;

	wpa_printf(MSG_DEBUG, "wpa_supp: Send EAPOL frame (encrypt=%d)", encrypt);

	ret = l2_packet_send(wpa_s->l2, addr, ETH_P_EAPOL, data, data_len);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: l2_packet_send failed: %d\n", __func__, ret);
		goto out;
	}

	ret = 0;
out:
	return ret;
}

#endif /* CONFIG_AP */

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
	.signal_poll = wpa_drv_zep_signal_poll,
	.send_action = wpa_drv_zep_send_action,
	.get_hw_feature_data = wpa_drv_get_hw_feature_data,
	.get_ext_capab = nl80211_get_ext_capab,
	.get_conn_info = wpa_drv_zep_get_conn_info,
#ifdef CONFIG_AP
	.hapd_send_eapol = wpa_drv_hapd_send_eapol,
	.send_mlme = wpa_drv_zep_send_mlme,
	.set_ap = wpa_drv_zep_set_ap,
	.stop_ap = wpa_drv_zep_stop_ap,
	.deinit_ap = wpa_drv_zep_deinit_ap,
	.sta_add = wpa_drv_zep_sta_add,
	.sta_set_flags = wpa_drv_zep_sta_set_flags,
	.sta_deauth = wpa_drv_zep_sta_deauth,
	.sta_disassoc = wpa_drv_zep_sta_disassoc,
	.sta_remove = wpa_drv_zep_sta_remove,
#endif /* CONFIG_AP */
};
