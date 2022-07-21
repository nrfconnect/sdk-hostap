/**
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/*
 * WPA Supplicant / main() function for Zephyr OS
 * Copyright (c) 2003-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <logging/log.h>

#include "includes.h"
#include "common.h"
#include "rsn_supp/preauth.h"
#include "common/defs.h"
#include "wpa_supplicant/config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "fst/fst.h"
#include "p2p_supplicant.h"
#include "wpa_supplicant_i.h"
#include "wifi_mgmt.h"

int cli_main(int, const char **);
extern struct wpa_supplicant *wpa_s_0;


int zep_supp_ctrl_iface_status(struct wpa_supplicant *wpa_s,
					    const char *params,
					    char *buf, size_t buflen)
{
	char *pos, *end, tmp[30];
	int res, verbose, wps, ret;
#ifdef CONFIG_HS20
	const u8 *hs20;
#endif /* CONFIG_HS20 */
	const u8 *sess_id;
	size_t sess_id_len;

	if (os_strcmp(params, "-DRIVER") == 0)
		return wpa_drv_status(wpa_s, buf, buflen);
	verbose = os_strcmp(params, "-VERBOSE") == 0;
	wps = os_strcmp(params, "-WPS") == 0;
	pos = buf;
	end = buf + buflen;
	if (wpa_s->wpa_state >= WPA_ASSOCIATED) {
		struct wpa_ssid *ssid = wpa_s->current_ssid;
		ret = os_snprintf(pos, end - pos, "bssid=" MACSTR "\n",
				  MAC2STR(wpa_s->bssid));
		if (os_snprintf_error(end - pos, ret))
			return pos - buf;
		pos += ret;
		ret = os_snprintf(pos, end - pos, "freq=%u\n",
				  wpa_s->assoc_freq);
		if (os_snprintf_error(end - pos, ret))
			return pos - buf;
		pos += ret;
		if (ssid) {
			u8 *_ssid = ssid->ssid;
			size_t ssid_len = ssid->ssid_len;
			u8 ssid_buf[SSID_MAX_LEN];
			if (ssid_len == 0) {
				int _res = wpa_drv_get_ssid(wpa_s, ssid_buf);
				if (_res < 0)
					ssid_len = 0;
				else
					ssid_len = _res;
				_ssid = ssid_buf;
			}
			ret = os_snprintf(pos, end - pos, "ssid=%s\nid=%d\n",
					  wpa_ssid_txt(_ssid, ssid_len),
					  ssid->id);
			if (os_snprintf_error(end - pos, ret))
				return pos - buf;
			pos += ret;

			if (wps && ssid->passphrase &&
			    wpa_key_mgmt_wpa_psk(ssid->key_mgmt) &&
			    (ssid->mode == WPAS_MODE_AP ||
			     ssid->mode == WPAS_MODE_P2P_GO)) {
				ret = os_snprintf(pos, end - pos,
						  "passphrase=%s\n",
						  ssid->passphrase);
				if (os_snprintf_error(end - pos, ret))
					return pos - buf;
				pos += ret;
			}
			if (ssid->id_str) {
				ret = os_snprintf(pos, end - pos,
						  "id_str=%s\n",
						  ssid->id_str);
				if (os_snprintf_error(end - pos, ret))
					return pos - buf;
				pos += ret;
			}

			switch (ssid->mode) {
			case WPAS_MODE_INFRA:
				ret = os_snprintf(pos, end - pos,
						  "mode=station\n");
				break;
			case WPAS_MODE_IBSS:
				ret = os_snprintf(pos, end - pos,
						  "mode=IBSS\n");
				break;
			case WPAS_MODE_AP:
				ret = os_snprintf(pos, end - pos,
						  "mode=AP\n");
				break;
			case WPAS_MODE_P2P_GO:
				ret = os_snprintf(pos, end - pos,
						  "mode=P2P GO\n");
				break;
			case WPAS_MODE_P2P_GROUP_FORMATION:
				ret = os_snprintf(pos, end - pos,
						  "mode=P2P GO - group "
						  "formation\n");
				break;
			case WPAS_MODE_MESH:
				ret = os_snprintf(pos, end - pos,
						  "mode=mesh\n");
				break;
			default:
				ret = 0;
				break;
			}
			if (os_snprintf_error(end - pos, ret))
				return pos - buf;
			pos += ret;
		}

		if (wpa_s->connection_set &&
		    (wpa_s->connection_ht || wpa_s->connection_vht ||
		     wpa_s->connection_he)) {
			ret = os_snprintf(pos, end - pos,
					  "wifi_generation=%u\n",
					  wpa_s->connection_he ? 6 :
					  (wpa_s->connection_vht ? 5 : 4));
			if (os_snprintf_error(end - pos, ret))
				return pos - buf;
			pos += ret;
		}

#ifdef CONFIG_AP
		if (wpa_s->ap_iface) {
			pos += ap_ctrl_iface_wpa_get_status(wpa_s, pos,
							    end - pos,
							    verbose);
		} else
#endif /* CONFIG_AP */
		pos += wpa_sm_get_status(wpa_s->wpa, pos, end - pos, verbose);
	}
#ifdef CONFIG_SME
#ifdef CONFIG_SAE
	if (wpa_s->wpa_state >= WPA_ASSOCIATED &&
#ifdef CONFIG_AP
	    !wpa_s->ap_iface &&
#endif /* CONFIG_AP */
	    wpa_s->sme.sae.state == SAE_ACCEPTED) {
		ret = os_snprintf(pos, end - pos, "sae_group=%d\n"
				  "sae_h2e=%d\n"
				  "sae_pk=%d\n",
				  wpa_s->sme.sae.group,
				  wpa_s->sme.sae.h2e,
				  wpa_s->sme.sae.pk);
		if (os_snprintf_error(end - pos, ret))
			return pos - buf;
		pos += ret;
	}
#endif /* CONFIG_SAE */
#endif /* CONFIG_SME */
	ret = os_snprintf(pos, end - pos, "wpa_state=%s\n",
			  wpa_supplicant_state_txt(wpa_s->wpa_state));
	if (os_snprintf_error(end - pos, ret))
		return pos - buf;
	pos += ret;

	if (wpa_s->l2 &&
	    l2_packet_get_ip_addr(wpa_s->l2, tmp, sizeof(tmp)) >= 0) {
		ret = os_snprintf(pos, end - pos, "ip_address=%s\n", tmp);
		if (os_snprintf_error(end - pos, ret))
			return pos - buf;
		pos += ret;
	}

#ifdef CONFIG_P2P
	if (wpa_s->global->p2p) {
		ret = os_snprintf(pos, end - pos, "p2p_device_address=" MACSTR
				  "\n", MAC2STR(wpa_s->global->p2p_dev_addr));
		if (os_snprintf_error(end - pos, ret))
			return pos - buf;
		pos += ret;
	}
#endif /* CONFIG_P2P */

	ret = os_snprintf(pos, end - pos, "address=" MACSTR "\n",
			  MAC2STR(wpa_s->own_addr));
	if (os_snprintf_error(end - pos, ret))
		return pos - buf;
	pos += ret;

#ifdef CONFIG_HS20
	if (wpa_s->current_bss &&
	    (hs20 = wpa_bss_get_vendor_ie(wpa_s->current_bss,
					  HS20_IE_VENDOR_TYPE)) &&
	    wpa_s->wpa_proto == WPA_PROTO_RSN &&
	    wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt)) {
		int release = 1;
		if (hs20[1] >= 5) {
			u8 rel_num = (hs20[6] & 0xf0) >> 4;
			release = rel_num + 1;
		}
		ret = os_snprintf(pos, end - pos, "hs20=%d\n", release);
		if (os_snprintf_error(end - pos, ret))
			return pos - buf;
		pos += ret;
	}

	if (wpa_s->current_ssid) {
		struct wpa_cred *cred;
		char *type;

		for (cred = wpa_s->conf->cred; cred; cred = cred->next) {
			size_t i;

			if (wpa_s->current_ssid->parent_cred != cred)
				continue;

			if (cred->provisioning_sp) {
				ret = os_snprintf(pos, end - pos,
						  "provisioning_sp=%s\n",
						  cred->provisioning_sp);
				if (os_snprintf_error(end - pos, ret))
					return pos - buf;
				pos += ret;
			}

			if (!cred->domain)
				goto no_domain;

			i = 0;
			if (wpa_s->current_bss && wpa_s->current_bss->anqp) {
				struct wpabuf *names =
					wpa_s->current_bss->anqp->domain_name;
				for (i = 0; names && i < cred->num_domain; i++)
				{
					if (domain_name_list_contains(
						    names, cred->domain[i], 1))
						break;
				}
				if (i == cred->num_domain)
					i = 0; /* show first entry by default */
			}
			ret = os_snprintf(pos, end - pos, "home_sp=%s\n",
					  cred->domain[i]);
			if (os_snprintf_error(end - pos, ret))
				return pos - buf;
			pos += ret;

		no_domain:
			if (wpa_s->current_bss == NULL ||
			    wpa_s->current_bss->anqp == NULL)
				res = -1;
			else
				res = interworking_home_sp_cred(
					wpa_s, cred,
					wpa_s->current_bss->anqp->domain_name);
			if (res > 0)
				type = "home";
			else if (res == 0)
				type = "roaming";
			else
				type = "unknown";

			ret = os_snprintf(pos, end - pos, "sp_type=%s\n", type);
			if (os_snprintf_error(end - pos, ret))
				return pos - buf;
			pos += ret;

			break;
		}
	}
#endif /* CONFIG_HS20 */

	if (wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt) ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		res = eapol_sm_get_status(wpa_s->eapol, pos, end - pos,
					  verbose);
		if (res >= 0)
			pos += res;
	}

#ifdef CONFIG_MACSEC
	res = ieee802_1x_kay_get_status(wpa_s->kay, pos, end - pos);
	if (res > 0)
		pos += res;
#endif /* CONFIG_MACSEC */

	sess_id = eapol_sm_get_session_id(wpa_s->eapol, &sess_id_len);
	if (sess_id) {
		char *start = pos;

		ret = os_snprintf(pos, end - pos, "eap_session_id=");
		if (os_snprintf_error(end - pos, ret))
			return start - buf;
		pos += ret;
		ret = wpa_snprintf_hex(pos, end - pos, sess_id, sess_id_len);
		if (ret <= 0)
			return start - buf;
		pos += ret;
		ret = os_snprintf(pos, end - pos, "\n");
		if (os_snprintf_error(end - pos, ret))
			return start - buf;
		pos += ret;
	}

	res = rsn_preauth_get_status(wpa_s->wpa, pos, end - pos, verbose);
	if (res >= 0)
		pos += res;

#ifdef CONFIG_WPS
	{
		char uuid_str[100];
		uuid_bin2str(wpa_s->wps->uuid, uuid_str, sizeof(uuid_str));
		ret = os_snprintf(pos, end - pos, "uuid=%s\n", uuid_str);
		if (os_snprintf_error(end - pos, ret))
			return pos - buf;
		pos += ret;
	}
#endif /* CONFIG_WPS */

	if (wpa_s->ieee80211ac) {
		ret = os_snprintf(pos, end - pos, "ieee80211ac=1\n");
		if (os_snprintf_error(end - pos, ret))
			return pos - buf;
		pos += ret;
	}

#ifdef ANDROID
	/*
	 * Allow using the STATUS command with default behavior, say for debug,
	 * i.e., don't generate a "fake" CONNECTION and SUPPLICANT_STATE_CHANGE
	 * events with STATUS-NO_EVENTS.
	 */
	if (os_strcmp(params, "-NO_EVENTS")) {
		wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_STATE_CHANGE
			     "id=%d state=%d BSSID=" MACSTR " SSID=%s",
			     wpa_s->current_ssid ? wpa_s->current_ssid->id : -1,
			     wpa_s->wpa_state,
			     MAC2STR(wpa_s->bssid),
			     wpa_s->current_ssid && wpa_s->current_ssid->ssid ?
			     wpa_ssid_txt(wpa_s->current_ssid->ssid,
					  wpa_s->current_ssid->ssid_len) : "");
		if (wpa_s->wpa_state == WPA_COMPLETED) {
			struct wpa_ssid *ssid = wpa_s->current_ssid;
			wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_CONNECTED
				     "- connection to " MACSTR
				     " completed %s [id=%d id_str=%s]",
				     MAC2STR(wpa_s->bssid), "(auth)",
				     ssid ? ssid->id : -1,
				     ssid && ssid->id_str ? ssid->id_str : "");
		}
	}
#endif /* ANDROID */

	return pos - buf;
}

int _prepare_and_call_wpa_cli(char *cmd)
{
	const char *argv[CONFIG_SHELL_ARGC_MAX + 1]; /* +1 reserved for NULL */
	size_t argc = 0;
	const char **argvp;
	char quote;
	int ret = -1;

	argv[0] = cmd;
	argvp = &argv[0];

	quote = z_shell_make_argv(&argc, argvp, cmd, 4);

	if (argc == 0) {
		return -ENOEXEC;
	} else if ((argc == 1) && (quote != 0)) {
		wpa_printf(MSG_ERROR, "not terminated: %c\n", quote);
		return -ENOEXEC;
	}

	return cli_main(argc, argv);
}

int zephyr_supp_disable_network(int id)
{
	char cmd[512] = {'\0'};

	os_snprintf(cmd, sizeof(cmd), "disable_network %d", id);
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_remove_network(char *id)
{
	char cmd[512] = {'\0'};

	os_snprintf(cmd, sizeof(cmd), "remove_network %s", id);
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_enable_network(int id)
{
	char cmd[512] = {'\0'};

	os_snprintf(cmd, sizeof(cmd), "enable_network %d", id);
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_select_network(int id)
{
	char cmd[512] = {'\0'};

	os_snprintf(cmd, sizeof(cmd), "select_network %d", id);
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_reassociate(void)
{
	char cmd[512] = {'\0'};
	os_snprintf(cmd, sizeof(cmd), "reassociate");
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_disconnect(void)
{
	char cmd[512] = {'\0'};
	os_snprintf(cmd, sizeof(cmd), "disconnect");
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_add_network(void)
{
	struct wpa_ssid *ssid;

	ssid = wpa_supplicant_add_network(wpa_s_0);
	if (ssid)
		return ssid->id;

	return -1;
}

int zephyr_supp_signal_poll(void)
{
	char cmd[512] = {'\0'};
	os_snprintf(cmd, sizeof(cmd), "signal_poll");
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_set_ssid(int id, const char *ssid_name)
{
	char cmd[512] = {'\0'};
	os_snprintf(cmd, sizeof(cmd), "set_network %d ssid %s", id, ssid_name);
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_set_psk(int id, const char *psk)
{
	char cmd[512] = {'\0'};
	os_snprintf(cmd, sizeof(cmd), "set_network %d psk %s", id, psk);
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_set_key_mgmt(int id, int key_mgmt)
{
	struct wpa_ssid *ssid;
	int errors = 0;

	if (!wpa_s_0) {
		wpa_printf(MSG_ERROR, "%s: wpa_supplicant is not initialized, "
		"droppping command\n", __func__);
		return -1;
	}
	ssid = wpa_config_get_network(wpa_s_0->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "Could not find network id=%d\n", id);
		return -1;
	}

	if (key_mgmt == 0) {
		wpa_printf(MSG_ERROR, "Line %d: no key_mgmt values configured.", id);
		errors = 1;
	}

	if (!errors && ssid->key_mgmt == key_mgmt)
		return 1;
	wpa_printf(MSG_MSGDUMP, "key_mgmt: 0x%x", key_mgmt);
	ssid->key_mgmt = key_mgmt;

	return errors ? -1 : 0;
}

int zephyr_supp_set_pairwise_cipher(int id, int pairwise_cipher)
{
	struct wpa_ssid *ssid;
	int errors = 0;

	if (!wpa_s_0) {
		wpa_printf(MSG_ERROR, "%s: wpa_supplicant is not initialized, "
		"droppping command\n", __func__);
		return -1;
	}
	ssid = wpa_config_get_network(wpa_s_0->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "Could not find network id=%d\n", id);
		return -1;
	}

	if (pairwise_cipher == 0) {
		wpa_printf(MSG_ERROR, "%d: no pairwise_cipher values configured.", id);
		errors = 1;
	}

	if (pairwise_cipher & ~WPA_ALLOWED_PAIRWISE_CIPHERS) {
		wpa_printf(MSG_ERROR, "Line %d: not allowed pairwise cipher (0x%x).",
		 id, pairwise_cipher);
		return -1;
	}

	if (!errors && ssid->pairwise_cipher == pairwise_cipher)
		return 1;
	wpa_printf(MSG_MSGDUMP, "pairwise_cipher: 0x%x", pairwise_cipher);
	ssid->pairwise_cipher = pairwise_cipher;

	return errors ? -1 : 0;
}

int zephyr_supp_set_group_cipher(int id, int group_cipher)
{
	struct wpa_ssid *ssid;
	int errors = 0;

	if (!wpa_s_0) {
		wpa_printf(MSG_ERROR, "%s: wpa_supplicant is not initialized, droppping command\n",
			   __func__);
		return -1;
	}
	ssid = wpa_config_get_network(wpa_s_0->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "Could not find network id=%d\n", id);
		return -1;
	}

	if (group_cipher == 0) {
		wpa_printf(MSG_ERROR, "%d: no group_cipher values configured.", id);
		errors = 1;
	}

	/*
	 * Backwards compatibility - filter out WEP ciphers that were previously
	 * allowed.
	 */
	group_cipher &= ~(WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40);

	if (group_cipher & ~WPA_ALLOWED_GROUP_CIPHERS) {
		wpa_printf(MSG_ERROR, "Line %d: not allowed group cipher (0x%x).",
		 id, group_cipher);
		return -1;
	}

	if (!errors && ssid->group_cipher == group_cipher)
		return 1;
	wpa_printf(MSG_MSGDUMP, "group_cipher: 0x%x", group_cipher);
	ssid->group_cipher = group_cipher;

	return errors ? -1 : 0;
}

int zephyr_supp_set_proto(int id, int proto)
{
	struct wpa_ssid *ssid;
	int errors = 0;

	if (!wpa_s_0) {
		wpa_printf(MSG_ERROR, "%s: wpa_supplicant is not initialized, droppping command\n",
			   __func__);
		return -1;
	}
	ssid = wpa_config_get_network(wpa_s_0->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "Could not find network id=%d\n", id);
		return -1;
	}

	if (proto == 0) {
		wpa_printf(MSG_ERROR,
			   "Line %d: no proto values configured.", id);
		errors = 1;
	}

	if (!errors && ssid->proto == proto)
		return 1;
	wpa_printf(MSG_MSGDUMP, "proto: 0x%x", proto);
	ssid->proto = proto;

	return errors ? -1 : 0;
}

int zephyr_supp_set_auth_alg(int id, int auth_alg)
{
	struct wpa_ssid *ssid;
	int errors = 0;

	if (!wpa_s_0) {
		wpa_printf(MSG_ERROR, "%s: wpa_supplicant is not initialized, droppping command\n",
			   __func__);
		return -1;
	}
	ssid = wpa_config_get_network(wpa_s_0->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "Could not find network id=%d\n", id);
		return -1;
	}

	if (auth_alg == 0) {
		wpa_printf(MSG_ERROR,
			   "Line %d: no auth_alg values configured.", id);
		errors = 1;
	}

	if (!errors && ssid->auth_alg == auth_alg)
		return 1;
	wpa_printf(MSG_MSGDUMP, "auth_alg: 0x%x", auth_alg);
	ssid->auth_alg = auth_alg;

	return errors ? -1 : 0;
}

int zephyr_supp_set_scan_ssid(int id, int scan_ssid)
{
	struct wpa_ssid *ssid;
	int errors = 0;

	if (!wpa_s_0) {
		wpa_printf(MSG_ERROR, "%s: wpa_supplicant is not initialized, droppping command\n",
			   __func__);
		return -1;
	}
	ssid = wpa_config_get_network(wpa_s_0->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "Could not find network id=%d\n", id);
		return -1;
	}

	if (!errors && ssid->scan_ssid == scan_ssid)
		return 1;
	wpa_printf(MSG_MSGDUMP, "scan_ssid: 0x%x", scan_ssid);
	ssid->scan_ssid = scan_ssid;

	return errors ? -1 : 0;
}

int zephyr_supp_sta_autoconnect(int autoconnect)
{
	if (!wpa_s_0) {
		wpa_printf(MSG_ERROR, "%s: wpa_supplicant is not initialized, droppping command\n",
			   __func__);
		return -1;
	}

	wpa_printf(MSG_MSGDUMP, "autoconnect: 0x%x", autoconnect);
	wpa_s_0->auto_reconnect_disabled = autoconnect == 0;

	return 0;
}

int zephyr_supp_set_bssid(int id, uint8_t *bssid)
{
	struct wpa_ssid *ssid;
	int errors = 0;

	if (!wpa_s_0) {
		wpa_printf(MSG_ERROR, "%s: wpa_supplicant is not initialized, droppping command\n",
			   __func__);
		return -1;
	}
	ssid = wpa_config_get_network(wpa_s_0->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "Could not find network id=%d\n", id);
		return -1;
	}

	wpa_printf(MSG_MSGDUMP, "bssid: %02x:%02x:%02x:%02x:%02x:%02x",
	bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
	memcpy(ssid->bssid, bssid, ETH_ALEN);
	ssid->bssid_set = 1;

	return errors ? -1 : 0;
}

int zephyr_supp_set_scan_freq(int id, int *freqs)
{
	struct wpa_ssid *ssid;
	int errors = 0;

	if (!wpa_s_0) {
		wpa_printf(MSG_ERROR, "%s: wpa_supplicant is not initialized, droppping command\n",
			   __func__);
		return -1;
	}
	ssid = wpa_config_get_network(wpa_s_0->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "Could not find network id=%d\n", id);
		return -1;
	}

	os_free(ssid->scan_freq);
	ssid->scan_freq = freqs;

	return errors ? -1 : 0;
}

int zephyr_supp_set_ieee80211w(int id, int ieee80211w)
{
	char cmd[512] = {'\0'};
	os_snprintf(cmd, sizeof(cmd), "set_network %d ieee80211w %d", id, ieee80211w);
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_set_country(const char *country_code)
{
	char cmd[512] = {'\0'};
	os_snprintf(cmd, sizeof(cmd), "set country %s", country_code);
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_set_pmf(int pmf)
{
	char cmd[512] = {'\0'};
	os_snprintf(cmd, sizeof(cmd), "set pmf %d", pmf);
	return _prepare_and_call_wpa_cli(cmd);
}

int zephyr_supp_status(char *status_buf, size_t buflen)
{
       return zep_supp_ctrl_iface_status(wpa_s_0,"", status_buf, buflen);
}
