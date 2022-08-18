/*
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
LOG_MODULE_REGISTER(wpa_supplicant, LOG_LEVEL_DBG);

#include "includes.h"
#include "common.h"
#include "wpa_supplicant/config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "fst/fst.h"
#include "includes.h"
#include "p2p_supplicant.h"
#include "wpa_supplicant_i.h"

/* Should match with the driver name */
#define DEFAULT_IFACE_NAME "wlan0"

static struct net_mgmt_event_callback cb;
struct k_mutex iface_up_mutex;
struct wpa_global *global;

static void start_wpa_supplicant(void);

K_THREAD_DEFINE(wpa_s_tid,
				CONFIG_WPA_SUPP_THREAD_STACK_SIZE,
				start_wpa_supplicant,
				NULL,
				NULL,
				NULL,
				0,
				0,
				0);

#ifdef CONFIG_MATCH_IFACE
static int wpa_supplicant_init_match(struct wpa_global *global)
{
	/*
	 * The assumption is that the first driver is the primary driver and
	 * will handle the arrival / departure of interfaces.
	 */
	if (wpa_drivers[0]->global_init && !global->drv_priv[0]) {
		global->drv_priv[0] = wpa_drivers[0]->global_init(global);
		if (!global->drv_priv[0]) {
			wpa_printf(MSG_ERROR,
				   "Failed to initialize driver '%s'",
				   wpa_drivers[0]->name);
			return -1;
		}
	}

	return 0;
}
#endif /* CONFIG_MATCH_IFACE */

#include "config.h"

int wpa_supplicant_get_iface_count(void)
{
	struct wpa_supplicant *wpa_s;
	unsigned count = 0;

	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
			count += 1;
	}
	return count;
}

static int wpas_add_interface(const char* ifname)
{
	struct wpa_supplicant *wpa_s;
	struct wpa_interface *iface = NULL;

	iface = os_zalloc(sizeof(struct wpa_interface));
	if (iface == NULL) {
		return -1;
	}

	wpa_printf(MSG_INFO, "Adding interface %s\n", ifname);
	iface->ifname = ifname;

	wpa_s = wpa_supplicant_add_iface(global, iface, NULL);
	if (wpa_s == NULL) {
		wpa_printf(MSG_ERROR, "Failed to add iface: %s", ifname);
		return -1;
	}
	wpa_s->conf->filter_ssids = 1;
	wpa_s->conf->ap_scan= 1;

	/* Default interface, kick start wpa_supplicant */
	if (wpa_supplicant_get_iface_count() == 1) {
		k_mutex_unlock(&iface_up_mutex);
	}

	return 0;
}

static int wpas_remove_interface(const char* ifname)
{
	int ret;
	struct wpa_supplicant *wpa_s = wpa_supplicant_get_iface(global, ifname);

	if (wpa_s == NULL) {
		wpa_printf(MSG_ERROR, "Failed to fetch iface: %s", ifname);
		return -1;
	}
	wpa_printf(MSG_INFO, "Remove interface %s\n", ifname);

	/* wpa_supplicant thread never terminates unless there is some failure in
	 * wpa_supplicant initialization
	 */
	ret = wpa_supplicant_remove_iface(global, wpa_s, 0);
	if (!ret) {
		wpa_printf(MSG_ERROR, "Failed to remove iface: %s, ret: %d", ifname, ret);
	}

	return ret;
}

static void iface_event_handler(struct net_mgmt_event_callback *cb,
							uint32_t mgmt_event, struct net_if *iface)
{
	const char *ifname = iface->if_dev->dev->name;

	wpa_printf(MSG_INFO, "Event: %d", mgmt_event);
	if (mgmt_event == NET_EVENT_IF_UP) {
		wpas_add_interface(ifname);
	} else if (mgmt_event == NET_EVENT_IF_DOWN) {
		wpas_remove_interface(ifname);
	}
}

static void register_iface_events(void)
{
	k_mutex_init(&iface_up_mutex);

	k_mutex_lock(&iface_up_mutex, K_FOREVER);
	net_mgmt_init_event_callback(&cb, iface_event_handler,
									NET_EVENT_IF_UP | NET_EVENT_IF_DOWN);
	net_mgmt_add_event_callback(&cb);
}

static void wait_for_interface_up(const char* iface_name)
{
	if (wpa_supplicant_get_iface_count() == 0) {
		k_mutex_lock(&iface_up_mutex, K_FOREVER);
	}
}

static void iface_cb(struct net_if *iface, void *user_data)
{
	const char *ifname = iface->if_dev->dev->name;

	if (strncmp(ifname, DEFAULT_IFACE_NAME, strlen(ifname)) != 0)
	{
		return;
	}

	/* Check default interface */
	if (net_if_flag_is_set(iface, NET_IF_UP)) {
		wpas_add_interface(ifname);
	} 

	register_iface_events();
}

static void start_wpa_supplicant(void)
{
	int exitcode = -1;
	struct wpa_params params;

	os_memset(&params, 0, sizeof(params));
	params.wpa_debug_level = CONFIG_WPA_SUPP_DEBUG_LEVEL;

	wpa_printf(MSG_INFO, "%s: %d Starting wpa_supplicant thread with debug level: %d\n",
		  __func__, __LINE__, params.wpa_debug_level);

	exitcode = 0;
	global = wpa_supplicant_init(&params);
	if (global == NULL) {
		wpa_printf(MSG_ERROR, "Failed to initialize wpa_supplicant");
		exitcode = -1;
		goto out;
	} else {
		wpa_printf(MSG_INFO, "Successfully initialized "
				     "wpa_supplicant");
	}

	if (fst_global_init()) {
		wpa_printf(MSG_ERROR, "Failed to initialize FST");
		exitcode = -1;
		goto out;
	}

#if defined(CONFIG_FST) && defined(CONFIG_CTRL_IFACE)
	if (!fst_global_add_ctrl(fst_ctrl_cli)) {
		wpa_printf(MSG_WARNING, "Failed to add CLI FST ctrl");
	}
#endif
	net_if_foreach(iface_cb, NULL);
	wait_for_interface_up(DEFAULT_IFACE_NAME);

#ifdef CONFIG_MATCH_IFACE
	if (exitcode == 0) {
		exitcode = wpa_supplicant_init_match(global);
	}
#endif /* CONFIG_MATCH_IFACE */

	if (exitcode == 0) {
		exitcode = wpa_supplicant_run(global);
	}

	wpa_supplicant_deinit(global);

	fst_global_deinit();

out:
#ifdef CONFIG_MATCH_IFACE
	os_free(params.match_ifaces);
#endif /* CONFIG_MATCH_IFACE */
	os_free(params.pid_file);

	wpa_printf(MSG_INFO, "wpa_supplicant_main: exitcode %d", exitcode);
	return;
}
