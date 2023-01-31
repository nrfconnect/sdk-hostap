/*
 * WPA Supplicant / Zephyr socket pair -based control interface
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
/* Per-interface ctrl_iface */
#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "config.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "common/wpa_ctrl.h"

struct ctrl_iface_priv {
	struct wpa_supplicant *wpa_s;
	/* 0 - wpa_cli, 1 - ctrl_iface */
	int sock_pair[2];
};

struct ctrl_iface_global_priv {
	struct wpa_global *global;
	/* 0 - wpa_cli, 1 - ctrl_iface */
	int sock_pair[2];
};

