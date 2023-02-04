/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef __WPA_CLI_ZEPHYR_H_
#define __WPA_CLI_ZEPHYR_H_

#include <zephyr/kernel.h>

#define SSID_MAX_LEN 32

/* Public data structures - no serialization done, so, non-nested only */
struct add_network_resp {
	int network_id;
};

struct signal_poll_resp {
	int rssi;
};

struct status_resp {
	char ssid_len;
	char ssid[SSID_MAX_LEN + 1];
};

/* Public APIs */
int z_wpa_ctrl_init(void *wpa_s);
void z_wpa_ctrl_deinit(void);
int z_wpa_ctrl_zephyr_cmd(int argc, const char *argv[]);
int z_wpa_cli_cmd_v(const char *fmt, ...);

int z_wpa_ctrl_add_network(struct add_network_resp *resp);
int z_wpa_ctrl_signal_poll(struct signal_poll_resp *resp);
int z_wpa_ctrl_status(struct status_resp *resp);

/* Global control interface */
int z_global_wpa_ctrl_init(void);
void z_global_wpa_ctrl_deinit(void);
int z_wpa_global_ctrl_zephyr_cmd(int argc, const char *argv[]);
int z_wpa_cli_global_cmd_v(const char *fmt, ...);

#endif /* __WPA_CLI_ZEPHYR_H_ */
