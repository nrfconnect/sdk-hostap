/*
 * Copyright (c) 2022 Nordic Semiconductor
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 */

#ifndef ZEPHYR_SUPP_MGMT_H
#define ZEPHYR_SUPP_MGMT_H

/**
 * @brief Disables the selected network.
 *
 * @param id: Network identifier returned by add_network call.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_disable_network(int id);

/**
 * @brief Removes the selected network.
 *
 * @param id: Network identifier returned by add_network call or "all"
 * if all configured networks are required to be removed.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_remove_network(char *id);

/**
 * @brief Enables the selected network. Triggers scan and connects to the
 * configured SSID
 *
 * @param id: Network identifier returned by add_network call.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_enable_network(int id);

/**
 * @brief Enables the selected network and disables all other networks.
 * Triggers scan and connects to the configured SSID
 *
 * @param id: Network identifier returned by add_network call.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_select_network(int id);

/**
 * @brief Forces station to reassociate with the configured SSID.
 *
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_reassociate(void);

/**
 * @brief Forces station to disconnect and stops any subsequent scan
 *  or connection attempts
 *
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_disconnect(void);

/**
 * @brief Initializes a network config structure. Needs to be called before
 * configuring any network params (SSID, key management etc).
 *
 * @return Network ID which needs to be passed to calls for network param
 * configuration.
 */
int zephyr_supp_add_network(void);

/**
 * @brief: Get the signal parameters like RSSI, frequeuncy etc.
 *
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_signal_poll(void);

/**
 * @brief: Configures SSID info of the network
 *
 * @param id: Network identifier returned by add_network call.
 * @param ssid_name: SSID needs to be passed in double quotes,
 * eg., zephyr_supp_set_ssid(id, "\"SSID-NAME\"");
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_ssid(int id, const char *ssid_name);

/**
 * @brief: Configures pre-shared-key. Its an ASCII string whose length
 * ranges 8 to 63 characters. 
 *
 * @param id: Network identifier returned by add_network call.
 * @param psk: PSK needs to be passed in double quotes,
 * eg., zephyr_supp_set_psk(id, "\"XXXXXXXXXX\""); 
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_psk(int id, const char *psk);

/**
 * @brief: List of accepted authenticated key management protocols
 *
 * @param id: Network identifier returned by add_network call.
 * @param key_mgmt: Bitwise OR'ed value of available methods.
 * Ref: hostap/src/common/defs.h for the key_mgmt method definitions
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_key_mgmt(int id, int key_mgmt);

/**
 * @brief: Cipher used for encrypting unicast traffic
 *
 * @param id: Network identifier returned by add_network call.
 * @param pairwise_cipher: Bitwise OR'ed value of available methods.
 * Ref: hostap/src/common/defs.h for the key_mgmt method definitions
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_pairwise_cipher(int id, int pairwise_cipher);

/**
 * @brief: Cipher used for encrypting multicast/broadcast traffic
 *
 * @param id: Network identifier returned by add_network call.
 * @param group_cipher: Bitwise OR'ed value of available methods.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_group_cipher(int id, int group_cipher);

/**
 * @brief: Security protocol to be used for connecting to a network
 *
 * @param id: Network identifier returned by add_network call.
 * @param proto: Bitwise OR'ed value of available methods.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_proto(int id, int proto);

/**
 * @brief: list of allowed IEEE 802.11 authentication algorithms
 *
 * @param id: Network identifier returned by add_network call.
 * @param auth_alg: Bitwise OR'd value of auth algorithms.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_auth_alg(int id, int auth_alg);

/**
 * @brief:  This lets the user to enable ssid specific probe requests.
 * Needed while connecting to hidden networks.
 *
 * @param id: Network identifier returned by add_network call.
 * @param scan_ssid: 0 for disabling ssid specific scanning
 *                   1 for enabling ssid specific scanning.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_scan_ssid(int id, int scan_ssid);

/**
 * @brief: Disable/Enable auto-reconnection. 
 *
 * @param id: Network identifier returned by add_network call.
 * @param autoconnect: 0 to disable, 1 to enable.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_sta_autoconnect(int id, int autoconnect);

/**
 * @brief: Used to associate with an AP using the configured BSSID
 *
 * @param id: Network identifier returned by add_network call.
 * @param bssid: MAC address of the AP
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_bssid(int id, uint8_t *bssid);

/**
 * @brief List of frequencies to be scanned. 
 *
 * @param id: Network identifier returned by add_network call.
 * @param freqs: Space separated frequencies in MHz.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_scan_freq(int id, int *freqs);

/**
 * @brief Setting to enable Protected Management Frame. This is a 
 * "per network" setting and overrides the pmf setting.
 *
 * @param id: Network identifier returned by add_network call.
 * @param ieee80211w: 0 for disabled, 1 for enabled and 2 for required.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_ieee80211w(int id, int ieee80211w);

/**
 * @brief: This setting enables the correct radio configuration as per the 
 * region's/country's regulation.
 *
 * @param country_code: 
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_country(const char *country_code);

/**
 * @brief Setting to enable Protected Management Frame. This is a global setting
 * applicable on all networks which don't have key_mgmt set to NONE.
 *
 * @param pmf: 0 for disabled, 1 for enabled and 2 for required.
 * @return: 0 for OK; -1 for ERROR
 */
int zephyr_supp_set_pmf(int pmf);

/**
 * @brief 
 * 
 * @param status_buf: Buffer which will be filled with status string.
 * Caller is responsible for memory allocation and free'ing of this buffer. 
 * @param buflen: Size of the allocated buffer. 
 * @return 0 for OK; -1 for ERROR
 */
int zephyr_supp_status(char *status_buf, size_t buflen);
#endif /* ZEPHYR_SUPP_MGMT_H */