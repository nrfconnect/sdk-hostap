/*
 * WPA Supplicant - command line interface for wpa_supplicant daemon
 * Copyright (c) 2004-2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#ifdef CONFIG_CTRL_IFACE

#ifdef CONFIG_CTRL_IFACE_UNIX
#include <dirent.h>
#endif /* CONFIG_CTRL_IFACE_UNIX */

#include "common/cli.h"
#include "common/wpa_ctrl.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/edit.h"
#include "utils/list.h"
#include "common/version.h"
#include "common/ieee802_11_defs.h"
#ifdef ANDROID
#include <cutils/properties.h>
#endif /* ANDROID */


static const char *const wpa_cli_version =
"wpa_cli v" VERSION_STR "\n"
"Copyright (c) 2004-2022, Jouni Malinen <j@w1.fi> and contributors";

struct wpa_ctrl *ctrl_conn;
char *ifname_prefix = NULL;

static struct wpa_ctrl *mon_conn;
static int wpa_cli_quit = 0;
static int wpa_cli_attached = 0;
static int wpa_cli_connected = -1;
static int wpa_cli_last_id = 0;
#ifndef CONFIG_CTRL_IFACE_DIR
#define CONFIG_CTRL_IFACE_DIR "/var/run/wpa_supplicant"
#endif /* CONFIG_CTRL_IFACE_DIR */
static const char *ctrl_iface_dir = CONFIG_CTRL_IFACE_DIR;
static const char *client_socket_dir = NULL;
static char *ctrl_ifname = NULL;
static const char *global = NULL;
static const char *pid_file = NULL;
static const char *action_file = NULL;
static int reconnect = 0;
static int ping_interval = 5;
static int interactive = 0;

static void print_help(const char *cmd);
static void wpa_cli_mon_receive(int sock, void *eloop_ctx, void *sock_ctx);
static void wpa_cli_close_connection(void);
static char * wpa_cli_get_default_ifname(void);
static char ** wpa_list_cmd_list(void);
static void update_creds(struct wpa_ctrl *ctrl);
static void update_networks(struct wpa_ctrl *ctrl);
static void update_stations(struct wpa_ctrl *ctrl);
static void update_ifnames(struct wpa_ctrl *ctrl);


static void usage(void)
{
	printf("wpa_cli [-p<path to ctrl sockets>] [-i<ifname>] [-hvBr] "
	       "[-a<action file>] \\\n"
	       "        [-P<pid file>] [-g<global ctrl>] [-G<ping interval>] "
	       "\\\n"
	       "        [-s<wpa_client_socket_file_path>] "
	       "[command..]\n"
	       "  -h = help (show this usage text)\n"
	       "  -v = shown version information\n"
	       "  -a = run in daemon mode executing the action file based on "
	       "events from\n"
	       "       wpa_supplicant\n"
	       "  -r = try to reconnect when client socket is disconnected.\n"
	       "       This is useful only when used with -a.\n"
	       "  -B = run a daemon in the background\n"
	       "  default path: " CONFIG_CTRL_IFACE_DIR "\n"
	       "  default interface: first interface found in socket path\n");
	print_help(NULL);
}


static int wpa_cli_show_event(const char *event)
{
	const char *start;

	start = os_strchr(event, '>');
	if (start == NULL)
		return 1;

	start++;
	/*
	 * Skip BSS added/removed events since they can be relatively frequent
	 * and are likely of not much use for an interactive user.
	 */
	if (str_starts(start, WPA_EVENT_BSS_ADDED) ||
	    str_starts(start, WPA_EVENT_BSS_REMOVED))
		return 0;

	return 1;
}


static int wpa_cli_open_connection(const char *ifname, int attach)
{
#if defined(CONFIG_CTRL_IFACE_UDP) || defined(CONFIG_CTRL_IFACE_NAMED_PIPE)
	ctrl_conn = wpa_ctrl_open(ifname);
	if (ctrl_conn == NULL)
		return -1;

	if (attach && interactive)
		mon_conn = wpa_ctrl_open(ifname);
	else
		mon_conn = NULL;
#else /* CONFIG_CTRL_IFACE_UDP || CONFIG_CTRL_IFACE_NAMED_PIPE */
	char *cfile = NULL;
	int flen, res;

	if (ifname == NULL)
		return -1;

#ifdef ANDROID
	if (access(ctrl_iface_dir, F_OK) < 0) {
		cfile = os_strdup(ifname);
		if (cfile == NULL)
			return -1;
	}
#endif /* ANDROID */

	if (client_socket_dir && client_socket_dir[0] &&
	    access(client_socket_dir, F_OK) < 0) {
		perror(client_socket_dir);
		os_free(cfile);
		return -1;
	}

	if (cfile == NULL) {
		flen = os_strlen(ctrl_iface_dir) + os_strlen(ifname) + 2;
		cfile = os_malloc(flen);
		if (cfile == NULL)
			return -1;
		res = os_snprintf(cfile, flen, "%s/%s", ctrl_iface_dir,
				  ifname);
		if (os_snprintf_error(flen, res)) {
			os_free(cfile);
			return -1;
		}
	}

	ctrl_conn = wpa_ctrl_open2(cfile, client_socket_dir);
	if (ctrl_conn == NULL) {
		os_free(cfile);
		return -1;
	}

	if (attach && interactive)
		mon_conn = wpa_ctrl_open2(cfile, client_socket_dir);
	else
		mon_conn = NULL;
	os_free(cfile);
#endif /* CONFIG_CTRL_IFACE_UDP || CONFIG_CTRL_IFACE_NAMED_PIPE */

	if (mon_conn) {
		if (wpa_ctrl_attach(mon_conn) == 0) {
			wpa_cli_attached = 1;
			if (interactive)
				eloop_register_read_sock(
					wpa_ctrl_get_fd(mon_conn),
					wpa_cli_mon_receive, NULL, NULL);
		} else {
			printf("Warning: Failed to attach to "
			       "wpa_supplicant.\n");
			wpa_cli_close_connection();
			return -1;
		}
	}

	return 0;
}


static void wpa_cli_close_connection(void)
{
	if (ctrl_conn == NULL)
		return;

	if (wpa_cli_attached) {
		wpa_ctrl_detach(interactive ? mon_conn : ctrl_conn);
		wpa_cli_attached = 0;
	}
	wpa_ctrl_close(ctrl_conn);
	ctrl_conn = NULL;
	if (mon_conn) {
		eloop_unregister_read_sock(wpa_ctrl_get_fd(mon_conn));
		wpa_ctrl_close(mon_conn);
		mon_conn = NULL;
	}
}


static void wpa_cli_msg_cb(char *msg, size_t len)
{
	printf("%s\n", msg);
}


static int _wpa_ctrl_command(struct wpa_ctrl *ctrl, const char *cmd, int print)
{
	char buf[4096];
	size_t len;
	int ret;

	if (ctrl_conn == NULL) {
		printf("Not connected to wpa_supplicant - command dropped.\n");
		return -1;
	}
	if (ifname_prefix) {
		os_snprintf(buf, sizeof(buf), "IFNAME=%s %s",
			    ifname_prefix, cmd);
		buf[sizeof(buf) - 1] = '\0';
		cmd = buf;
	}
	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, os_strlen(cmd), buf, &len,
			       wpa_cli_msg_cb);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}
	if (print) {
		buf[len] = '\0';
		printf("%s", buf);
		if (interactive && len > 0 && buf[len - 1] != '\n')
			printf("\n");
	}
	return 0;
}


int wpa_ctrl_command(struct wpa_ctrl *ctrl, const char *cmd)
{
	return _wpa_ctrl_command(ctrl, cmd, 1);
}


static int wpa_cli_cmd(struct wpa_ctrl *ctrl, const char *cmd, int min_args,
		       int argc, char *argv[])
{
	char buf[4096];
	if (argc < min_args) {
		printf("Invalid %s command - at least %d argument%s "
		       "required.\n", cmd, min_args,
		       min_args > 1 ? "s are" : " is");
		return -1;
	}
	if (write_cmd(buf, sizeof(buf), cmd, argc, argv) < 0)
		return -1;
	return wpa_ctrl_command(ctrl, buf);
}


/*
 * Prints command usage, lines are padded with the specified string.
 */
static void print_cmd_help(const struct wpa_cli_cmd *cmd, const char *pad)
{
	char c;
	size_t n;

	printf("%s%s ", pad, cmd->cmd);
	for (n = 0; (c = cmd->usage[n]); n++) {
		printf("%c", c);
		if (c == '\n')
			printf("%s", pad);
	}
	printf("\n");
}


static void print_help(const char *cmd)
{
	int n;
	printf("commands:\n");
	for (n = 0; wpa_cli_commands[n].cmd; n++) {
		if (cmd == NULL || str_starts(wpa_cli_commands[n].cmd, cmd))
			print_cmd_help(&wpa_cli_commands[n], "  ");
	}
}


static int wpa_cli_edit_filter_history_cb(void *ctx, const char *cmd)
{
	const char *c, *delim;
	int n;
	size_t len;

	delim = os_strchr(cmd, ' ');
	if (delim)
		len = delim - cmd;
	else
		len = os_strlen(cmd);

	for (n = 0; (c = wpa_cli_commands[n].cmd); n++) {
		if (os_strncasecmp(cmd, c, len) == 0 && len == os_strlen(c))
			return (wpa_cli_commands[n].flags &
				cli_cmd_flag_sensitive);
	}
	return 0;
}


static char ** wpa_list_cmd_list(void)
{
	char **res;
	int i, count;
	struct cli_txt_entry *e;

	count = ARRAY_SIZE(wpa_cli_commands);
	count += dl_list_len(&p2p_groups);
	count += dl_list_len(&ifnames);
	res = os_calloc(count + 1, sizeof(char *));
	if (res == NULL)
		return NULL;

	for (i = 0; wpa_cli_commands[i].cmd; i++) {
		res[i] = os_strdup(wpa_cli_commands[i].cmd);
		if (res[i] == NULL)
			break;
	}

	dl_list_for_each(e, &p2p_groups, struct cli_txt_entry, list) {
		size_t len = 8 + os_strlen(e->txt);
		res[i] = os_malloc(len);
		if (res[i] == NULL)
			break;
		os_snprintf(res[i], len, "ifname=%s", e->txt);
		i++;
	}

	dl_list_for_each(e, &ifnames, struct cli_txt_entry, list) {
		res[i] = os_strdup(e->txt);
		if (res[i] == NULL)
			break;
		i++;
	}

	return res;
}


static char ** wpa_cli_cmd_completion(const char *cmd, const char *str,
				      int pos)
{
	int i;

	for (i = 0; wpa_cli_commands[i].cmd; i++) {
		if (os_strcasecmp(wpa_cli_commands[i].cmd, cmd) == 0) {
			if (wpa_cli_commands[i].completion)
				return wpa_cli_commands[i].completion(str,
								      pos);
			edit_clear_line();
			printf("\r%s\n", wpa_cli_commands[i].usage);
			edit_redraw();
			break;
		}
	}

	return NULL;
}


static char ** wpa_cli_edit_completion_cb(void *ctx, const char *str, int pos)
{
	char **res;
	const char *end;
	char *cmd;

	if (pos > 7 && os_strncasecmp(str, "IFNAME=", 7) == 0) {
		end = os_strchr(str, ' ');
		if (end && pos > end - str) {
			pos -= end - str + 1;
			str = end + 1;
		}
	}

	end = os_strchr(str, ' ');
	if (end == NULL || str + pos < end)
		return wpa_list_cmd_list();

	cmd = os_malloc(pos + 1);
	if (cmd == NULL)
		return NULL;
	os_memcpy(cmd, str, pos);
	cmd[end - str] = '\0';
	res = wpa_cli_cmd_completion(cmd, str, pos);
	os_free(cmd);
	return res;
}


static int wpa_request(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	const struct wpa_cli_cmd *cmd, *match = NULL;
	int count;
	int ret = 0;

	if (argc > 1 && os_strncasecmp(argv[0], "IFNAME=", 7) == 0) {
		ifname_prefix = argv[0] + 7;
		argv = &argv[1];
		argc--;
	} else
		ifname_prefix = NULL;

	if (argc == 0)
		return -1;

	count = 0;
	cmd = wpa_cli_commands;
	while (cmd->cmd) {
		if (os_strncasecmp(cmd->cmd, argv[0], os_strlen(argv[0])) == 0)
		{
			match = cmd;
			if (os_strcasecmp(cmd->cmd, argv[0]) == 0) {
				/* we have an exact match */
				count = 1;
				break;
			}
			count++;
		}
		cmd++;
	}

	if (count > 1) {
		printf("Ambiguous command '%s'; possible commands:", argv[0]);
		cmd = wpa_cli_commands;
		while (cmd->cmd) {
			if (os_strncasecmp(cmd->cmd, argv[0],
					   os_strlen(argv[0])) == 0) {
				printf(" %s", cmd->cmd);
			}
			cmd++;
		}
		printf("\n");
		ret = 1;
	} else if (count == 0) {
		printf("Unknown command '%s'\n", argv[0]);
		ret = 1;
	} else {
		ret = match->handler(ctrl, argc - 1, &argv[1]);
	}

	return ret;
}


static int wpa_cli_exec(const char *program, const char *arg1,
			const char *arg2)
{
	char *arg;
	size_t len;
	int res;

	/* If no interface is specified, set the global */
	if (!arg1)
		arg1 = "global";

	len = os_strlen(arg1) + os_strlen(arg2) + 2;
	arg = os_malloc(len);
	if (arg == NULL)
		return -1;
	os_snprintf(arg, len, "%s %s", arg1, arg2);
	res = os_exec(program, arg, 1);
	os_free(arg);

	return res;
}


static void wpa_cli_action_process(const char *msg)
{
	const char *pos;
	char *copy = NULL, *id, *pos2;
	const char *ifname = ctrl_ifname;
	char ifname_buf[100];

	if (eloop_terminated())
		return;

	pos = msg;
	if (os_strncmp(pos, "IFNAME=", 7) == 0) {
		const char *end;
		end = os_strchr(pos + 7, ' ');
		if (end && (unsigned int) (end - pos) < sizeof(ifname_buf)) {
			pos += 7;
			os_memcpy(ifname_buf, pos, end - pos);
			ifname_buf[end - pos] = '\0';
			ifname = ifname_buf;
			pos = end + 1;
		}
	}
	if (*pos == '<') {
		const char *prev = pos;
		/* skip priority */
		pos = os_strchr(pos, '>');
		if (pos)
			pos++;
		else
			pos = prev;
	}

	if (str_starts(pos, WPA_EVENT_CONNECTED)) {
		int new_id = -1;
		os_unsetenv("WPA_ID");
		os_unsetenv("WPA_ID_STR");
		os_unsetenv("WPA_CTRL_DIR");

		pos = os_strstr(pos, "[id=");
		if (pos)
			copy = os_strdup(pos + 4);

		if (copy) {
			pos2 = id = copy;
			while (*pos2 && *pos2 != ' ')
				pos2++;
			*pos2++ = '\0';
			new_id = atoi(id);
			os_setenv("WPA_ID", id, 1);
			while (*pos2 && *pos2 != '=')
				pos2++;
			if (*pos2 == '=')
				pos2++;
			id = pos2;
			while (*pos2 && *pos2 != ']')
				pos2++;
			*pos2 = '\0';
			os_setenv("WPA_ID_STR", id, 1);
			os_free(copy);
		}

		os_setenv("WPA_CTRL_DIR", ctrl_iface_dir, 1);

		if (wpa_cli_connected <= 0 || new_id != wpa_cli_last_id) {
			wpa_cli_connected = 1;
			wpa_cli_last_id = new_id;
			wpa_cli_exec(action_file, ifname, "CONNECTED");
		}
	} else if (str_starts(pos, WPA_EVENT_DISCONNECTED)) {
		if (wpa_cli_connected) {
			wpa_cli_connected = 0;
			wpa_cli_exec(action_file, ifname, "DISCONNECTED");
		}
	} else if (str_starts(pos, WPA_EVENT_CHANNEL_SWITCH_STARTED)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_starts(pos, AP_EVENT_ENABLED)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_starts(pos, AP_EVENT_DISABLED)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_starts(pos, MESH_GROUP_STARTED)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_starts(pos, MESH_GROUP_REMOVED)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_starts(pos, MESH_PEER_CONNECTED)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_starts(pos, MESH_PEER_DISCONNECTED)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_starts(pos, P2P_EVENT_GROUP_STARTED)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, P2P_EVENT_GROUP_REMOVED)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, P2P_EVENT_CROSS_CONNECT_ENABLE)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, P2P_EVENT_CROSS_CONNECT_DISABLE)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, P2P_EVENT_GO_NEG_FAILURE)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, WPS_EVENT_SUCCESS)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, WPS_EVENT_ACTIVE)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, WPS_EVENT_OVERLAP)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, WPS_EVENT_PIN_ACTIVE)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, WPS_EVENT_CANCEL)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, WPS_EVENT_TIMEOUT)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, WPS_EVENT_FAIL)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, AP_STA_CONNECTED)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, AP_STA_DISCONNECTED)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, ESS_DISASSOC_IMMINENT)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, HS20_SUBSCRIPTION_REMEDIATION)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, HS20_DEAUTH_IMMINENT_NOTICE)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, HS20_T_C_ACCEPTANCE)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, DPP_EVENT_CONF_RECEIVED)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, DPP_EVENT_CONFOBJ_AKM)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, DPP_EVENT_CONFOBJ_SSID)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, DPP_EVENT_CONNECTOR)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, DPP_EVENT_CONFOBJ_PASS)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, DPP_EVENT_CONFOBJ_PSK)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, DPP_EVENT_C_SIGN_KEY)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, DPP_EVENT_NET_ACCESS_KEY)) {
		wpa_cli_exec(action_file, ifname, pos);
	} else if (str_starts(pos, WPA_EVENT_TERMINATING)) {
		printf("wpa_supplicant is terminating - stop monitoring\n");
		if (!reconnect)
			wpa_cli_quit = 1;
	}
}


#ifndef CONFIG_ANSI_C_EXTRA
static void wpa_cli_action_cb(char *msg, size_t len)
{
	wpa_cli_action_process(msg);
}
#endif /* CONFIG_ANSI_C_EXTRA */


static int wpa_cli_open_global_ctrl(void)
{
#ifdef CONFIG_CTRL_IFACE_NAMED_PIPE
	ctrl_conn = wpa_ctrl_open(NULL);
#else /* CONFIG_CTRL_IFACE_NAMED_PIPE */
	ctrl_conn = wpa_ctrl_open(global);
#endif /* CONFIG_CTRL_IFACE_NAMED_PIPE */
	if (!ctrl_conn) {
		fprintf(stderr,
			"Failed to connect to wpa_supplicant global interface: %s  error: %s\n",
			global, strerror(errno));
		return -1;
	}

	if (interactive) {
		update_ifnames(ctrl_conn);
		mon_conn = wpa_ctrl_open(global);
		if (mon_conn) {
			if (wpa_ctrl_attach(mon_conn) == 0) {
				wpa_cli_attached = 1;
				eloop_register_read_sock(
					wpa_ctrl_get_fd(mon_conn),
					wpa_cli_mon_receive,
					NULL, NULL);
			} else {
				printf("Failed to open monitor connection through global control interface\n");
			}
		}
		update_stations(ctrl_conn);
	}

	return 0;
}


static void wpa_cli_reconnect(void)
{
	wpa_cli_close_connection();
	if ((global && wpa_cli_open_global_ctrl() < 0) ||
	    (!global && wpa_cli_open_connection(ctrl_ifname, 1) < 0))
		return;

	if (interactive) {
		edit_clear_line();
		printf("\rConnection to wpa_supplicant re-established\n");
		edit_redraw();
		update_stations(ctrl_conn);
	}
}


static void cli_event(const char *str)
{
	const char *start, *s;

	start = os_strchr(str, '>');
	if (start == NULL)
		return;

	start++;

	if (str_starts(start, WPA_EVENT_BSS_ADDED)) {
		s = os_strchr(start, ' ');
		if (s == NULL)
			return;
		s = os_strchr(s + 1, ' ');
		if (s == NULL)
			return;
		cli_txt_list_add(&bsses, s + 1);
		return;
	}

	if (str_starts(start, WPA_EVENT_BSS_REMOVED)) {
		s = os_strchr(start, ' ');
		if (s == NULL)
			return;
		s = os_strchr(s + 1, ' ');
		if (s == NULL)
			return;
		cli_txt_list_del_addr(&bsses, s + 1);
		return;
	}

#ifdef CONFIG_P2P
	if (str_starts(start, P2P_EVENT_DEVICE_FOUND)) {
		s = os_strstr(start, " p2p_dev_addr=");
		if (s == NULL)
			return;
		cli_txt_list_add_addr(&p2p_peers, s + 14);
		return;
	}

	if (str_starts(start, P2P_EVENT_DEVICE_LOST)) {
		s = os_strstr(start, " p2p_dev_addr=");
		if (s == NULL)
			return;
		cli_txt_list_del_addr(&p2p_peers, s + 14);
		return;
	}

	if (str_starts(start, P2P_EVENT_GROUP_STARTED)) {
		s = os_strchr(start, ' ');
		if (s == NULL)
			return;
		cli_txt_list_add_word(&p2p_groups, s + 1, ' ');
		return;
	}

	if (str_starts(start, P2P_EVENT_GROUP_REMOVED)) {
		s = os_strchr(start, ' ');
		if (s == NULL)
			return;
		cli_txt_list_del_word(&p2p_groups, s + 1, ' ');
		return;
	}
#endif /* CONFIG_P2P */
}


static int check_terminating(const char *msg)
{
	const char *pos = msg;

	if (*pos == '<') {
		/* skip priority */
		pos = os_strchr(pos, '>');
		if (pos)
			pos++;
		else
			pos = msg;
	}

	if (str_starts(pos, WPA_EVENT_TERMINATING) && ctrl_conn) {
		edit_clear_line();
		printf("\rConnection to wpa_supplicant lost - trying to "
		       "reconnect\n");
		edit_redraw();
		wpa_cli_attached = 0;
		wpa_cli_close_connection();
		return 1;
	}

	return 0;
}


static void wpa_cli_recv_pending(struct wpa_ctrl *ctrl, int action_monitor)
{
	if (ctrl_conn == NULL) {
		wpa_cli_reconnect();
		return;
	}
	while (wpa_ctrl_pending(ctrl) > 0) {
		char buf[4096];
		size_t len = sizeof(buf) - 1;
		if (wpa_ctrl_recv(ctrl, buf, &len) == 0) {
			buf[len] = '\0';
			if (action_monitor)
				wpa_cli_action_process(buf);
			else {
				cli_event(buf);
				if (wpa_cli_show_event(buf)) {
					edit_clear_line();
					printf("\r%s\n", buf);
					edit_redraw();
				}

				if (interactive && check_terminating(buf) > 0)
					return;
			}
		} else {
			printf("Could not read pending message.\n");
			break;
		}
	}

	if (wpa_ctrl_pending(ctrl) < 0) {
		printf("Connection to wpa_supplicant lost - trying to "
		       "reconnect\n");
		if (reconnect) {
			eloop_terminate();
			return;
		}
		wpa_cli_reconnect();
	}
}


static void wpa_cli_ping(void *eloop_ctx, void *timeout_ctx)
{
	if (ctrl_conn) {
		int res;
		char *prefix = ifname_prefix;

		ifname_prefix = NULL;
		res = _wpa_ctrl_command(ctrl_conn, "PING", 0);
		ifname_prefix = prefix;
		if (res) {
			printf("Connection to wpa_supplicant lost - trying to "
			       "reconnect\n");
			wpa_cli_close_connection();
		}
	}
	if (!ctrl_conn)
		wpa_cli_reconnect();
	eloop_register_timeout(ping_interval, 0, wpa_cli_ping, NULL, NULL);
}


static void wpa_cli_mon_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	wpa_cli_recv_pending(mon_conn, 0);
}


static void wpa_cli_edit_cmd_cb(void *ctx, char *cmd)
{
	char *argv[max_args];
	int argc;
	argc = tokenize_cmd(cmd, argv);
	if (argc)
		wpa_request(ctrl_conn, argc, argv);
}


static void wpa_cli_edit_eof_cb(void *ctx)
{
	eloop_terminate();
}


static int warning_displayed = 0;
static char *hfile = NULL;
static int edit_started = 0;

static void start_edit(void)
{
	char *home;
	char *ps = NULL;

#ifdef CONFIG_CTRL_IFACE_UDP_REMOTE
	ps = wpa_ctrl_get_remote_ifname(ctrl_conn);
#endif /* CONFIG_CTRL_IFACE_UDP_REMOTE */

#ifdef CONFIG_WPA_CLI_HISTORY_DIR
	home = CONFIG_WPA_CLI_HISTORY_DIR;
#else /* CONFIG_WPA_CLI_HISTORY_DIR */
	home = getenv("HOME");
#endif /* CONFIG_WPA_CLI_HISTORY_DIR */
	if (home) {
		const char *fname = ".wpa_cli_history";
		int hfile_len = os_strlen(home) + 1 + os_strlen(fname) + 1;
		hfile = os_malloc(hfile_len);
		if (hfile)
			os_snprintf(hfile, hfile_len, "%s/%s", home, fname);
	}

	if (edit_init(wpa_cli_edit_cmd_cb, wpa_cli_edit_eof_cb,
		      wpa_cli_edit_completion_cb, NULL, hfile, ps) < 0) {
		eloop_terminate();
		return;
	}

	edit_started = 1;
	eloop_register_timeout(ping_interval, 0, wpa_cli_ping, NULL, NULL);
}


static void update_bssid_list(struct wpa_ctrl *ctrl)
{
	char buf[4096];
	size_t len = sizeof(buf);
	int ret;
	const char *cmd = "BSS RANGE=ALL MASK=0x2";
	char *pos, *end;

	if (ctrl == NULL)
		return;
	ret = wpa_ctrl_request(ctrl, cmd, os_strlen(cmd), buf, &len, NULL);
	if (ret < 0)
		return;
	buf[len] = '\0';

	pos = buf;
	while (pos) {
		pos = os_strstr(pos, "bssid=");
		if (pos == NULL)
			break;
		pos += 6;
		end = os_strchr(pos, '\n');
		if (end == NULL)
			break;
		*end = '\0';
		cli_txt_list_add(&bsses, pos);
		pos = end + 1;
	}
}


static void update_ifnames(struct wpa_ctrl *ctrl)
{
	char buf[4096];
	size_t len = sizeof(buf);
	int ret;
	const char *cmd = "INTERFACES";
	char *pos, *end;
	char txt[200];

	cli_txt_list_flush(&ifnames);

	if (ctrl == NULL)
		return;
	ret = wpa_ctrl_request(ctrl, cmd, os_strlen(cmd), buf, &len, NULL);
	if (ret < 0)
		return;
	buf[len] = '\0';

	pos = buf;
	while (pos) {
		end = os_strchr(pos, '\n');
		if (end == NULL)
			break;
		*end = '\0';
		ret = os_snprintf(txt, sizeof(txt), "ifname=%s", pos);
		if (!os_snprintf_error(sizeof(txt), ret))
			cli_txt_list_add(&ifnames, txt);
		pos = end + 1;
	}
}


static void update_creds(struct wpa_ctrl *ctrl)
{
	char buf[4096];
	size_t len = sizeof(buf);
	int ret;
	const char *cmd = "LIST_CREDS";
	char *pos, *end;
	int header = 1;

	cli_txt_list_flush(&creds);

	if (ctrl == NULL)
		return;
	ret = wpa_ctrl_request(ctrl, cmd, os_strlen(cmd), buf, &len, NULL);
	if (ret < 0)
		return;
	buf[len] = '\0';

	pos = buf;
	while (pos) {
		end = os_strchr(pos, '\n');
		if (end == NULL)
			break;
		*end = '\0';
		if (!header)
			cli_txt_list_add_word(&creds, pos, '\t');
		header = 0;
		pos = end + 1;
	}
}


static void update_networks(struct wpa_ctrl *ctrl)
{
	char buf[4096];
	size_t len = sizeof(buf);
	int ret;
	const char *cmd = "LIST_NETWORKS";
	char *pos, *end;
	int header = 1;

	cli_txt_list_flush(&networks);

	if (ctrl == NULL)
		return;
	ret = wpa_ctrl_request(ctrl, cmd, os_strlen(cmd), buf, &len, NULL);
	if (ret < 0)
		return;
	buf[len] = '\0';

	pos = buf;
	while (pos) {
		end = os_strchr(pos, '\n');
		if (end == NULL)
			break;
		*end = '\0';
		if (!header)
			cli_txt_list_add_word(&networks, pos, '\t');
		header = 0;
		pos = end + 1;
	}
}


static void update_stations(struct wpa_ctrl *ctrl)
{
#ifdef CONFIG_AP
	char addr[32], cmd[64];

	if (!ctrl || !interactive)
		return;

	cli_txt_list_flush(&stations);

	if (wpa_ctrl_command_sta(ctrl, "STA-FIRST", addr, sizeof(addr), 0))
		return;
	do {
		if (os_strcmp(addr, "") != 0)
			cli_txt_list_add(&stations, addr);
		os_snprintf(cmd, sizeof(cmd), "STA-NEXT %s", addr);
	} while (wpa_ctrl_command_sta(ctrl, cmd, addr, sizeof(addr), 0) == 0);
#endif /* CONFIG_AP */
}


static void try_connection(void *eloop_ctx, void *timeout_ctx)
{
	if (ctrl_conn)
		goto done;

	if (ctrl_ifname == NULL)
		ctrl_ifname = wpa_cli_get_default_ifname();

	if (wpa_cli_open_connection(ctrl_ifname, 1)) {
		if (!warning_displayed) {
			printf("Could not connect to wpa_supplicant: "
			       "%s - re-trying\n",
			       ctrl_ifname ? ctrl_ifname : "(nil)");
			warning_displayed = 1;
		}
		eloop_register_timeout(1, 0, try_connection, NULL, NULL);
		return;
	}

	update_bssid_list(ctrl_conn);
	update_creds(ctrl_conn);
	update_networks(ctrl_conn);
	update_stations(ctrl_conn);

	if (warning_displayed)
		printf("Connection established.\n");

done:
	start_edit();
}


static void wpa_cli_interactive(void)
{
	printf("\nInteractive mode\n\n");

	eloop_register_timeout(0, 0, try_connection, NULL, NULL);
	eloop_run();
	eloop_cancel_timeout(try_connection, NULL, NULL);

	cli_txt_list_flush(&p2p_peers);
	cli_txt_list_flush(&p2p_groups);
	cli_txt_list_flush(&bsses);
	cli_txt_list_flush(&ifnames);
	cli_txt_list_flush(&creds);
	cli_txt_list_flush(&networks);
	if (edit_started)
		edit_deinit(hfile, wpa_cli_edit_filter_history_cb);
	os_free(hfile);
	eloop_cancel_timeout(wpa_cli_ping, NULL, NULL);
	wpa_cli_close_connection();
}


static void wpa_cli_action_ping(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_ctrl *ctrl = eloop_ctx;
	char buf[256];
	size_t len;

	/* verify that connection is still working */
	len = sizeof(buf) - 1;
	if (wpa_ctrl_request(ctrl, "PING", 4, buf, &len,
			     wpa_cli_action_cb) < 0 ||
	    len < 4 || os_memcmp(buf, "PONG", 4) != 0) {
		printf("wpa_supplicant did not reply to PING command - exiting\n");
		eloop_terminate();
		return;
	}
	eloop_register_timeout(ping_interval, 0, wpa_cli_action_ping,
			       ctrl, NULL);
}


static void wpa_cli_action_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct wpa_ctrl *ctrl = eloop_ctx;

	wpa_cli_recv_pending(ctrl, 1);
}


static void wpa_cli_action(struct wpa_ctrl *ctrl)
{
#ifdef CONFIG_ANSI_C_EXTRA
	/* TODO: ANSI C version(?) */
	printf("Action processing not supported in ANSI C build.\n");
#else /* CONFIG_ANSI_C_EXTRA */
	int fd;

	fd = wpa_ctrl_get_fd(ctrl);
	eloop_register_timeout(ping_interval, 0, wpa_cli_action_ping,
			       ctrl, NULL);
	eloop_register_read_sock(fd, wpa_cli_action_receive, ctrl, NULL);
	eloop_run();
	eloop_cancel_timeout(wpa_cli_action_ping, ctrl, NULL);
	eloop_unregister_read_sock(fd);
#endif /* CONFIG_ANSI_C_EXTRA */
}


static void wpa_cli_cleanup(void)
{
	wpa_cli_close_connection();
	if (pid_file)
		os_daemonize_terminate(pid_file);

	os_program_deinit();
}


static void wpa_cli_terminate(int sig, void *ctx)
{
	eloop_terminate();
	if (reconnect)
		wpa_cli_quit = 1;
}


static char * wpa_cli_get_default_ifname(void)
{
	char *ifname = NULL;

#ifdef ANDROID
	char ifprop[PROPERTY_VALUE_MAX];
	if (property_get("wifi.interface", ifprop, NULL) != 0) {
		ifname = os_strdup(ifprop);
		printf("Using interface '%s'\n", ifname ? ifname : "N/A");
	}
#else /* ANDROID */
#ifdef CONFIG_CTRL_IFACE_UNIX
	struct dirent *dent;
	DIR *dir = opendir(ctrl_iface_dir);
	if (!dir) {
		return NULL;
	}
	while ((dent = readdir(dir))) {
#ifdef _DIRENT_HAVE_D_TYPE
		/*
		 * Skip the file if it is not a socket. Also accept
		 * DT_UNKNOWN (0) in case the C library or underlying
		 * file system does not support d_type.
		 */
		if (dent->d_type != DT_SOCK && dent->d_type != DT_UNKNOWN)
			continue;
#endif /* _DIRENT_HAVE_D_TYPE */
		/* Skip current/previous directory and special P2P Device
		 * interfaces. */
		if (os_strcmp(dent->d_name, ".") == 0 ||
		    os_strcmp(dent->d_name, "..") == 0 ||
		    os_strncmp(dent->d_name, "p2p-dev-", 8) == 0)
			continue;
		printf("Selected interface '%s'\n", dent->d_name);
		ifname = os_strdup(dent->d_name);
		break;
	}
	closedir(dir);
#endif /* CONFIG_CTRL_IFACE_UNIX */

#ifdef CONFIG_CTRL_IFACE_NAMED_PIPE
	char buf[4096], *pos;
	size_t len;
	struct wpa_ctrl *ctrl;
	int ret;

	ctrl = wpa_ctrl_open(NULL);
	if (ctrl == NULL)
		return NULL;

	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, "INTERFACES", 10, buf, &len, NULL);
	if (ret >= 0) {
		buf[len] = '\0';
		pos = os_strchr(buf, '\n');
		if (pos)
			*pos = '\0';
		ifname = os_strdup(buf);
	}
	wpa_ctrl_close(ctrl);
#endif /* CONFIG_CTRL_IFACE_NAMED_PIPE */
#endif /* ANDROID */

	return ifname;
}


int main(int argc, char *argv[])
{
	int c;
	int daemonize = 0;
	int ret = 0;

	if (os_program_init())
		return -1;

	for (;;) {
		c = getopt(argc, argv, "a:Bg:G:hi:p:P:rs:v");
		if (c < 0)
			break;
		switch (c) {
		case 'a':
			action_file = optarg;
			break;
		case 'B':
			daemonize = 1;
			break;
		case 'g':
			global = optarg;
			break;
		case 'G':
			ping_interval = atoi(optarg);
			break;
		case 'h':
			usage();
			return 0;
		case 'v':
			printf("%s\n", wpa_cli_version);
			return 0;
		case 'i':
			os_free(ctrl_ifname);
			ctrl_ifname = os_strdup(optarg);
			break;
		case 'p':
			ctrl_iface_dir = optarg;
			break;
		case 'P':
			pid_file = optarg;
			break;
		case 'r':
			reconnect = 1;
			break;
		case 's':
			client_socket_dir = optarg;
			break;
		default:
			usage();
			return -1;
		}
	}

	interactive = (argc == optind) && (action_file == NULL);

	if (interactive)
		printf("%s\n\n%s\n\n", wpa_cli_version, cli_license);

	if (eloop_init())
		return -1;

	if (global && wpa_cli_open_global_ctrl() < 0)
		return -1;

	eloop_register_signal_terminate(wpa_cli_terminate, NULL);

	if (ctrl_ifname == NULL)
		ctrl_ifname = wpa_cli_get_default_ifname();

	if (reconnect && action_file && ctrl_ifname) {
		while (!wpa_cli_quit) {
			if (ctrl_conn)
				wpa_cli_action(ctrl_conn);
			else
				os_sleep(1, 0);
			wpa_cli_close_connection();
			wpa_cli_open_connection(ctrl_ifname, 0);
			if (ctrl_conn) {
				if (wpa_ctrl_attach(ctrl_conn) != 0)
					wpa_cli_close_connection();
				else
					wpa_cli_attached = 1;
			}
		}
	} else if (interactive) {
		wpa_cli_interactive();
	} else {
		if (!global &&
		    wpa_cli_open_connection(ctrl_ifname, 0) < 0) {
			fprintf(stderr, "Failed to connect to non-global "
				"ctrl_ifname: %s  error: %s\n",
				ctrl_ifname ? ctrl_ifname : "(nil)",
				strerror(errno));
			return -1;
		}

		if (action_file) {
			if (wpa_ctrl_attach(ctrl_conn) == 0) {
				wpa_cli_attached = 1;
			} else {
				printf("Warning: Failed to attach to "
				       "wpa_supplicant.\n");
				return -1;
			}
		}

		if (daemonize && os_daemonize(pid_file) && eloop_sock_requeue())
			return -1;

		if (action_file)
			wpa_cli_action(ctrl_conn);
		else
			ret = wpa_request(ctrl_conn, argc - optind,
					  &argv[optind]);
	}

	os_free(ctrl_ifname);
	eloop_destroy();
	wpa_cli_cleanup();

	return ret;
}

#else /* CONFIG_CTRL_IFACE */
int main(int argc, char *argv[])
{
	printf("CONFIG_CTRL_IFACE not defined - wpa_cli disabled\n");
	return -1;
}
#endif /* CONFIG_CTRL_IFACE */
