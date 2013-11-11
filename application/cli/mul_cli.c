/*
 *  mul_cli.c: CLI application for MUL Controller 
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "mul_cli.h"

cli_struct_t *cli;

static int cli_init_mul_service(cli_struct_t *cli, struct vty *vty);
static void cli_core_closed(void);
static void cli_core_reconn(void);

struct mul_app_client_cb cli_app_cbs = {
    .core_conn_closed = cli_core_closed,
    .core_conn_reconn = cli_core_reconn
};

static void
cli_core_closed(void)
{
    c_log_info("%s: ", FN);
    return;
}

static void
cli_core_reconn(void)
{
    c_log_info("%s: ", FN);
    mul_register_app_cb(NULL, CLI_APP_NAME, C_APP_ALL_SW, C_DP_REG | C_DP_UNREG,
                        0, NULL, &cli_app_cbs);
}

/**
 * nbapi_dump -
 */
static void
nbapi_dump(void *vty_arg, void *buf)
{
    int                     sent_sz;
    struct vty              *vty = vty_arg;
    int                     retries = 10;
    nbapi_resp_message_t    *header = buf;
    int                     buf_len = header->len;
    
        
try_again:
    sent_sz = send(vty->fd, buf, buf_len, MSG_NOSIGNAL);
    if (sent_sz <= 0) {
        if (errno == EINTR) goto retry;
        goto out;
    }

    if (sent_sz < buf_len) {
        buf_len -= sent_sz;
        buf = (char *)buf + sent_sz;
        goto retry;
    }


out:
    free(header);
    return;

retry:
    if (retries-- <= 0) {
        goto out;
    }

    goto try_again;
}

/**
 * nbapi_dump_err -
 *
 * Note - err_str will not be freed here
 */
static int 
return_vty(void *vty_arg, uint16_t type, uint16_t status,
           char *err_str)
{
    struct vty *vty = vty_arg;
    nbapi_resp_config_status_t *resp;

    if (vty->type != VTY_NBAPI) {
        if (err_str) {
            vty_out(vty, "%s%s", err_str, VTY_NEWLINE);
        }
        return status;
    }

    resp = calloc(1, sizeof(*resp));
    if (!resp) {
        c_log_err("%s: [PANIC] Buf alloc failed", FN);
        return status;
    }

    resp->header.type = type;
    resp->header.len = sizeof(*resp);
    resp->status = status;
    
    nbapi_dump(vty_arg, resp);

    return status; 
}

/**
 * vty_dump -
 */
static void
vty_dump(void *vty, void *pbuf)
{
    vty_out((struct vty *)vty, "%s", (char *)pbuf);
}

/** 
 * cli_recv_err_msg -
 *
 * Handler for error notifications from controller/switch 
 */
static void UNUSED
cli_recv_err_msg(cli_struct_t *cli UNUSED, c_ofp_error_msg_t *cofp_err)
{
    c_log_err("%s: Controller sent error type %hu code %hu", FN,
               ntohs(cofp_err->type), ntohs(cofp_err->code));

    /* FIXME : Handle errors */
}

static void
mul_core_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_err("%s: %d", FN, conn_event);
}

static void
mul_tr_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_err("%s: %d", FN, conn_event);
}


static void
mul_fab_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_err("%s: %d", FN, conn_event);
}

static int
cli_init_mul_service(cli_struct_t *cli, struct vty *vty)
{
     if (!cli->mul_service) {
        cli->mul_service = mul_app_get_service_notify(MUL_CORE_SERVICE_NAME,
                                                  mul_core_service_conn_event,
                                                  false, NULL);
        if (!cli->mul_service) {
            if (vty) vty_out(vty, "mul-core service is not alive");
            return CMD_WARNING;
        }
    } else if (!mul_service_available(cli->mul_service)) {
         if (vty) vty_out(vty, "mul-core service is not alive");
         return CMD_WARNING;
    }

    return 0;
}

static int
cli_init_fab_service(cli_struct_t *cli, struct vty *vty)
{
     if (!cli->fab_service) {
        cli->fab_service = mul_app_get_service_notify(MUL_FAB_CLI_SERVICE_NAME,
                                                  mul_fab_service_conn_event,
                                                  false, NULL);
        if (!cli->fab_service) {
            return return_vty(vty, NB_CONFIG_OF_FAB_MODE,
                              CMD_WARNING, "mul-fab dead");
        }
    } else if (!mul_service_available(cli->fab_service)) {
        return return_vty(vty, NB_CONFIG_OF_FAB_MODE,
                          CMD_WARNING, "mul-fab dead");
    }

    return 0;
}

static int
cli_init_tr_service(cli_struct_t *cli, struct vty *vty)
{
     if (!cli->tr_service) {
        cli->tr_service = mul_app_get_service_notify(MUL_TR_SERVICE_NAME,
                                                  mul_tr_service_conn_event,
                                                  false, NULL);
        if (!cli->tr_service) {
            return return_vty(vty, NB_CONFIG_OF_TR_MODE,
                              CMD_WARNING, "mul-tr dead");
        }
    } else if (!mul_service_available(cli->tr_service)) {
        return return_vty(vty, NB_CONFIG_OF_TR_MODE,
                          CMD_WARNING, "mul-tr dead");
    }

    return 0;
}

static void UNUSED
cli_exit_mul_service(cli_struct_t *cli)
{
    if (cli->mul_service) {
        mul_app_destroy_service(cli->mul_service);
        cli->mul_service = NULL;
    }
}

static void UNUSED
cli_exit_fab_service(cli_struct_t *cli)
{
    if (cli->fab_service) {
        mul_app_destroy_service(cli->fab_service);
        cli->fab_service = NULL;
    }
}

static void UNUSED
cli_exit_tr_service(cli_struct_t *cli)
{
    if (cli->tr_service) {
        mul_app_destroy_service(cli->tr_service);
        cli->tr_service = NULL;
    }
}


static void
cli_timer(evutil_socket_t fd UNUSED, short event UNUSED, void *arg UNUSED)
{
    struct timeval update_tv = { CLI_TIMER_TS, CLI_TIMER_TUS };

    evtimer_add(cli->timer_event, &update_tv);
}

/**
 * cli_module_init -
 *
 * CLI application entry point 
 */
void
cli_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval update_tv = { CLI_TIMER_INIT_TS, CLI_TIMER_INIT_TUS };
    
    c_log_debug("%s", FN);

    cli = calloc(1, sizeof(cli_struct_t));
    assert(cli);

    c_rw_lock_init(&cli->lock);
    cli->base = base;

    cli->mul_service = mul_app_get_service_notify(MUL_CORE_SERVICE_NAME,
                                                  mul_core_service_conn_event,
                                                  false, NULL);
    if (cli->mul_service == NULL) {
        c_log_err("%s:  Mul core service instantiation failed", FN);
    }
    cli->tr_service = mul_app_get_service_notify(MUL_TR_SERVICE_NAME,
                                                 mul_tr_service_conn_event,
                                                 false, NULL);
    if (cli->tr_service == NULL) {
        c_log_err("%s:  Mul TR service instantiation failed", FN);
    }
    cli->fab_service = mul_app_get_service_notify(MUL_FAB_CLI_SERVICE_NAME,
                                                  mul_fab_service_conn_event,
                                                  false, NULL);
    if (cli->fab_service == NULL) {
        c_log_err("%s:  Mul fab service instantiation failed", FN);
    }

    cli->cli_list = g_slist_append(cli->cli_list, "mul-core");
    cli->cli_list = g_slist_append(cli->cli_list, "mul-tr");
    cli->cli_list = g_slist_append(cli->cli_list, "mul-fab");
    
    cli->timer_event = evtimer_new(base, cli_timer, (void *)cli);
    evtimer_add(cli->timer_event, &update_tv);

    mul_register_app_cb(NULL, CLI_APP_NAME, C_APP_ALL_SW, C_DP_REG | C_DP_UNREG,
                        0, NULL, &cli_app_cbs);

    return;
}

struct cmd_node mul_conf_node =
{
    MUL_NODE,
    "(mul-main)# ",
    1,
    NULL,
    NULL
};

struct cmd_node tr_conf_node =
{
    MULTR_NODE,
    "(mul-tr)# ",
    1,
    NULL,
    NULL
};

struct cmd_node fab_conf_node =
{
    MULFAB_NODE,
    "(mul-fab)# ",
    1,
    NULL,
    NULL
};

struct cmd_node flow_actions_node =
{
    FLOW_NODE,
    "(config-flow-action)# ",
    1,
    NULL,
    NULL
};

DEFUN (mul_conf,
       mul_conf_cmd,
       "mul-conf",
       "mul-core conf mode\n")
{
    if (cli_init_mul_service(cli, vty)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    vty->node = MUL_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_conf_exit,
       mul_conf_exit_cmd,
       "exit",
       "Exit mul-core conf mode\n")
{
    /* cli_exit_mul_service(cli); */
    vty->node = ENABLE_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_tr_conf,
       mul_tr_conf_cmd,
       "mul-tr-conf",
       "mul-tr (topo-route) conf mode\n")
{

    if (cli_init_tr_service(cli, vty)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    vty->node = MULTR_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_tr_conf_exit,
       mul_tr_conf_exit_cmd,
       "exit",
       "Exit mul-tr conf mode\n")
{
    /* cli_exit_tr_service(cli); */
    vty->node = ENABLE_NODE;
    return CMD_SUCCESS;
}


DEFUN (mul_fab_conf,
       mul_fab_conf_cmd,
       "mul-fab-conf",
       "mul-fab conf mode\n")
{
    if (cli_init_fab_service(cli, vty)) {
        vty->node = ENABLE_NODE;
        return CMD_SUCCESS;
    }

    vty->node = MULFAB_NODE;
    return CMD_SUCCESS;
}

DEFUN (mul_fab_conf_exit,
       mul_fab_conf_exit_cmd,
       "exit",
       "Exit mul-fab conf mode\n")
{
    /* cli_exit_fab_service(cli); */
    vty->node = ENABLE_NODE;
    return CMD_SUCCESS;
}

DEFUN (flow_actions,
       flow_actions_cmd,
       "flow ARGS",
       "Flow\n"
       "Flow tuples\n")
{
    vty->node = FLOW_NODE;

    return CMD_SUCCESS;
}

DEFUN (show_of_switch,
       show_of_switch_cmd,
       "show of-switch all",
       SHOW_STR
       "Openflow switches\n"
       "Summary information for all")
{
    struct cbuf *b;
    char *pbuf = NULL;

    vty_out (vty,
            "%sSwitch-DP-id    |   State     |  "
            "Peer                 | Ports%s",
            VTY_NEWLINE, VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    b = mul_get_switches_brief(cli->mul_service);
    if (b) {
        pbuf = mul_dump_switches_brief(b, true);
        if (pbuf) {
            vty_out (vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}


DEFUN (show_of_switch_detail,
       show_of_switch_detail_cmd,
       "show of-switch X detail",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Detailed information\n")
{
    uint64_t    dp_id;
    struct cbuf *b;
    char *      pbuf;

    dp_id = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);


    b = mul_get_switch_detail(cli->mul_service, dp_id);
    if (b) {
        pbuf = mul_dump_switch_detail(b, true);
        if (pbuf) {
            vty_out (vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}


DEFUN (show_of_switch_flow,
       show_of_switch_flow_cmd,
       "show of-flow switch X",
       SHOW_STR
       "Openflow flow tuple\n"
       "For a particular switch\n"
       "datapath-id in 0xXXX format\n")
{
    uint64_t                    dp_id;

    dp_id = strtoull(argv[0], NULL, 16);

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_get_flow_info(cli->mul_service, dp_id, false,
                      false, vty->type == VTY_NBAPI, vty,
                      vty->type != VTY_NBAPI ? vty_dump : nbapi_dump);

    return CMD_SUCCESS;
}


DEFUN (show_of_flow_all,
       show_of_flow_all_cmd,
       "show of-flow all",
       SHOW_STR
       "Openflow flow tuple\n"
       "On all switches\n")
{
    if (vty->type == VTY_NBAPI) {
        return_vty(vty, NB_UNKNOWN, CMD_WARNING, NULL);
    }

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_get_flow_info(cli->mul_service, 0, false,
                      false, false, vty, vty_dump);

    return CMD_SUCCESS;
}

DEFUN (show_of_switch_flow_static,
       show_of_switch_flow_static_cmd,
       "show of-flow switch X static",
       SHOW_STR
       "Openflow flow tuple\n"
       "For a particular switch\n"
       "datapath-id in 0xXXX format\n")
{
    uint64_t                    dp_id;

    if (vty->type == VTY_NBAPI) {
        return_vty(vty, NB_UNKNOWN, CMD_WARNING, NULL);
    }

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    dp_id = strtoull(argv[0], NULL, 16);

    mul_get_flow_info(cli->mul_service, dp_id, true,
                      false, false, vty, vty_dump);

    return CMD_SUCCESS;
}

DEFUN (show_of_flow_all_static,
       show_of_flow_all_static_cmd,
       "show of-flow all-static",
       SHOW_STR
       "Openflow flow tuple\n"
       "All static flows\n")
{
    if (vty->type == VTY_NBAPI) {
        return_vty(vty, NB_UNKNOWN, CMD_WARNING, NULL);
    }

    if (cli_init_mul_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_get_flow_info(cli->mul_service, 0, true,
                      false, false, vty, vty_dump);

    return CMD_SUCCESS;
}

DEFUN (of_flow_vty_del,
       of_flow_vty_del_cmd,
       "of-flow del switch X smac (X|*) dmac (X|*) eth-type (<0-65535>|*) vid (<0-4095>|*)"
       " vlan-pcp (<0-7>|*) dip A.B.C.D/M sip A.B.C.D/M proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "in-port (<0-65535>|*) table <0-254>",
       "OF-Flow configuration\n"
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "Enter valid source mac\n"
       "* for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac\n"
       "OR * for wildcard\n"
       "ether type\n"
       "Enter valid ether type\n"
       "* for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id\n"
       "* for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "* for wildcard\n"
       "dst-ip/mask\n"
       "Enter valid ip address and mask\n"
       "src-ip/mask\n"
       "Enter valid ip address and mask\n"
       "IP protocol\n"
       "Enter a valid ip-proto\n"
       "* for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value\n"
       "* for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port\n"
       "* for wildcard\n"
       "src-port\n"
       "Enter valid src port\n"
       "* for wildcard\n"
       "input port\n"
       "Enter input port index"
       "* for wildcard\n")
{
    int                          i;
    uint64_t                     dp_id;
    struct flow                  *flow;
    struct flow                  *mask;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct prefix_ipv4           dst_p, src_p;
    uint32_t                     nmask;

    flow = calloc(1, sizeof(*flow));
    assert(flow);

    mask = calloc(1, sizeof(*mask));
    assert(mask);
    of_mask_set_no_dc(mask); 

    dp_id = strtoull(argv[0], NULL, 16);

    if (!strncmp(argv[1], "*", strlen(argv[1]))) {
        memset(flow->dl_src, 0, 6);
        memset(mask->dl_src, 0, 6);
    } else {
        mac_str = (void *)argv[1];
        for (i = 0; i < 6; i++) {
            flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[2], "*", strlen(argv[2]))) {
        memset(flow->dl_dst, 0, 6);
        memset(mask->dl_dst, 0, 6);
    } else {
        mac_str = (void *)argv[2];
        for (i = 0; i < 6; i++) {
            flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[3], "*", strlen(argv[3]))) {
        flow->dl_type = 0;
        mask->dl_type = 0;
    } else {
        flow->dl_type = htons(atoi(argv[3]));
    }

    if (!strncmp(argv[4], "*", strlen(argv[4]))) {
        flow->dl_vlan = 0;
        mask->dl_vlan = 0;
    } else {
        flow->dl_vlan = htons(atoi(argv[4])); // Check ?
    }

    if (!strncmp(argv[5], "*", strlen(argv[5]))) {
        flow->dl_vlan_pcp = 0;
        mask->dl_vlan_pcp = 0;
    } else {
        flow->dl_vlan_pcp = htons(atoi(argv[5])); // Check ?
    }

    ret = str2prefix(argv[6], (void *)&dst_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto free_err_out;
    } 

    if (dst_p.prefixlen) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            nmask = make_inet_mask(dst_p.prefixlen);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    } else {
        nmask = 0;
    }

    mask->nw_dst = htonl(nmask);
    flow->nw_dst = dst_p.prefix.s_addr & htonl(nmask);

    ret = str2prefix(argv[7], (void *)&src_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto free_err_out;
    }

    if (src_p.prefixlen) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            nmask = make_inet_mask(src_p.prefixlen);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    } else {
        nmask = 0;
    }

    mask->nw_src = htonl(nmask);
    flow->nw_src = src_p.prefix.s_addr & htonl(nmask);

    if (!strncmp(argv[8], "*", strlen(argv[8]))) {
        flow->nw_proto = 0;
        mask->nw_proto = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_proto = atoi(argv[8]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[9], "*", strlen(argv[9]))) {
        flow->nw_tos = 0;
        mask->nw_tos = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_tos = atoi(argv[9]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[10], "*", strlen(argv[10]))) {
        flow->tp_dst = 0;
        mask->tp_dst = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_dst = htons(atoi(argv[10]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IP || ip_type != UDP/TCP %s",
                     VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[11], "*", strlen(argv[11]))) {
        flow->tp_src = 0;
        mask->tp_src = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_src = htons(atoi(argv[11]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IP || ip_type != UDP/TCP %s",
                    VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[12], "*", strlen(argv[12]))) {
        flow->in_port = 0;
        mask->in_port = 0;
    } else {
        flow->in_port = htonl(atoi(argv[12]));
    }

    flow->table_id = atoi(argv[13]);
    mul_service_send_flow_del(cli->mul_service, dp_id, flow, mask,
                          0, C_FL_PRIO_DFL, C_FL_ENT_STATIC,
                          OFPG_ANY);

    if (c_service_timed_throw_resp(cli->mul_service) > 0) {
        vty_out(vty, "Failed to delete a flow. Check log messages%s",
                VTY_NEWLINE);
    }

    free(flow);
    free(mask);

    return CMD_SUCCESS;

free_err_out:
    free(flow);
    free(mask);
    return CMD_WARNING;
}

DEFUN_NOSH (of_flow_vty_add,
       of_flow_vty_add_cmd,
       "of-flow add switch X smac (X|*) dmac (X|*) eth-type (<0-65535>|*) vid (<0-4095>|*)"
       " vlan-pcp (<0-7>|*) dip A.B.C.D/M sip A.B.C.D/M proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "in-port (<0-65535>|*) table <0-254>",
       "OF-Flow configuration\n"
       "Add\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "Enter valid source mac\n"
       "* for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac\n"
       "* for wildcard\n"
       "ether type\n"
       "Enter valid ether type\n"
       "* for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id\n"
       "* for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "* for wildcard\n"
       "dst-ip/mask\n"
       "Enter valid ip address and mask\n"
       "src-ip/mask\n"
       "Enter valid ip address and mask\n"
       "IP protocol\n"
       "Enter a valid ip-proto"
       "* for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value\n"
       "* for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port\n"
       "* for wildcard\n"
       "src-port\n"
       "Enter valid src port\n"
       "* for wildcard\n"
       "input port\n"
       "Enter input port index\n"
       "* for wildcard\n"
       "table-id"
       "Enter table-id\n")
{
    int                          i;
    struct flow                  *flow;
    struct flow                  *mask;
    struct mul_act_mdata         *mdata;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct prefix_ipv4           dst_p, src_p;
    struct cli_flow_action_parms *args; 
    uint32_t                     nmask;

    flow = calloc(1, sizeof(*flow));
    assert(flow);

    mask = calloc(1, sizeof(*mask));
    assert(mask);
    memset(mask, 0xff, sizeof(*flow));

    mdata= calloc(1, sizeof(*mdata));
    assert(mdata);

    args = calloc(1, sizeof(*args));
    assert(args);

    args->dpid = strtoull(argv[0], NULL, 16);

    if (!strncmp(argv[1], "*", strlen(argv[1]))) {
        memset(flow->dl_src, 0, 6);
        memset(mask->dl_src, 0, 6);
    } else {
        mac_str = (void *)argv[1];
        for (i = 0; i < 6; i++) {
            flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[2], "*", strlen(argv[2]))) {
        memset(flow->dl_dst, 0, 6);
        memset(mask->dl_dst, 0, 6);
    } else {
        mac_str = (void *)argv[2];
        for (i = 0; i < 6; i++) {
            flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[3], "*", strlen(argv[3]))) {
        flow->dl_type = 0;
        mask->dl_type = 0;
    } else {
        flow->dl_type = htons(atoi(argv[3]));
    }

    if (!strncmp(argv[4], "*", strlen(argv[4]))) {
        flow->dl_vlan = 0;
        mask->dl_vlan = 0;
    } else {
        flow->dl_vlan = htons(atoi(argv[4])); // Check ?
    }

    if (!strncmp(argv[5], "*", strlen(argv[5]))) {
        flow->dl_vlan_pcp = 0;
        mask->dl_vlan_pcp = 0;
    } else {
        flow->dl_vlan_pcp = htons(atoi(argv[5])); // Check ?
    }

    ret = str2prefix(argv[6], (void *)&dst_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto free_err_out;
    }

    if (dst_p.prefixlen) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            nmask = make_inet_mask(dst_p.prefixlen);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    } else {
        nmask = 0;
    }

    mask->nw_dst = htonl(nmask);
    flow->nw_dst = dst_p.prefix.s_addr & htonl(nmask);

    ret = str2prefix(argv[7], (void *)&src_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto free_err_out;
    }

    if (src_p.prefixlen) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            nmask = make_inet_mask(src_p.prefixlen);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    } else {
        nmask = 0;
    }

    mask->nw_src = htonl(nmask);
    flow->nw_src = src_p.prefix.s_addr & htonl(nmask);

    if (!strncmp(argv[8], "*", strlen(argv[8]))) {
        flow->nw_proto = 0;
        mask->nw_proto = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_proto = atoi(argv[8]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[9], "*", strlen(argv[9]))) {
        flow->nw_tos = 0;
        mask->nw_tos = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_tos = atoi(argv[9]);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto free_err_out;
        }
    }
    
    if (!strncmp(argv[10], "*", strlen(argv[10]))) {
        flow->tp_dst = 0;
        mask->tp_dst = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_dst = htons(atoi(argv[10]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IP || ip_type != UDP/TCP %s",
                     VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[11], "*", strlen(argv[11]))) {
        flow->tp_src = 0;
        mask->tp_src = 0;
    } else {
        if (flow->dl_type == htons(ETH_TYPE_IP) &&
            (flow->nw_proto == IP_TYPE_UDP ||
            flow->nw_proto == IP_TYPE_TCP)) {
            flow->tp_src = htons(atoi(argv[11]));
        } else {
            vty_out(vty, "dl_type != ETH_TYPE_IP || ip_type != UDP/TCP %s",
                    VTY_NEWLINE);
            goto free_err_out;
        }
    }

    if (!strncmp(argv[12], "*", strlen(argv[12]))) {
        flow->in_port = 0;
        mask->in_port = 0;
    } else {
        flow->in_port = htonl(atoi(argv[12]));
    }

    flow->table_id = atoi(argv[13]);
#if 0
    char *fl_str = of_dump_flow_generic(flow, mask);
    printf ("%s\n", fl_str);
    free(fl_str);
    of1_0_flow_correction(flow, mask);
#endif

    mul_app_act_alloc(mdata);
    mul_app_act_set_ctors(mdata, args->dpid); 
    args->fl = flow;
    args->mask = mask;
    args->mdata = mdata;
    args->cmn.flow_act = true;

    vty->index = args;

    if ((ret = flow_actions_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto free_err_out;  
    }

    return CMD_SUCCESS;

free_err_out:
    free(args);
    free(flow);
    mul_app_act_free(mdata);
    free(mdata);
    free(mask);
    return CMD_WARNING;
}

DEFUN (of_add_output_action,
       of_add_output_action_cmd,
       "action-add output <0-65535>",
       "Add openflow action\n"
       "Output action\n"
       "Enter port-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    mul_app_action_output(mdata, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN (of_add_set_vid_action,
       of_add_set_vid_action_cmd,
       "action-add vlan-id <0-4094>",
       "Add openflow action\n"
       "set vlanid action\n"
       "Enter vlan-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    mul_app_action_set_vid(mdata, strtoull(argv[0], NULL, 10));
    return CMD_SUCCESS;
}

DEFUN (of_add_strip_vlan_action,
       of_add_strip_vlan_action_cmd,
       "action-add strip-vlan",
       "Add openflow action\n"
       "Strip vlan action\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);    

    mul_app_action_strip_vlan(mdata);
    return CMD_SUCCESS;
}

DEFUN (of_add_set_vpcp_action,
       of_add_set_vpcp_action_cmd,
       "action-add vlan-pcp <0-7>",
       "Add openflow action\n"
       "set vlan-pcp action\n"
       "Enter vlan-pcp\n")
{
    mul_act_mdata_t *mdata = NULL;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    mul_app_action_set_vlan_pcp(mdata, strtoull(argv[0], NULL, 10));
    return CMD_SUCCESS;
}

DEFUN (of_add_set_dmac_action,
       of_add_set_dmac_action_cmd,
       "action-add set-dmac X",
       "Add openflow action\n"
       "set dmac action\n"
       "Enter MAC address (xx:xx:xx:xx:xx:xx) \n")
{
    mul_act_mdata_t *mdata = NULL;
    uint8_t                      dmac[6];
    char                         *mac_str, *next = NULL;
    int                          i = 0;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);


    mac_str = (void *)argv[0];
    for (i = 0; i < 6; i++) {
        dmac[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    mul_app_action_set_dmac(mdata, dmac);
    return CMD_SUCCESS;
}

DEFUN (of_add_set_smac_action,
       of_add_set_smac_action_cmd,
       "action-add set-smac X",
       "Add openflow action\n"
       "set smac action\n"
       "Enter MAC address (xx:xx:xx:xx:xx:xx) \n")
{
    mul_act_mdata_t *mdata = NULL;
    uint8_t                      smac[6];
    char                         *mac_str, *next = NULL;
    int                          i = 0;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);


    mac_str = (void *)argv[0];
    for (i = 0; i < 6; i++) {
        smac[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    mul_app_action_set_smac(mdata, smac);
    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_saddr_action,
       of_add_set_nw_saddr_action_cmd,
       "action-add nw-saddr A.B.C.D",
       "Add openflow action\n"
       "set source ip address action\n"
       "Enter ip address\n")
{
    mul_act_mdata_t *mdata = NULL;
    struct in_addr               ip_addr;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (inet_aton(argv[0], &ip_addr) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    mul_app_action_set_nw_saddr(mdata, ntohl(ip_addr.s_addr));
    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_daddr_action,
       of_add_set_nw_daddr_action_cmd,
       "action-add nw-daddr A.B.C.D",
       "Add openflow action\n"
       "set destination ip address action\n"
       "Enter ip address\n")
{
    mul_act_mdata_t *mdata = NULL;
    struct in_addr               ip_addr;
    CLI_ARGS_TO_ACT_MDATA_SW(mdata, vty->index);

    if (inet_aton(argv[0], &ip_addr) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    mul_app_action_set_nw_daddr(mdata, ntohl(ip_addr.s_addr));
    return CMD_SUCCESS;
}

DEFUN (of_add_drop_action,
       of_add_drop_action_cmd,
       "action-add drop",
       "Add openflow action\n"
       "drop packet action\n")
{
    struct cli_common_args *__cmn = vty->index;
    if (__cmn->flow_act) {
        struct cli_flow_action_parms *fl_parms = vty->index;
        fl_parms->drop_pkt = true;
    } else {
        struct cli_group_mod_parms *g_parms = vty->index;
        g_parms->drop_pkt[g_parms->act_vec_len] = true;
    }

    return CMD_SUCCESS;
}

DEFUN (flow_actions_commit,
       flow_actions_commit_cmd,
       "commit",
       "commit the acl and its actions")
{
    struct cli_flow_action_parms *args = vty->index;
    void *actions = NULL;
    uint8_t prio;
    size_t action_len = args->mdata ? mul_app_act_len(args->mdata) : 0;

    if (args) {
        if (action_len >= 4 || args->drop_pkt) {
            /* TODO action validation here */

            if (!args->drop_pkt) {
                actions = args->mdata->act_base;
                action_len = mul_app_act_len(args->mdata);
                prio = C_FL_PRIO_DFL;
            } else {
                action_len = 0;
                prio = C_FL_PRIO_DFL;
                vty_out(vty, "Ignoring all non-drop actions if any%s",
                        VTY_NEWLINE);
            }
            mul_service_send_flow_add(cli->mul_service, args->dpid,
                                  args->fl, args->mask, 
                                  CLI_UNK_BUFFER_ID,
                                  actions, action_len,
                                  0, 0, prio, 
                                  C_FL_ENT_STATIC);
            if (c_service_timed_throw_resp(cli->mul_service) > 0) {
                vty_out(vty, "Failed to add a flow. Check log messages%s", 
                        VTY_NEWLINE);
            }
        } else {
            vty_out(vty, "No actions added.Flow not added%s", VTY_NEWLINE);
        }

        if (args->fl) {
            free(args->fl);
        }
        if (args->mask) {
            free(args->mask);
        }
        if (args->mdata) {
            mul_app_act_free(args->mdata);
            free(args->mdata);
        }
        free(args);
        vty->index = NULL;
    }

    vty->node = MUL_NODE;
    return CMD_SUCCESS;
}

DEFUN (flow_actions_exit,
       flow_actions_exit_cmd,
       "exit",
       "Exit from Flow action configuration mode")
{
    struct cli_flow_action_parms *args = vty->index;

    if (args) {
        if (args->fl) free(args->fl);
        if (args->mdata) {
            mul_app_act_free(args->mdata);
            free(args->mdata);
        }
        free(args);
    }

    vty->node = MUL_NODE;
    return CMD_SUCCESS;
}

struct cmd_node group_node =
{
    GROUP_NODE,
    "(config-grp-act-vectors)# ",
    1,
    NULL,
    NULL
};


DEFUN (group_act_vec_exit,
       group_act_vec_exit_cmd,
       "exit",
       "Exit from group vector actions configuration mode")
{
    struct cli_group_mod_parms *args = vty->index;
    int act;

    if (args) {
        for (act = 0; act < args->act_vec_len; act++) {
            of_mact_free(&args->mdata[act]);
        }
        free(args);
    }

    vty->node = CONFIG_NODE;
    return CMD_SUCCESS;
}

DEFUN (group_actions_vectors,
       group_actions_vectors_cmd,
       "group ARGS",
       "group\n"
       "group entries\n")
{
    vty->node = GROUP_NODE;

    return CMD_SUCCESS;
}

DEFUN (group_act_vector_done,
       group_act_vector_done_cmd,
       "group-act-vector-finish",
       "Save the current vector and add a new action vector\n")
{
    struct cli_group_mod_parms *args = vty->index;

    if (args->act_vec_len + 1 >= OF_MAX_ACT_VECTORS) {
        vty_out(vty, "Cant add more group action vectors\r\n");
        group_act_vec_exit_cmd.func(self, vty, argc, argv);
        return CMD_SUCCESS;
    }

    if (!args->drop_pkt[args->act_vec_len-1] &&
        !of_mact_len(&args->mdata[args->act_vec_len-1])) {
        vty_out(vty, "No actions added. Try adding again..\r\n");
        return CMD_SUCCESS;
    }

    assert(args->act_vec_len);

    args->act_vec_len++;
    of_mact_alloc(&args->mdata[args->act_vec_len-1]);
    args->mdata[args->act_vec_len-1].only_acts = true;
    mul_app_act_set_ctors(&args->mdata[args->act_vec_len-1], args->dpid);

    return CMD_SUCCESS;
}

DEFUN (group_commit,
       group_commit_cmd,
       "commit-group",
       "commit the group and its actions-vectors")
{
    struct cli_group_mod_parms *args = vty->index;
    struct of_group_mod_params g_parms;
    struct of_act_vec_elem *act_elem;
    int act = 0;

    memset(&g_parms, 0, sizeof(g_parms));

    if (args) {

        if (!args->drop_pkt[args->act_vec_len-1] &&
            !of_mact_len(&args->mdata[args->act_vec_len-1])) {
            vty_out(vty, "No actions added. Try adding again..\r\n");
            return CMD_SUCCESS;
        }

        g_parms.group = args->group;
        g_parms.type = args->type;
        for (act = 0; act < args->act_vec_len; act++) {
            bool drop = args->drop_pkt[act];
            if (drop) {
                of_mact_free(&args->mdata[act]);
            } else {
                act_elem = calloc(1, sizeof(*act_elem));
                act_elem->actions = args->mdata[act].act_base;
                act_elem->action_len = of_mact_len(&args->mdata[act]);
                g_parms.act_vectors[act] = act_elem;
            }
        }
        g_parms.act_vec_len = args->act_vec_len;
        mul_service_send_group_add(cli->mul_service, args->dpid, &g_parms);
        if (c_service_timed_throw_resp(cli->mul_service) > 0) {
            vty_out(vty, "Failed to add group. Check log messages%s",
                    VTY_NEWLINE);
        }
        for (act = 0; act < args->act_vec_len; act++) {
            of_mact_free(&args->mdata[act]);
            free(g_parms.act_vectors[act]);
        }
        free(args);
        vty->index = NULL;
    }

    vty->node = CONFIG_NODE;
    return CMD_SUCCESS;
}

DEFUN_NOSH (of_group_vty_add,
       of_group_vty_add_cmd,
       "of-group add switch X group <0-65535> type (all|select|indirect|ff)",
       "OF-group configuration\n"
       "Add\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "openflow-group\n"
       "Enter valid group-id\n"
       "group-type\n"
       "Executes all action buckets \n"
       "Selects one of the buckets \n"
       "Tndirect single bucket\n"
       "Fast failover bucket\n")
{
    uint64_t dpid;
    struct cli_group_mod_parms *cli_parms;
    uint32_t group;
    uint8_t type, version;
    int ret = CMD_WARNING;

    dpid = strtoull(argv[0], NULL, 16);
    if (!dpid) {
        vty_out(vty, "No such switch\r\n");
        return CMD_WARNING;
    }

    version = c_app_switch_get_version_with_id(dpid);
    if (version !=  OFP_VERSION_131) {
        vty_out(vty, "Switch 0x%llx does not support groups", U642ULL(dpid));
        return CMD_WARNING;
    }

    group = atol(argv[1]);

    if (!strncmp(argv[2], "all", strlen(argv[2]))) {
        type = OFPGT_ALL;
    } else if (!strncmp(argv[2], "select", strlen(argv[2]))) {
        type = OFPGT_SELECT;
    } else if (!strncmp(argv[2], "indirect", strlen(argv[2]))) {
        type = OFPGT_INDIRECT;
    } else if (!strncmp(argv[2], "ff", strlen(argv[2]))) {
        type = OFPGT_FF;
    } else {
        vty_out(vty, "Unrecognized group-type (%s)\r\n", argv[2]);
        return CMD_WARNING;
    }

    cli_parms = calloc(1, sizeof(*cli_parms));
    if (!cli_parms) {
        return CMD_WARNING;
    }

    cli_parms->dpid = dpid;
    cli_parms->group = group;
    cli_parms->type = type;
    of_mact_alloc(&cli_parms->mdata[0]);
    cli_parms->mdata[0].only_acts = true;
    mul_app_act_set_ctors(&cli_parms->mdata[0], dpid);
    cli_parms->act_vec_len = 1;

    vty->index = cli_parms;

    if ((ret = group_actions_vectors_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto free_err_out;
    }

    return CMD_SUCCESS;

free_err_out:
    /* FIXME - Free action vectors */
    free(cli_parms);
    return CMD_WARNING;
}


DEFUN (of_group_vty_del,
       of_group_vty_del_cmd,
       "of-group del switch X group <0-65535>",
       "OF-group configuration\n"
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "openflow-group\n"
       "Enter valid group-id\n")
{
    struct of_group_mod_params gp_parms;
    uint64_t dpid;
    uint32_t group;

    memset(&gp_parms, 0, sizeof(gp_parms));

    dpid = strtoull(argv[0], NULL, 16);

    group = atol(argv[1]);
    gp_parms.group = group;

    mul_service_send_group_del(cli->mul_service, dpid, &gp_parms);
    if (c_service_timed_throw_resp(cli->mul_service) > 0) {
        vty_out(vty, "Failed to del the group. Check log messages%s",
                VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN (show_neigh_switch_detail,
       show_neigh_switch_detail_cmd,
       "show neigh switch X detail",
       SHOW_STR
       "Switch Neighbour Detail\n"
       "Detailed information for the switch")
{
    uint64_t dpid;
    struct cbuf *b;
    char *pbuf = NULL;

    if (cli_init_tr_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    dpid = strtoull(argv[0], NULL, 16);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    vty_out (vty,"%12s | %10s | %10s | %s%s","port #","status","neighbor #",
             "neighbor port #",VTY_NEWLINE);
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    b = mul_neigh_get(cli->tr_service, dpid);
    if (b) {
        pbuf = mul_dump_neigh(b, true);
        if (pbuf) {
            vty_out(vty, "%s", pbuf);
            free(pbuf);
        }
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);


    return CMD_SUCCESS;
}


static int
__add_fab_host_cmd(struct vty *vty, const char **argv, bool is_gw)
{
    uint16_t tenant_id;
    uint16_t network_id;
    uint64_t dpid;
    struct flow fl;
    struct prefix_ipv4 host_ip;
    char *mac_str = NULL, *next = NULL;
    int  i = 0, ret = 0;

    memset(&fl, 0, sizeof(fl));

    tenant_id = atoi(argv[0]);
    network_id = atoi(argv[1]);
    dpid = strtoull(argv[4], NULL, 16);
    fl.in_port= htons(atoi(argv[5]));

    ret = str2prefix(argv[2], (void *)&host_ip);
    if (ret <= 0) {
        return return_vty(vty, 
                          is_gw ? NB_CONFIG_OF_FAB_HOST_GW :
                                  NB_CONFIG_OF_FAB_HOST_NONGW,
                          CMD_WARNING, "Malformed address");
    }

    fl.nw_src = host_ip.prefix.s_addr;
    fab_add_tenant_id(&fl, NULL, tenant_id);
    fab_add_network_id(&fl, network_id);
    fl.FL_DFL_GW = is_gw;

    mac_str = (void *)argv[3];
    for (i = 0; i < 6; i++) {
        fl.dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        return return_vty(vty, 
                          is_gw ? NB_CONFIG_OF_FAB_HOST_GW :
                                  NB_CONFIG_OF_FAB_HOST_NONGW,
                          CMD_WARNING, "Malformed address");
    }

    if (mul_fabric_host_mod(cli->fab_service, dpid, &fl, true)) {
        return return_vty(vty,
                          is_gw ? NB_CONFIG_OF_FAB_HOST_GW :
                                  NB_CONFIG_OF_FAB_HOST_NONGW,
                          CMD_WARNING, "Host add failed");
    }

    return return_vty(vty,
                      is_gw ? NB_CONFIG_OF_FAB_HOST_GW :
                                  NB_CONFIG_OF_FAB_HOST_NONGW,
                      CMD_SUCCESS, NULL);

}

DEFUN (add_fab_host_nongw,
       add_fab_host_nongw_cmd,
        "add fabric-host tenant <0-4096> network <0-65535> "
        "host-ip A.B.C.D host-mac X "
        "switch X port <0-65535> non-gw",
        "Add a configuration"
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter Network-id\n"
        "Host ip address\n"
        "Valid ip address\n"
        "Host mac address\n"
        "Valid mac address in X:X...X format \n"
        "Switch directly connected to\n"
        "Enter dpid\n"
        "Enter alias-id\n"
        "ConnectepPort on switch\n"
        "Enter port-number\n"
        "This host is non gateway\n")
{
    return __add_fab_host_cmd(vty, argv, false);
}

DEFUN (add_fab_host_gw,
       add_fab_host_gw_cmd,
        "add fabric-host tenant <0-4096> network <0-65535> "
        "host-ip A.B.C.D host-mac X "
        "switch X port <0-65535> gw",
        "Add a configuration"
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter Network-id\n"
        "Host ip address\n"
        "Valid ip address\n"
        "Host mac address\n"
        "Valid mac address in X:X...X format \n"
        "Switch directly connected to\n"
        "Enter dpid\n"
        "Enter alias-id\n"
        "ConnectepPort on switch\n"
        "Enter port-number\n"
        "This host is non gateway\n")
{
    return __add_fab_host_cmd(vty, argv, true);
}


DEFUN (del_fab_host,
       del_fab_host_cmd,
        "del fabric-host tenant <0-4096> network <0-65535> "
        "host-ip A.B.C.D host-mac X",
        "Del a configuration"
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Host ip address\n"
        "Valid ip address\n"
        "Host mac address\n"
        "Valid mac address in X:X...X format \n")
{
    uint16_t tenant_id;
    uint16_t network_id;
    struct flow fl;
    struct prefix_ipv4 host_ip;
    char *mac_str = NULL, *next = NULL;
    int  i = 0, ret = 0;

    memset(&fl, 0, sizeof(fl));

    tenant_id = atoi(argv[0]);
    network_id = atoi(argv[1]);

    ret = str2prefix(argv[2], (void *)&host_ip);
    if (ret <= 0) {
        return return_vty(vty,
                          NB_CONFIG_OF_FAB_HOST_DEL,
                          CMD_WARNING, "Malformed address");
    }

    fl.nw_src = host_ip.prefix.s_addr;
    fab_add_tenant_id(&fl, NULL, tenant_id);
    fab_add_network_id(&fl, network_id);

    mac_str = (void *)argv[3];
    for (i = 0; i < 6; i++) {
        fl.dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        return return_vty(vty,
                          NB_CONFIG_OF_FAB_HOST_DEL,
                          CMD_WARNING, "Malformed mac address");
    }

    if (mul_fabric_host_mod(cli->fab_service, 0, &fl, false)) {
        return return_vty(vty,
                          NB_CONFIG_OF_FAB_HOST_DEL,
                          CMD_WARNING, "Host delete failed");
    }

    return return_vty(vty,
                      NB_CONFIG_OF_FAB_HOST_DEL,
                      CMD_SUCCESS, NULL);
}

DEFUN (show_fab_host_all_active,
       show_fab_host_all_active_cmd,
        "show fabric-hosts all-active",
        SHOW_STR
        "Fabric connected host\n"
        "All active hosts\n")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_fab_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_fabric_show_hosts(cli->fab_service, true, false,
                          (void *)vty, vty_dump);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_fab_host_all_inactive,
       show_fab_host_all_inactive_cmd,
        "show fabric-hosts all-inactive",
        SHOW_STR
        "Fabric connected host\n"
        "All inactive hosts\n")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (cli_init_fab_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_fabric_show_hosts(cli->fab_service, false, false,
                          (void *)vty, vty_dump);


    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

static void
vty_src_host_dump(void *vty_arg, char *pbuf)
{
    struct vty *vty = vty_arg;
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);


    vty_out(vty, "%10s:", "Source" );
    vty_dump(vty, pbuf);
}

static void
vty_dst_host_dump(void *vty_arg, char *pbuf)
{
    struct vty *vty = vty_arg;
    vty_out(vty, "%10s:", "Dest" );
    vty_dump(vty, pbuf);
}

static void
vty_route_dump(void *vty_arg, char *pbuf)
{
    struct vty *vty = vty_arg;

    vty_out(vty, "%10s:", "Route" );
    vty_dump(vty, pbuf);
    vty_out(vty, "|||%s", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

}

DEFUN (show_fab_route_all,
       show_fab_route_all_cmd,
       "show fabric-route all",
       SHOW_STR
       "Dump all routes\n")
{

    if (cli_init_fab_service(cli, vty)) {
        return CMD_SUCCESS;
    }

    mul_fabric_show_routes(cli->fab_service, vty, vty_src_host_dump,
                           vty_dst_host_dump, vty_route_dump);


    return CMD_SUCCESS;
}


/**
 * cli_module_vty_init -
 *
 * CLI application's vty entry point 
 */
void
cli_module_vty_init(void *arg UNUSED)
{
    c_log_debug("%s:", FN);
    install_node(&mul_conf_node, NULL);
    install_node(&tr_conf_node, NULL);
    install_node(&fab_conf_node, NULL);
    install_node(&flow_actions_node, NULL);
    install_node(&group_node, NULL);

    install_default(MUL_NODE);
    install_default(MULTR_NODE);
    install_default(MULFAB_NODE);
    install_default(FLOW_NODE);
    install_default(GROUP_NODE);
    install_element_attr_type(CONFIG_NODE, &mul_conf_cmd, MUL_NODE);
    install_element(MUL_NODE, &mul_conf_exit_cmd);
    install_element(ENABLE_NODE, &show_of_switch_cmd);
    install_element(ENABLE_NODE, &show_of_switch_detail_cmd);
    install_element(ENABLE_NODE, &show_of_switch_flow_cmd);
    install_element(ENABLE_NODE, &show_of_flow_all_cmd);
    install_element(ENABLE_NODE, &show_of_switch_flow_static_cmd);
    install_element(ENABLE_NODE, &show_of_flow_all_static_cmd);
    install_element(MUL_NODE, &of_flow_vty_add_cmd);
    install_element(MUL_NODE, &of_flow_vty_del_cmd);
    install_element_attr_type(FLOW_NODE, &of_add_output_action_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_set_vid_action_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_set_dmac_action_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &flow_actions_exit_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &flow_actions_commit_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_set_nw_saddr_action_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_set_nw_daddr_action_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_set_smac_action_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_strip_vlan_action_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_set_vpcp_action_cmd, MUL_NODE);
    install_element_attr_type(FLOW_NODE, &of_add_drop_action_cmd, MUL_NODE); 
    install_element(MUL_NODE, &of_group_vty_add_cmd);
    install_element(MUL_NODE, &of_group_vty_del_cmd);
    install_element_attr_type(GROUP_NODE, &of_add_output_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_vid_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_dmac_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_nw_saddr_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_nw_daddr_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_smac_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_strip_vlan_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &of_add_set_vpcp_action_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_act_vector_done_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_commit_cmd, MUL_NODE);
    install_element_attr_type(GROUP_NODE, &group_act_vec_exit_cmd, MUL_NODE);

    install_element_attr_type(CONFIG_NODE, &mul_tr_conf_cmd, MULTR_NODE);
    install_element(MULTR_NODE, &mul_tr_conf_exit_cmd);
    install_element(ENABLE_NODE, &show_neigh_switch_detail_cmd);

    install_element_attr_type(CONFIG_NODE, &mul_fab_conf_cmd, MULFAB_NODE);
    install_element(MULFAB_NODE, &mul_fab_conf_exit_cmd);
    install_element(MULFAB_NODE, &add_fab_host_gw_cmd);
    install_element(MULFAB_NODE, &add_fab_host_nongw_cmd);
    install_element(MULFAB_NODE, &del_fab_host_cmd);
    install_element(ENABLE_NODE, &show_fab_host_all_active_cmd);
    install_element(ENABLE_NODE, &show_fab_host_all_inactive_cmd);
    install_element(ENABLE_NODE, &show_fab_route_all_cmd);

    host_config_set(CLI_CONF_FILE);
}

module_init(cli_module_init);
module_vty_init(cli_module_vty_init);
