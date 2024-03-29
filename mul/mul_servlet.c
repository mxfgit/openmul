/*
 *  mul_servlet.c: MUL controller service 
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

#include "mul_common.h"
#include "mul_servlet.h"
#include "mul_nbapi.h"

static char print_sep[] =
            "-------------------------------------------"
            "----------------------------------\r\n";

static char *ha_state[] = { "HA None",
                            "HA Connected",
                            "HA Master",
                            "HA Slave",
                            "HA Conflict",
                            "HA Disabled" };

static void
ofp_switch_states_tostr(char *string, uint32_t state)
{
    if (state == 0) {
        strcpy(string, "Init\n");
        return;
    }
    if (state & SW_REGISTERED) {
        strcpy(string, "Registered ");
    }
    if (state & SW_REINIT) {
        strcat(string, "Reinit");
    }
    if (state & SW_REINIT_VIRT) {
        strcat(string, "Reinit-Virt");
    }
    if (state & SW_DEAD) {
        strcat(string, "Dead");
    }
}

static void
ofp_port_config_tostr(char *string, uint32_t config)
{
    if (config & OFPPC_PORT_DOWN) {
        strcat(string, " PORT_DOWN");
    } else {
        strcat(string, " PORT_UP");
    }
}

static void
ofp_capabilities_tostr(char *string, uint32_t capabilities)
{
    if (capabilities == 0) {
        strcpy(string, "No capabilities\n");
        return;
    }
    if (capabilities & OFPC_FLOW_STATS) {
        strcat(string, "FLOW_STATS ");
    }
    if (capabilities & OFPC_TABLE_STATS) {
        strcat(string, "TABLE_STATS ");
    }
    if (capabilities & OFPC_PORT_STATS) {
        strcat(string, "PORT_STATS ");
    }
    if (capabilities & OFPC_STP) {
        strcat(string, "STP ");
    }
    if (capabilities & OFPC_IP_REASM) {
        strcat(string, "IP_REASM ");
    }
    if (capabilities & OFPC_QUEUE_STATS) {
        strcat(string, "QUEUE_STATS ");
    }
    if (capabilities & OFPC_ARP_MATCH_IP) {
        strcat(string, "ARP_MATCH_IP");
    }
}

static char *
of_dump_flow_cmd(struct flow *fl, uint32_t wildcards, uint64_t dpid)   
{
#define FL_PBUF_SZ 4096
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;
    uint32_t nw_dst_mask, nw_src_mask;
    uint32_t ip_wc;
    struct in_addr ip_addr = { .s_addr = 0 }; 

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "of-flow add switch 0x%llx ", U642ULL(dpid));

    wildcards = ntohl(wildcards);
    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = ip_wc >= 32 ? 0 :
                           make_inet_mask(32-ip_wc);

    ip_addr.s_addr = fl->nw_dst & htonl(nw_dst_mask);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "dip %s/%d ", inet_ntoa(ip_addr),
                    ip_wc >= 32 ? 0 : 32-ip_wc); 

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = ip_wc >= 32 ? 0 :
                           make_inet_mask(32-ip_wc);

    ip_addr.s_addr = fl->nw_src & htonl(nw_src_mask);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "sip %s/%d ", inet_ntoa(ip_addr),
                    ip_wc >= 32 ? 0 : 32-ip_wc); 

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "proto ");
    if (!(wildcards & OFPFW_NW_PROTO)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%d ", fl->nw_proto);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "tos ");
    if (!(wildcards & OFPFW_NW_TOS)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%d ", fl->nw_tos);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
    }


    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "dport ");
    if (!(wildcards & OFPFW_TP_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%hu ", ntohs(fl->tp_dst));
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "sport ");
    if (!(wildcards & OFPFW_TP_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%hu ", ntohs(fl->tp_src));
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "smac ");
    if (!(wildcards & OFPFW_DL_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%02x:%02x:%02x:%02x:%02x:%02x ",
                   fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5]);
        assert(len < FL_PBUF_SZ-1);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "dmac ");
    if (!(wildcards & OFPFW_DL_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
        assert(len < FL_PBUF_SZ-1);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "eth-type ");
    if (!(wildcards & OFPFW_DL_TYPE)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%hu ", ntohs(fl->dl_type));
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
    }


    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "vlan-id ");
    if (!(wildcards & OFPFW_DL_VLAN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%hu ", ntohs(fl->dl_vlan));
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "vlan-pcp ");
    if (!(wildcards & OFPFW_DL_VLAN_PCP)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%d ", fl->dl_vlan_pcp);
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* ");
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "in-port ");
    if (!(wildcards & OFPFW_IN_PORT)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%hu \r\n", ntohs(fl->in_port));
    } else {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "* \r\n");
    }

     
    return pbuf;
}

static char *
of_dump_actions_cmd(void *actions, size_t action_len)
{
    char                     *pbuf;
    size_t                   len = 0, parsed_len = 0;
    uint16_t                 act_type;
    struct ofp_action_header *hdr;
#define OF_DUMP_ACT_SZ 4096 
    pbuf = calloc(1, OF_DUMP_ACT_SZ);
    assert(pbuf);

    if (!action_len) {
        len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1, "action-add drop\r\n");
        goto commit;
    }

    while (action_len) {
        hdr =  (struct ofp_action_header *)actions;
        act_type = ntohs(hdr->type);
        switch (act_type) {
        case OFPAT_OUTPUT:
            {
                struct ofp_action_output *op_act = (void *)hdr;
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1, 
                                "action-add output %hu\r\n", 
                                ntohs(op_act->port));    
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*op_act);
                break;
            }
        case OFPAT_SET_VLAN_VID:
            {
                struct ofp_action_vlan_vid *vid_act = (void *)hdr;    
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "action-add vlan-id %hu\r\n",
                                ntohs(vid_act->vlan_vid));
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*vid_act);
                break;
                                 
            } 
        case OFPAT_SET_DL_DST:
            {
                struct ofp_action_dl_addr *dmac_act = (void *)hdr;
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "action-add set-dmac "
                                "%02x:%02x:%02x:%02x:%02x:%02x\r\n",
                                dmac_act->dl_addr[0], dmac_act->dl_addr[1], 
                                dmac_act->dl_addr[2], dmac_act->dl_addr[3], 
                                dmac_act->dl_addr[4], dmac_act->dl_addr[5]);
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*dmac_act);
                break;
            }
        case OFPAT_SET_DL_SRC:
            {
                struct ofp_action_dl_addr *smac_act = (void *)hdr;
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "action-add set-smac "
                                "%02x:%02x:%02x:%02x:%02x:%02x\r\n",
                                smac_act->dl_addr[0], smac_act->dl_addr[1], 
                                smac_act->dl_addr[2], smac_act->dl_addr[3], 
                                smac_act->dl_addr[4], smac_act->dl_addr[5]);
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*smac_act);
                break;
            }
        case OFPAT_SET_VLAN_PCP:
            {
                struct ofp_action_vlan_pcp *vpcp_act = (void *)hdr;
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "action-add vlan-pcp %d\r\n",
                                vpcp_act->vlan_pcp);
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*vpcp_act);
                break;
            }
        case OFPAT_STRIP_VLAN:
            {
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "action-add strip-vlan\r\n");
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(struct ofp_action_header);    
                break;
            }
        case OFPAT_SET_NW_SRC:
            {
                struct ofp_action_nw_addr *nw_addr_act = (void *)hdr;
                struct in_addr in_addr = { .s_addr = nw_addr_act->nw_addr };
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "action-add nw-saddr %s\r\n",
                                inet_ntoa(in_addr));
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*nw_addr_act);
                break;
            }
        case OFPAT_SET_NW_DST:
            {
                struct ofp_action_nw_addr *nw_addr_act = (void *)hdr;
                struct in_addr in_addr = { .s_addr = nw_addr_act->nw_addr };
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "action-add nw-daddr %s\r\n",
                                inet_ntoa(in_addr));
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*nw_addr_act);
                break;
            }
        default:
            {
                c_log_err("%s:unhandled action %u", FN, act_type);
                free(pbuf);
                return NULL;
            }
        }

        action_len -= parsed_len;
        actions = ((uint8_t *)actions + parsed_len);
    }

commit:
    len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1, "commit\r\n");

    return pbuf;
}


static bool 
check_reply_type(struct cbuf *b, uint32_t cmd_code)
{
    c_ofp_auxapp_cmd_t *cofp_auc  = (void *)(b->data);

    if (ntohs(cofp_auc->header.length) < sizeof(*cofp_auc)) {
        return false;
    }

    if (cofp_auc->header.type != C_OFPT_AUX_CMD ||
        cofp_auc->cmd_code != htonl(cmd_code)) {
        c_log_err("%s: type(%hu) cmd_code (%u)", FN,
                  cofp_auc->header.type, ntohl(cofp_auc->cmd_code));
        return false;
    }
 
    return true;
}

/**
 * mul_get_switches_brief -
 *
 * Get a brief of all switches connected to mul 
 */
struct cbuf *
mul_get_switches_brief(void *service)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;

    if (!service) return NULL;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_GET_SWITCHES);

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        if (!check_reply_type(b, C_AUX_CMD_MUL_GET_SWITCHES_REPLY)) {
            c_log_err("%s: Failed", FN);
            free_cbuf(b);
            return NULL;
        }
    }

    return b;
}
     

/**
 * mul_dump_switches_brief -
 */
char *
mul_dump_switches_brief(struct cbuf *b, bool free_buf)
{
    char    *pbuf = calloc(1, SWITCH_BR_PBUF_SZ);
    int     len = 0; 
    int     i = 0, n_switches;
    char    string[OFP_PRINT_MAX_STRLEN];
    c_ofp_auxapp_cmd_t *cofp_auc;
    c_ofp_switch_brief_t *cofp_swb;
    
    if (!pbuf) {
        c_log_err("%s: pbuf alloc failed", FN);
        goto out;
    }

    cofp_auc = (void *)(b->data);
    n_switches = (ntohs(cofp_auc->header.length) - sizeof(c_ofp_auxapp_cmd_t))/
                 sizeof(c_ofp_switch_brief_t);

    cofp_swb = (void *)(cofp_auc->data);
    for (; i < n_switches; i++) {
        cofp_swb->conn_str[OFP_CONN_DESC_SZ-1] = '\0';
        ofp_switch_states_tostr(string, ntohl(cofp_swb->state));
        len += snprintf(pbuf + len, SWITCH_BR_PBUF_SZ-len-1,
                        "0x%012llx    %-11s %-26s %-8d\r\n",
                        U642ULL(ntohll(cofp_swb->switch_id.datapath_id)),
                        string,
                        cofp_swb->conn_str,
                        ntohl(cofp_swb->n_ports));
        if (len >= SWITCH_BR_PBUF_SZ-1) {
            c_log_err("%s: pbuf overrun", FN);
            break;
        }
        cofp_swb += 1;
    }

out:
    if (free_buf) {
        if (b) free_cbuf(b);
    }    

    return pbuf;
}

/**
 * mul_get_switch_detail -
 *
 * Get detail switch info connected to mul 
 */
struct cbuf *
mul_get_switch_detail(void *service, uint64_t dpid)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_req_dpid_attr *cofp_rda;
    struct ofp_header *h;

    if (!service) return NULL;

    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rda),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_MUL_GET_SWITCH_DETAIL);
    cofp_rda = (void *)(cofp_auc->data);
    cofp_rda->datapath_id = htonll(dpid);

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        h = (void *)(b->data);
        if (h->type != C_OFPT_SWITCH_ADD ||
            ntohs(h->length) < sizeof(struct ofp_switch_features)) {
            c_log_err("%s: Failed", FN);
            free_cbuf(b);
            return NULL;
        }
    }

    return b;
}
 

/**
 * mul_dump_switch_detail -
 */
char *
mul_dump_switch_detail(struct cbuf *b, bool free_buf)
{
    char    *pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ);
    int     len = 0; 
    int     i = 0, n_ports;
    struct c_ofp_switch_add *osf = CBUF_DATA(b);
    char    string[OFP_PRINT_MAX_STRLEN];
    
    if (!pbuf) {
        c_log_err("%s: pbuf alloc failed", FN);
        goto out;
    }

    n_ports = ((ntohs(osf->header.length)
                - offsetof(struct ofp_switch_features, ports))
            / sizeof *osf->ports);

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1, "Datapath-id : 0x%llx\r\n",
                    U642ULL(ntohll(osf->datapath_id)));
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1, "Alias-id    : %d\r\n",
                    C_GET_ALIAS_IN_SWADD(osf));
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1, "OFP-ver     : %d\r\n",
                    osf->ver);
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err;

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Buffers     : %d\r\n",ntohl(osf->n_buffers));
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Tables      : %d\r\n", osf->n_tables);
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

#if 0 // This is deprecated with OF1.3.1
    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Actions     : 0x%x\r\n", ntohl(osf->actions));
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 
#endif

    memset(string, 0, 64);
    ofp_capabilities_tostr(string, ntohl(osf->capabilities));

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Capabilities: 0x%x(%s)\r\n", ntohl(osf->capabilities),
                    string);
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Num Ports   : %d\r\n", n_ports);
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
            "-------------------------------------------"
            "----------------------------------\r\n");
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "                              Port info\r\n");
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
            "-------------------------------------------"
            "----------------------------------\r\n");
    if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 


    for (i = 0; i < n_ports; i ++) {
        struct c_sw_port   *p_info = &osf->ports[i];

        p_info->name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
        memset(string, 0, OFP_PRINT_MAX_STRLEN);
        ofp_port_config_tostr(string, ntohl(p_info->config));

        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "%-6d %-10s %02x:%02x:%02x:%02x:%02x:%02x %-15s\r\n",
                        ntohl(p_info->port_no), p_info->name,
                        p_info->hw_addr[0], p_info->hw_addr[1], p_info->hw_addr[2],
                        p_info->hw_addr[3], p_info->hw_addr[4], p_info->hw_addr[5],
                        string);
        if (len >= MUL_SERVLET_PBUF_DFL_SZ-1) goto out_pbuf_err; 

        memset(string, 0, OFP_PRINT_MAX_STRLEN);
    }


out:
    if (free_buf) {
        if (b) free_cbuf(b);
    }    

    return pbuf;
out_pbuf_err:
    c_log_err("%s: pbuf overrun", FN);
    goto out;
}

static void
mul_dump_single_flow(struct c_ofp_flow_info *cofp_fi, void *arg,
                     void (*cb_fn)(void *arg, void *pbuf))
{
    char     *pbuf;
    int      len = 0;
    size_t   action_len;
    uint64_t dpid = U642ULL(ntohll(cofp_fi->datapath_id));
    uint8_t  version;

    version = c_app_switch_get_version_with_id(dpid);
    if (version != OFP_VERSION && version !=  OFP_VERSION_131) {
        cb_fn(arg, "Unable to parse flow:Unknown OFP version");
        return;
    }

    action_len = ntohs(cofp_fi->header.length) - sizeof(*cofp_fi);
        
    cb_fn(arg, print_sep);
    pbuf = of_dump_flow_generic(&cofp_fi->flow, &cofp_fi->mask);
    if (pbuf) {
        cb_fn(arg, pbuf);
        free(pbuf);
    }

    if (version == OFP_VERSION)
        pbuf = of10_dump_actions(cofp_fi->actions, action_len, false);
    else if (version == OFP_VERSION_131)
        pbuf = of131_dump_actions(cofp_fi->actions, action_len, false);
    else {
        NOT_REACHED();
    }
    if (pbuf) {
        cb_fn(arg, pbuf);
        free(pbuf);
    }

    pbuf = calloc(1, MUL_SERVLET_PBUF_DFL_SZ); 
    if (!pbuf) return; 

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "%s: %hu ", "Prio", ntohs(cofp_fi->priority));

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "%s: %s %s %s ", "Flags",
            cofp_fi->flags & C_FL_ENT_STATIC ? "static":"dynamic",
            cofp_fi->flags & C_FL_ENT_CLONE ? "clone": "no-clone",
            cofp_fi->flags & C_FL_ENT_LOCAL ? "local": "non-local"); 
    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "Datapath-id: 0x%llx ",
                    U642ULL(ntohll(cofp_fi->datapath_id)));

    if (cofp_fi->flags & C_FL_ENT_GSTATS) {
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Stats: Bytes %llu Packets %llu ",
                        U642ULL(ntohll(cofp_fi->byte_count)), 
                        U642ULL(ntohll(cofp_fi->packet_count)));
        len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                        "Bps %s Pps %s",
                        cofp_fi->bps, cofp_fi->pps);
    }

    len += snprintf(pbuf+len, MUL_SERVLET_PBUF_DFL_SZ-len-1,
                    "%s", "\r\n");
            
    cb_fn(arg, pbuf);
    free(pbuf);

    cb_fn(arg, print_sep);

    return;

}

static void
mul_dump_single_flow_cmd(struct c_ofp_flow_info *cofp_fi, void *arg,
                         void (*cb_fn)(void *arg, void *pbuf))
{
    char     *pbuf;
    size_t   action_len;

    action_len = ntohs(cofp_fi->header.length) - sizeof(*cofp_fi);

    pbuf = of_dump_flow_cmd(&cofp_fi->flow, cofp_fi->wildcards,
                            ntohll(cofp_fi->datapath_id));
    if (pbuf) {
        cb_fn(arg, pbuf);
        free(pbuf);
    }

    pbuf = of_dump_actions_cmd(cofp_fi->actions, action_len);
    if (pbuf) {
        cb_fn(arg, pbuf);
        free(pbuf);
    }

    return;
}

/**
 * mul_get_flow_info -
 *
 * Dump all flows 
 */
int
mul_get_flow_info(void *service, uint64_t dpid, bool flow_self,
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  void (*cb_fn)(void *arg, void *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_req_dpid_attr *cofp_rda;
    struct c_ofp_flow_info *cofp_fi;
    struct ofp_header *h;
    int n_flows = 0;
    struct cbuf_head bufs;
    int retries = 0;

    if (!service) return -1;

    if (!cb_fn) {
        c_log_err("%s: cb fn is null", FN);
        return -1;
    }

    cbuf_list_head_init(&bufs);

try_again:
    b = of_prep_msg(sizeof(*cofp_auc) + sizeof(*cofp_rda),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = flow_self ?
                         htonl(C_AUX_CMD_MUL_GET_APP_FLOW):
                         htonl(C_AUX_CMD_MUL_GET_ALL_FLOWS);
    cofp_rda = (void *)(cofp_auc->data);
    cofp_rda->datapath_id = htonll(dpid);

    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            h = (void *)(b->data);
            if (h->type  != OFPT_FLOW_MOD) { 
                free_cbuf(b);
                break;
            }
            cofp_fi = (void *)(b->data);
            if (ntohs(cofp_fi->header.length) < sizeof(*cofp_fi)) {
                free_cbuf(b);
                goto try_restart;
            } 

            b = cbuf_realloc_headroom(b, 0, true);
            cbuf_list_queue_tail(&bufs, b);
            n_flows++;
        } else {
            goto try_restart;
        }
    }

    while ((b = cbuf_list_dequeue(&bufs))) {
        cofp_fi = (void *)(b->data);
        if (!dump_cmd) {
            if (!nbapi_cmd) {
                mul_dump_single_flow(cofp_fi, arg, cb_fn);
            } else {
                cb_fn(arg, cofp_fi);
            }
        } else {
            mul_dump_single_flow_cmd(cofp_fi, arg, cb_fn);
        }
        free_cbuf(b);
    }
    return n_flows;

try_restart:
    cbuf_list_purge(&bufs);
    if (retries++ >= C_SERV_RETRY_CNT) {
        cbuf_list_purge(&bufs);
        c_log_err("%s: Restarting serv msg", FN);
        goto try_again;
    }
    c_log_err("%s: Can't restart serv msg", FN);
    return 0;
}
