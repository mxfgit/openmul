/*
 *  mul_vty.c: MUL vty implementation 
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
#include "mul.h"
#include "mul_vty.h"

int c_vty_thread_run(void *arg);

char              *vty_addr = NULL;
int               vty_port  = C_VTY_PORT;
extern ctrl_hdl_t ctrl_hdl;

struct vty_common_args
{
    bool flow_act;
};

struct vty_flow_action_parms
{
    struct vty_common_args cmn;
    void *sw;
    void *fl;
    void *mask;
    mul_act_mdata_t mdata;
    uint32_t wildcards;
    bool drop_pkt;
};

struct vty_group_mod_parms
{
    struct vty_common_args cmn;
    void *sw;
    uint32_t group;
    uint8_t type;
    mul_act_mdata_t mdata[OF_MAX_ACT_VECTORS];
    bool drop_pkt[OF_MAX_ACT_VECTORS];
    size_t act_vec_len;
};

#define VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw, args) \
do { \
    struct vty_common_args *__cmn = (void *)(args); \
    if (__cmn->flow_act) { \
        struct vty_flow_action_parms *fl_parms = args; \
        (mdata) = &fl_parms->mdata; \
        (sw) = fl_parms->sw; \
    } else { \
        struct vty_group_mod_parms *g_parms = args; \
        (mdata) = &g_parms->mdata[g_parms->act_vec_len-1]; \
        (sw) = g_parms->sw; \
    } \
} while (0)

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
ofp_capabilities_tostr(char *string, uint32_t capabilities)
{
    if (capabilities == 0) {
        strcpy(string, "No capabilities\n");
        return;
    }
    if (capabilities & OFPC_FLOW_STATS) {
        strcpy(string, "FLOW_STATS ");
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

static void UNUSED
ofp_port_features_tostr(char *string, uint32_t features)
{
    if (features == 0) {
        strcpy(string, "Unsupported\n");
        return;
    }
    if (features & OFPPF_10MB_HD) {
        strcat(string, "10MB-HD ");
    }
    if (features & OFPPF_10MB_FD) {
        strcat(string, "10MB-FD ");
    }
    if (features & OFPPF_100MB_HD) {
        strcat(string, "100MB-HD ");
    }
    if (features & OFPPF_100MB_FD) {
        strcat(string, "100MB-FD ");
    }
    if (features & OFPPF_1GB_HD) {
        strcat(string, "1GB-HD ");
    }
    if (features & OFPPF_1GB_FD) {
        strcat(string, "1GB-FD ");
    }
    if (features & OFPPF_10GB_FD) {
        strcat(string, "10GB-FD ");
    }
    if (features & OFPPF_COPPER) {
        strcat(string, "COPPER ");
    }
    if (features & OFPPF_FIBER) {
        strcat(string, "FIBER ");
    }
    if (features & OFPPF_AUTONEG) {
        strcat(string, "AUTO_NEG ");
    }
    if (features & OFPPF_PAUSE) {
        strcat(string, "AUTO_PAUSE ");
    }
    if (features & OFPPF_PAUSE_ASYM) {
        strcat(string, "AUTO_PAUSE_ASYM ");
    }
}

static void
c_port_config_tostr(char *string, uint32_t config)
{
    if (config & C_MLPC_DOWN) {
        strcat(string, " PORT_DOWN");
    } else {
        strcat(string, " PORT_UP");
    }
}

static void
c_port_state_tostr(char *string, uint32_t config)
{
    if (config & C_MLPS_DOWN) {
        strcat(string, " LINK_DOWN");
    } else {
        strcat(string, " LINK_UP");
    }
}

static void
of_show_switch_info(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;
    struct      vty *vty = arg;
    char        string[OFP_PRINT_MAX_STRLEN];

    ofp_switch_states_tostr(string, sw->switch_state);

    vty_out (vty, "0x%012llx    %-11s %-26s %-8d %s",
             sw->datapath_id,
             string,
             sw->conn.conn_str,
             sw->n_ports,
             VTY_NEWLINE);
}


DEFUN (show_of_switch,
       show_of_switch_cmd,
       "show of-switch all",
       SHOW_STR
       "Openflow switches\n"
       "Summary information for all")
{

    vty_out (vty,
            "%sSwitch-DP-id    |   State     |  "
            "Peer                 | Ports%s",
            VTY_NEWLINE, VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    c_switch_traverse_all(&ctrl_hdl, of_show_switch_info, vty);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}

static void
of_show_switch_port_info(void *k UNUSED, void *v, void *arg)
{
    c_sw_port_t *p_info = v;
    struct vty *vty = arg;
    char string[OFP_PRINT_MAX_STRLEN];

    memset(string, 0, OFP_PRINT_MAX_STRLEN);
    c_port_config_tostr(string, p_info->config);
    c_port_state_tostr(string, p_info->state);

    vty_out(vty, "%-6d %-10s %02x:%02x:%02x:%02x:%02x:%02x %-15s",
            p_info->port_no, p_info->name,
            p_info->hw_addr[0], p_info->hw_addr[1], p_info->hw_addr[2],
            p_info->hw_addr[3], p_info->hw_addr[4], p_info->hw_addr[5],
            string);

    memset(string, 0, OFP_PRINT_MAX_STRLEN);
    vty_out(vty, "%s", VTY_NEWLINE);
}

DEFUN (show_of_switch_detail,
       show_of_switch_detail_cmd,
       "show of-switch X detail",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Detailed information\n")
{
    uint64_t dp_id;
    c_switch_t *sw;
    char string[OFP_PRINT_MAX_STRLEN];

    dp_id = strtoull(argv[0], NULL, 16);

    sw = c_switch_get(&ctrl_hdl, dp_id);

    if (!sw) {
        return CMD_SUCCESS;
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);
    vty_out (vty, "Datapath-id : 0x%llx%s", (unsigned long long)dp_id, VTY_NEWLINE);
    vty_out (vty, "OFP-Version : 0x%d%s", sw->version, VTY_NEWLINE);
    vty_out (vty, "Buffers     : %d%s", sw->n_buffers, VTY_NEWLINE);
    vty_out (vty, "Tables      : %d%s", sw->n_tables, VTY_NEWLINE);
    vty_out (vty, "Actions     : 0x%x%s", sw->actions, VTY_NEWLINE);

    memset(string, 0, OFP_PRINT_MAX_STRLEN);
    ofp_capabilities_tostr(string, sw->capabilities);

    vty_out (vty, "Capabilities: 0x%x(%s)%s", sw->capabilities,
            string, VTY_NEWLINE);
    vty_out (vty, "Num Ports   : %d%s", sw->n_ports, VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    vty_out (vty, "                              Port info%s",
            VTY_NEWLINE);
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    c_rd_lock(&sw->lock);
    __c_switch_port_traverse_all(sw, of_show_switch_port_info, vty);
    c_rd_unlock(&sw->lock);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    c_switch_put(sw);

    return CMD_SUCCESS;

}

struct cmd_node flow_actions_node =
{
    FLOW_NODE,
    "(config-flow-action)# ",
    1,
    NULL,
    NULL 
};

static void
vty_of_print_flow(void *arg, c_fl_entry_t *ent)
{
    char *flow_print_str = NULL;
    char *actions_print_str = NULL;
    char *wc_print_str = NULL;
    char *flow_app_str = NULL;
    struct vty *vty = arg;

    assert(ent->sw->ofp_ctors->dump_flow);
    assert(ent->sw->ofp_ctors->dump_acts);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    flow_print_str = ent->sw->ofp_ctors->dump_flow(&ent->fl, &ent->fl_mask);
    vty_out(vty, "%s", flow_print_str);

    actions_print_str = ent->sw->ofp_ctors->dump_acts(ent->actions,
                                                      ent->action_len,
                                                      false);
    vty_out(vty, "%s %s", "Actions:", actions_print_str);

    if (!(ent->FL_FLAGS & C_FL_ENT_CLONE) && (ent->FL_FLAGS & C_FL_ENT_GSTATS) 
        && !(ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
        vty_out(vty, "%s: Bytes %llu Packets %llu ", "Stats",
                (unsigned long long)ent->fl_stats.byte_count, 
                (unsigned long long)ent->fl_stats.pkt_count);

        vty_out(vty, " Bps %f Pps %f\r\n",
                (float)ent->fl_stats.bps,  (float)ent->fl_stats.pps);
    }

    vty_out(vty, "%s:%hu %s:%d ", "Prio", ent->FL_PRIO, "Table", ent->fl.table_id);
    vty_out(vty, "%s:%s %s %s ", "Flags",
            ent->FL_FLAGS & C_FL_ENT_STATIC ? "static":"dynamic",
            ent->FL_FLAGS & C_FL_ENT_CLONE ? "clone": "no-clone",
            ent->FL_FLAGS & C_FL_ENT_LOCAL ? "local": "non-local");

    flow_app_str = of_dump_fl_app(ent);
    vty_out(vty, "%s\r\n", flow_app_str);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);


    if (flow_print_str) free(flow_print_str);
    if (actions_print_str) free(actions_print_str);
    if (wc_print_str) free(wc_print_str);
    if (flow_app_str) free(flow_app_str);
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
    c_switch_t                  *sw;

    dp_id = strtoull(argv[0], NULL, 16);

    sw = c_switch_get(&ctrl_hdl, dp_id);

    if (!sw) {
        return CMD_SUCCESS;
    }

    if (sw->fp_ops.fp_db_dump) {
        sw->fp_ops.fp_db_dump(sw, vty, vty_of_print_flow);
    } else {
        c_flow_traverse_tbl_all(sw, vty, vty_of_print_flow); 
    }

    c_switch_put(sw);

    return CMD_SUCCESS;
}

DEFUN (of_add_goto_instruction,
       of_add_goto_instruction_cmd,
       "action-add goto <1-254>",
       "Add openflow action\n"
       "goto instruction\n"
       "Enter table-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw, vty->index);

    if (sw->ofp_ctors->inst_goto) {
        sw->ofp_ctors->inst_goto(mdata, atoi(argv[0]));
    } else {
        vty_out(vty, "Instruction not supported by switch\r\n");
    }

    return CMD_SUCCESS;
}

DEFUN (of_add_output_action,
       of_add_output_action_cmd,
       "action-add output <0-65535>",
       "Add openflow action\n"
       "Output action\n"
       "Enter port-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw, vty->index);

    if (sw->ofp_ctors->act_output) {
        sw->ofp_ctors->act_output(mdata, atoi(argv[0]));
    } else {
        vty_out(vty, "Action not supported by switch\r\n");
    }

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
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw,  vty->index);

    if (sw->ofp_ctors->act_set_vid) {
        sw->ofp_ctors->act_set_vid(mdata, strtoull(argv[0], NULL, 10));
    } else {
        vty_out(vty, "Action not supported by switch\r\n");
    }

    return CMD_SUCCESS;
}

DEFUN (of_add_strip_vlan_action,
       of_add_strip_vlan_action_cmd,
       "action-add strip-vlan",
       "Add openflow action\n"
       "Strip vlan action\n")
{
    mul_act_mdata_t *mdata = NULL;
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw,  vty->index);

    if (sw->ofp_ctors->act_strip_vid) {
        sw->ofp_ctors->act_strip_vid(mdata);
    } else {
        vty_out(vty, "Action not supported by switch\r\n");
    }

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
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw, vty->index);

    if (sw->ofp_ctors->act_set_vlan_pcp) {
        sw->ofp_ctors->act_set_vlan_pcp(mdata, strtoull(argv[0], NULL, 10));
    } else {
        vty_out(vty, "Action not supported by switch\r\n");
    }

    return CMD_SUCCESS;
}


DEFUN (of_add_set_dmac_action,
       of_add_set_dmac_action_cmd,
       "action-add set-dmac X",
       "Add openflow action\n"
       "set dmac action\n"
       "Enter MAC address (xx:xx:xx:xx:xx:xx) \n")
{
    uint8_t dmac[6];
    char *mac_str, *next = NULL;
    int i = 0;
    mul_act_mdata_t *mdata = NULL;
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw, vty->index);

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


    if (sw->ofp_ctors->act_set_dmac) {
        sw->ofp_ctors->act_set_dmac(mdata, dmac);
    } else {
        vty_out(vty, "Action not supported by switch\r\n");
    }

    return CMD_SUCCESS;
}

DEFUN (of_add_set_smac_action,
       of_add_set_smac_action_cmd,
       "action-add set-smac X",
       "Add openflow action\n"
       "set smac action\n"
       "Enter MAC address (xx:xx:xx:xx:xx:xx) \n")
{
    uint8_t smac[6];
    char *mac_str, *next = NULL;
    int i = 0;
    mul_act_mdata_t *mdata = NULL;
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw, vty->index);

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

    if (sw->ofp_ctors->act_set_smac) {
        sw->ofp_ctors->act_set_smac(mdata, smac);
    } else {
        vty_out(vty, "Action not supported by switch\r\n");
    }

    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_saddr_action,
       of_add_set_nw_saddr_action_cmd,
       "action-add nw-saddr A.B.C.D",
       "Add openflow action\n"
       "set source ip address action\n"
       "Enter ip address\n")
{
    struct in_addr ip_addr;
    mul_act_mdata_t *mdata = NULL;
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw, vty->index);

    if (inet_aton(argv[0], &ip_addr) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (sw->ofp_ctors->act_set_nw_saddr) {
        sw->ofp_ctors->act_set_nw_saddr(mdata, ntohl(ip_addr.s_addr));
    } else {
        vty_out(vty, "Action not supported by switch\r\n");        
    }

    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_daddr_action,
       of_add_set_nw_daddr_action_cmd,
       "action-add nw-daddr A.B.C.D",
       "Add openflow action\n"
       "set destination ip address action\n"
       "Enter ip address\n")
{
    struct in_addr ip_addr;
    mul_act_mdata_t *mdata = NULL;
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw, vty->index);

    if (inet_aton(argv[0], &ip_addr) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (sw->ofp_ctors->act_set_nw_daddr) {
        sw->ofp_ctors->act_set_nw_daddr(mdata, ntohl(ip_addr.s_addr));
    } else {
        vty_out(vty, "Action not supported by switch\r\n");
    }

    return CMD_SUCCESS;
}

DEFUN (of_add_set_group_action,
       of_add_set_group_action_cmd,
       "action-add group-id <0-65535>",
       "Add openflow action\n"
       "set group-id action\n"
       "Enter group-id\n")
{
    mul_act_mdata_t *mdata = NULL;
    c_switch_t *sw = NULL;
    VTY_ARGS_TO_ACT_MDATA_SW(mdata, sw,  vty->index);

    if (sw->ofp_ctors->act_set_group) {
        sw->ofp_ctors->act_set_group(mdata, strtoull(argv[0], NULL, 10));
    } else {
        vty_out(vty, "Action not supported by switch\r\n");
    }

    return CMD_SUCCESS;
}

DEFUN (of_add_drop_action,
       of_add_drop_action_cmd,
       "action-add drop",
       "Add openflow action\n"
       "drop packet action\n")
{
    struct vty_common_args *__cmn = vty->index;
    if (__cmn->flow_act) {
        struct vty_flow_action_parms *fl_parms = vty->index;
        fl_parms->drop_pkt = true;
    } else {
        struct vty_group_mod_parms *g_parms = vty->index;
        g_parms->drop_pkt[g_parms->act_vec_len] = true;
    }

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


DEFUN (flow_actions_commit,
       flow_actions_commit_cmd,
       "commit",
       "commit the flow and its actions")
{
    struct vty_flow_action_parms *args = vty->index;
    struct of_flow_mod_params fl_parms;
    c_switch_t *sw; 
    void *app;

    if (args) {
        sw = args->sw;
        if ((of_mact_len(&args->mdata) >= 4 || args->drop_pkt)&& args->sw) {

            app = c_app_get(&ctrl_hdl, C_VTY_NAME);
            if (app && sw->switch_state & SW_REGISTERED) {

                /* TODO action validation here */
                memset(&fl_parms, 0, sizeof(fl_parms));

                fl_parms.flow = args->fl;
                fl_parms.mask = args->mask;
                if (!args->drop_pkt) {
                    fl_parms.actions = args->mdata.act_base;
                    fl_parms.action_len = of_mact_len(&args->mdata);
                    fl_parms.prio = C_FL_PRIO_DFL;
                } else {
                    of_mact_free(&args->mdata);
                    fl_parms.prio = C_FL_PRIO_DRP;
                    vty_out(vty, "Ignoring all non-drop actions if any%s",
                            VTY_NEWLINE);
                }
                fl_parms.buffer_id = (uint32_t)(-1);
                fl_parms.flags = C_FL_ENT_GSTATS | C_FL_ENT_STATIC;
                fl_parms.prio = C_FL_PRIO_DFL;
                fl_parms.app_owner = app;
                c_switch_flow_add(args->sw, &fl_parms);
            }
            if (app) c_app_put(app);
            else vty_out(vty, "Can't get vty app handle%s", VTY_NEWLINE);
        } else {
            vty_out(vty, "No actions added.Flow not added%s", VTY_NEWLINE);
        } 

        if (args->fl) {
            free(args->fl);
        }
        if (args->mask) {
            free(args->mask);
        }

        free(args);
        vty->index = NULL;
    }

    vty->node = CONFIG_NODE;
    return CMD_SUCCESS;
}



DEFUN (flow_actions_exit,
       flow_actions_exit_cmd,
       "exit",
       "Exit from Flow action configuration mode")
{
    struct vty_flow_action_parms *args = vty->index;

    if (args) {
        if (args->sw) {
            c_switch_put(args->sw);
        }
        free(args->fl);
        free(args->mask);
        free(args);
    }

    vty->node = CONFIG_NODE;
    return CMD_SUCCESS;
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
    uint64_t                     dp_id;
    c_switch_t                   *sw;
    struct flow                  *flow;
    struct flow                  *mask;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct prefix_ipv4           dst_p, src_p;
    struct vty_flow_action_parms *args; 
    uint32_t                     nmask;

    flow = calloc(1, sizeof(*flow));
    assert(flow);

    mask = calloc(1, sizeof(*flow));
    assert(mask);
    memset(mask, 0xff, sizeof(*flow));

    args = calloc(1, sizeof(*args));
    assert(args);

    of_mact_alloc(&args->mdata);

    dp_id = strtoull(argv[0], NULL, 16);
    sw = c_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        free(flow);
        of_mact_free(&args->mdata);
        free(args);
        free(mask);
        return CMD_WARNING;
    }

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
            goto deref_free_err_out;
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
            goto deref_free_err_out;  
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
        goto deref_free_err_out;
    }

    if (dst_p.prefixlen) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            nmask = make_inet_mask(dst_p.prefixlen);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto deref_free_err_out;
        }
    } else {
        nmask = 0;
    }

    mask->nw_dst = htonl(nmask);
    flow->nw_dst = dst_p.prefix.s_addr & htonl(nmask); 

    ret = str2prefix(argv[7], (void *)&src_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;
    }

    if (src_p.prefixlen) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            nmask = make_inet_mask(src_p.prefixlen);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto deref_free_err_out;
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
            goto deref_free_err_out;
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
            goto deref_free_err_out;
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
            goto deref_free_err_out;
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
            goto deref_free_err_out;
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
    char *fl_str = of1_0_dump_flow(flow, mask);
    printf ("%s\n", fl_str);
    free(fl_str);
#endif

    args->fl = flow;
    args->mask = mask;
    args->sw = sw;
    args->wildcards = 0;
    args->cmn.flow_act = true;

    vty->index = args;

    if ((ret = flow_actions_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto deref_free_err_out;  
    }

    c_switch_put(sw);  

    return CMD_SUCCESS;

deref_free_err_out:
    of_mact_free(&args->mdata);
    free(args);
    free(mask);
    free(flow);
    c_switch_put(sw);  
    return CMD_WARNING;
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
    c_switch_t                   *sw;
    struct flow                  *flow;
    struct flow                  *mask;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct prefix_ipv4           dst_p, src_p;
    uint32_t                     nmask;
    struct of_flow_mod_params    fl_parms;
    void                         *app;

    memset(&fl_parms, 0, sizeof(fl_parms));

    flow = calloc(1, sizeof(*flow));
    assert(flow);

    mask = calloc(1, sizeof(*flow));
    assert(mask);
    memset(mask, 0xff, sizeof(*flow));

    dp_id = strtoull(argv[0], NULL, 16);
    sw = c_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        free(flow);
        free(mask);
        return CMD_WARNING;
    }

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
            goto deref_free_err_out;
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
            goto deref_free_err_out;  
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
        goto deref_free_err_out;
    }

    if (dst_p.prefixlen) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            nmask = make_inet_mask(dst_p.prefixlen);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto deref_free_err_out;
        }
    } else {
        nmask = 0;
    }

    mask->nw_dst = htonl(nmask);
    flow->nw_dst = dst_p.prefix.s_addr & htonl(nmask); 

    ret = str2prefix(argv[7], (void *)&src_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;
    }

    if (src_p.prefixlen) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            nmask = make_inet_mask(src_p.prefixlen);
        } else {
            vty_out (vty, "dl_type != ETH_TYPE_IP %s", VTY_NEWLINE);
            goto deref_free_err_out;
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
            goto deref_free_err_out;
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
            goto deref_free_err_out;
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
            goto deref_free_err_out;
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
            goto deref_free_err_out;
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
    char *fl_str = of_dump_flow(flow);
    printf ("%s\n", fl_str);
    printf ("0x%x\n", wildcards);
    free(fl_str);
#endif
    fl_parms.flow = flow;
    fl_parms.mask = mask;
    fl_parms.wildcards = 0;
    fl_parms.prio = C_FL_PRIO_DFL;

    if (!(app = c_app_get(&ctrl_hdl, C_VTY_NAME))) {
        goto deref_free_err_out;  
    }

    fl_parms.app_owner = app;

    if (c_switch_flow_del(sw, &fl_parms)) {
        vty_out(vty, "Flow delete failed\r\n");
    } else {
        vty_out(vty, "Flow deleted\r\n");
    }

    c_app_put(app);
    c_switch_put(sw);  

    free(flow);
    free(mask);

    return CMD_SUCCESS;

deref_free_err_out:
    free(flow);
    free(mask);
    c_switch_put(sw);  
    return CMD_WARNING;
}

DEFUN (of_flow_reset,
       of_flow_reset_cmd,
       "of-flow reset-all switch X",
       "Openflow flow\n"  
       "reset-all flows\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n")
{
    uint64_t                     dp_id;
    c_switch_t                   *sw;
    struct flow                  flow;
    struct flow                  mask;
    struct of_flow_mod_params    fl_parms;

    memset(&fl_parms, 0, sizeof(fl_parms));
    memset(&flow, 0, sizeof(flow));
    memset(&mask, 0, sizeof(mask));

    dp_id = strtoull(argv[0], NULL, 16);
    sw = c_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        return CMD_WARNING;
    }

    __of_send_flow_del_direct(sw, &flow, &mask, OFPP_NONE,
                              false, C_FL_PRIO_DFL, OFPG_ANY);

    c_switch_flow_tbl_reset(sw);
    c_switch_put(sw);

    vty_out(vty, "All Flows reset\r\n");

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
    struct vty_group_mod_parms *args = vty->index;
    int act;

    if (args) {
        for (act = 0; act < args->act_vec_len; act++) {
            of_mact_free(&args->mdata[act]);
        }
        if (args->sw) {
            c_switch_put(args->sw);
            args->sw = NULL;
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
    struct vty_group_mod_parms *args = vty->index;

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

    return CMD_SUCCESS;
}

DEFUN (group_commit,
       group_commit_cmd,
       "commit-group",
       "commit the group and its actions-vectors")
{
    struct vty_group_mod_parms *args = vty->index;
    struct of_group_mod_params g_parms;
    struct of_act_vec_elem *act_elem;
    c_switch_t *sw; 
    void *app;
    int act = 0;

    memset(&g_parms, 0, sizeof(g_parms));

    if (args) {

        if (!args->drop_pkt[args->act_vec_len-1] &&
            !of_mact_len(&args->mdata[args->act_vec_len-1])) {
            vty_out(vty, "No actions added. Try adding again..\r\n");
            return CMD_SUCCESS;
        }

        sw = args->sw;
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
        app = c_app_get(&ctrl_hdl, C_VTY_NAME);
        if (app && sw->switch_state & SW_REGISTERED) {
            g_parms.app_owner = app;
            if (c_switch_group_add(args->sw, &g_parms)) {
                vty_out(vty, "Group add failed\r\n"); 
                for (act = 0; act < args->act_vec_len; act++) {
                     of_mact_free(&args->mdata[act]);
                     free(g_parms.act_vectors[act]);
                }
            }
        }
        if (app) c_app_put(app);
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
    uint64_t dp_id;
    struct vty_group_mod_parms *vty_parms;
    c_switch_t *sw;
    uint32_t group;
    uint8_t type;
    int ret = CMD_WARNING;

    dp_id = strtoull(argv[0], NULL, 16);
    sw = c_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        vty_out(vty, "No such switch\r\n");
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

    vty_parms = calloc(1, sizeof(*vty_parms));
    if (!vty_parms) {
        return CMD_WARNING;
    }

    vty_parms->sw = sw;
    vty_parms->group = group;
    vty_parms->type = type;    
    of_mact_alloc(&vty_parms->mdata[0]);
    vty_parms->mdata[0].only_acts = true;
    vty_parms->act_vec_len = 1;

    vty->index = vty_parms;

    if ((ret = group_actions_vectors_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto free_err_out;
    }

    c_switch_put(sw);

    return CMD_SUCCESS;

free_err_out:
    /* FIXME - Free action vectors */ 
    free(vty_parms);
    c_switch_put(sw);
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
    c_switch_t *sw;
    uint64_t dp_id;
    uint32_t group;
    void *app;

    memset(&gp_parms, 0, sizeof(gp_parms));

    dp_id = strtoull(argv[0], NULL, 16);
    sw = c_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        vty_out(vty, "group-del fail : No such switch\r\n");
        return CMD_WARNING;
    }

    group = atol(argv[1]);
    if (!(app = c_app_get(&ctrl_hdl, C_VTY_NAME))) {
        vty_out(vty, "group-del fail : Internal Error\r\n");
        goto err_out;
    }

    gp_parms.group = group;
    gp_parms.app_owner = app;

    if (c_switch_group_del(sw, &gp_parms)) {
        vty_out(vty, "group-del fail : Error\r\n");
    }

    c_app_put(app);
    c_switch_put(sw);

    return CMD_SUCCESS;

err_out:
    c_switch_put(sw);
    return CMD_WARNING;
}


static void
of_show_switch_group_info(void *arg, c_switch_group_t *grp)
{
    char *grp_types[] = { "all", "select", "indirect", "ff" }; 
    char *type;
    int act = 0;
    c_switch_t *sw = grp->sw;
    struct vty *vty = arg;
 
    if (grp->type > OFPGT_FF) {
        type = "Unknown"; 
    } else {
        type = grp_types[grp->type];
    }
 
    vty_out(vty, "Group: %lu Type: %s\r\n", U322UL(grp->group), type);
    for (act = 0; act < grp->act_vec_len; act++) {
        char *pbuf;
        vty_out(vty, "Action bucket %d: ", act); 
        if (sw->ofp_ctors && sw->ofp_ctors->dump_acts) {
            pbuf = sw->ofp_ctors->dump_acts(grp->act_vectors[act]->actions,
                                            grp->act_vectors[act]->action_len,
                                            true);
            vty_out(vty, "%s", pbuf); 
            free(pbuf);
        }
    }
    vty_out(vty, "%s", VTY_NEWLINE);
}

DEFUN (show_of_switch_group,
       show_of_switch_group_cmd,
       "show of-switch X groups",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Groups information\n")
{
    uint64_t dp_id;
    c_switch_t *sw;

    dp_id = strtoull(argv[0], NULL, 16);

    sw = c_switch_get(&ctrl_hdl, dp_id);

    if (!sw) {
        return CMD_SUCCESS;
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    c_switch_group_traverse_all(sw, vty, of_show_switch_group_info);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    c_switch_put(sw);

    return CMD_SUCCESS;

}


 
static void
modvty__initcalls(void *arg)
{
    initcall_t *mod_init;

    mod_init = &__start_modvtyinit_sec;
    do {
        (*mod_init)(arg);
        mod_init++;
    } while (mod_init < &__stop_modvtyinit_sec);
}

static void
mul_vty_init(void)
{
    install_node(&flow_actions_node, NULL);
    install_node(&group_node, NULL);
    install_element(ENABLE_NODE, &show_of_switch_cmd);
    install_element(ENABLE_NODE, &show_of_switch_detail_cmd);
    install_element(CONFIG_NODE, &of_flow_vty_add_cmd);
    install_element(CONFIG_NODE, &of_flow_vty_del_cmd);
    install_element(CONFIG_NODE, &of_flow_reset_cmd);
    install_element(ENABLE_NODE, &show_of_switch_flow_cmd);
    install_default(FLOW_NODE);
    install_element(FLOW_NODE, &of_add_goto_instruction_cmd);
    install_element(FLOW_NODE, &of_add_output_action_cmd);
    install_element(FLOW_NODE, &of_add_set_vid_action_cmd);
    install_element(FLOW_NODE, &of_add_set_dmac_action_cmd);
    install_element(FLOW_NODE, &flow_actions_exit_cmd);
    install_element(FLOW_NODE, &flow_actions_commit_cmd);
    install_element(FLOW_NODE, &of_add_set_nw_saddr_action_cmd);
    install_element(FLOW_NODE, &of_add_set_nw_daddr_action_cmd);
    install_element(FLOW_NODE, &of_add_set_smac_action_cmd);
    install_element(FLOW_NODE, &of_add_strip_vlan_action_cmd);
    install_element(FLOW_NODE, &of_add_set_vpcp_action_cmd);
    install_element(FLOW_NODE, &of_add_drop_action_cmd);
    install_element(FLOW_NODE, &of_add_set_group_action_cmd);
    install_element(CONFIG_NODE, &of_group_vty_add_cmd);
    install_element(CONFIG_NODE, &of_group_vty_del_cmd);
    install_element(ENABLE_NODE, &show_of_switch_group_cmd);
    install_default(GROUP_NODE);
    install_element(GROUP_NODE, &of_add_output_action_cmd);
    install_element(GROUP_NODE, &of_add_set_vid_action_cmd);
    install_element(GROUP_NODE, &of_add_set_dmac_action_cmd);
    install_element(GROUP_NODE, &of_add_set_nw_saddr_action_cmd);
    install_element(GROUP_NODE, &of_add_set_nw_daddr_action_cmd);
    install_element(GROUP_NODE, &of_add_set_smac_action_cmd);
    install_element(GROUP_NODE, &of_add_strip_vlan_action_cmd);
    install_element(GROUP_NODE, &of_add_set_vpcp_action_cmd);
    install_element(GROUP_NODE, &group_act_vector_done_cmd);
    install_element(GROUP_NODE, &group_commit_cmd);
    install_element(GROUP_NODE, &group_act_vec_exit_cmd);
    
    modvty__initcalls(NULL);
}

int
c_vty_thread_run(void *arg)
{
    uint64_t            dpid = 0;
    struct thread       thread;
    struct c_vty_ctx    *vty_ctx = arg;
    ctrl_hdl_t          *c_hdl = vty_ctx->cmn_ctx.c_hdl; 

    c_set_thread_dfl_affinity();

    signal(SIGPIPE, SIG_IGN);

    /* Register vty as an app for static flow install */
    mul_register_app(NULL, C_VTY_NAME, 0, 0, 1, &dpid, NULL);

    c_hdl->vty_master = thread_master_create();

    cmd_init(1);
    vty_init(c_hdl->vty_master);
    mul_vty_init();
    sort_node();

    vty_serv_sock(vty_addr, vty_port, C_VTYSH_PATH, 1);

    c_log_debug(" VTY THREAD RUNNING \n");

     /* Execute each thread. */
    while (thread_fetch(c_hdl->vty_master, &thread))
        thread_call(&thread);

    /* Not reached. */
    return (0);
}
