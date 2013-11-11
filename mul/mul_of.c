/*
 *  mul_of.c: MUL openflow abstractions 
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

extern ctrl_hdl_t ctrl_hdl;
extern struct c_rlim_dat crl; 

static void of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, 
                             uint32_t buffer_id, bool ha_sync);
static void of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent,
                             uint16_t oport, bool strict, uint32_t group);
static void of_send_flow_del_strict(c_switch_t *sw, c_fl_entry_t *ent,
                                    uint16_t oport, uint32_t group);
static void c_send_flow_add_sync(c_switch_t *sw, c_fl_entry_t *ent,
                                  uint32_t buffer_id);
static c_fl_entry_t *__c_flow_get_exm(c_switch_t *sw, struct flow *fl);
static void c_flow_rule_free(void *arg, void *u_arg);
static void port_config_to_ofxlate(uint32_t *of_port_config, uint32_t config);
static void port_status_to_ofxlate(uint32_t *of_port_config, uint32_t status);
static void c_switch_group_ent_free(void *arg);

struct c_ofp_rx_handler of_boot_handlers[];
struct c_ofp_rx_handler of_init_handlers[];
struct c_ofp_rx_handler of131_init_handlers[];
struct c_ofp_rx_handler of_handlers[];
struct c_ofp_rx_handler of131_handlers[];
struct c_ofp_proc_helpers ofp_priv_procs;
struct c_ofp_proc_helpers ofp131_priv_procs;

static struct c_ofp_ctors of10_ctors = {
    .hello = of_prep_hello,
    .echo_req = of_prep_echo,
    .echo_rsp = of_prep_echo_reply,
    .set_config = of_prep_set_config,
    .features = of_prep_features_request,
    .pkt_out = of_prep_pkt_out_msg,
    .pkt_out_fast = of_send_pkt_out_inline,
    .flow_add = of_prep_flow_add_msg,
    .flow_del = of_prep_flow_del_msg,
    .flow_stat_req = of_prep_flow_stat_msg,
    .normalize_flow = of10_flow_correction,
    .act_output = of_make_action_output,
    .act_set_vid = of_make_action_set_vid,
    .act_strip_vid = of_make_action_strip_vlan,
    .act_set_dmac = of_make_action_set_dmac,
    .act_set_smac = of_make_action_set_smac,
    .act_set_nw_saddr = of_make_action_set_nw_saddr,
    .act_set_nw_daddr = of_make_action_set_nw_daddr,
    .act_set_vlan_pcp = of_make_action_set_vlan_pcp,
    .act_set_nw_tos = of_make_action_set_nw_tos,
    .act_set_tp_udp_dport = of_make_action_set_tp_udp_dport,
    .act_set_tp_udp_sport = of_make_action_set_tp_udp_sport,
    .act_set_tp_tcp_dport = of_make_action_set_tp_tcp_dport,
    .act_set_tp_tcp_sport = of_make_action_set_tp_tcp_sport,
    .dump_flow = of10_dump_flow,
    .dump_acts = of10_dump_actions
};

static struct c_ofp_ctors of131_ctors = {
    .hello = of131_prep_hello_msg, 
    .echo_req = of_prep_echo,
    .echo_rsp = of_prep_echo_reply,
    .set_config = of131_prep_set_config_msg,
    .features = of131_prep_features_request_msg,
    .pkt_out = of131_prep_pkt_out_msg,
    .pkt_out_fast = of131_send_pkt_out_inline,
    .flow_add = of131_prep_flow_add_msg,
    .flow_del = of131_prep_flow_del_msg,
    .flow_stat_req = of131_prep_flow_stat_msg,
    .group_validate = of131_group_validate,
    .group_add = of131_prep_group_add_msg,
    .group_del = of131_prep_group_del_msg,
    .act_init = NULL,
    .act_fini = NULL,
    .inst_goto = of131_make_inst_goto,
    .act_output = of131_make_action_output,
    .act_set_vid = of131_make_action_set_vid,
    .act_strip_vid = of131_make_action_strip_vlan,
    .act_set_dmac = of131_make_action_set_dmac,
    .act_set_smac = of131_make_action_set_smac,
    .act_set_nw_saddr = of131_make_action_set_ipv4_src,
    .act_set_nw_daddr = of131_make_action_set_ipv4_dst, 
    .act_set_vlan_pcp = of131_make_action_set_vlan_pcp,
    .act_set_nw_tos = of131_make_action_set_nw_tos,
    .act_set_tp_udp_dport = of131_make_action_set_tp_udp_dport,
    .act_set_tp_udp_sport = of131_make_action_set_tp_udp_sport,
    .act_set_tp_tcp_dport = of131_make_action_set_tp_tcp_dport,
    .act_set_tp_tcp_sport = of131_make_action_set_tp_tcp_sport,
    .act_set_group = of131_make_action_group,
    .dump_flow = of_dump_flow_generic,
    .dump_acts = of131_dump_actions,    
    .multi_table_support = of131_supports_multi_tables
};

static struct c_ofp_ctors of_unk_ctors = {
     .hello = of131_prep_hello_msg, 
     .echo_req = of_prep_echo,
     .echo_rsp = of_prep_echo_reply,
};


static inline int
c_flow_mod_validate_parms(c_switch_t *sw,
                          struct of_flow_mod_params *fl_parms)
{
    if (!of_switch_table_supported(sw, fl_parms->flow->table_id) || 
        (!fl_parms->app_owner) ||
        (fl_parms->flags & C_FL_ENT_CLONE && fl_parms->flags & C_FL_ENT_LOCAL) ||
        (fl_parms->flags & C_FL_ENT_NOCACHE)) { 
        c_log_err("%s: Invalid flow mod flags", FN);
        return -1;
    }

    return 0;
}

static inline int
of_exm_flow_mod_validate_parms(c_switch_t *sw,
                               struct of_flow_mod_params *fl_parms)
{
    if (!of_switch_table_supported(sw, fl_parms->flow->table_id) ||
        fl_parms->flags & C_FL_ENT_CLONE || fl_parms->flags & C_FL_ENT_NOCACHE || 
        !fl_parms->app_owner) { 
        c_log_err("%s: Invalid flow mod flags", FN);
        return -1;
    }

    return 0;
}

static inline void
c_switch_tx(c_switch_t *sw, struct cbuf *b, bool only_q)
{
    if (c_switch_is_virtual(sw)) {
        free_cbuf(b);
        return;
    } 

    c_thread_tx(&sw->conn, b, only_q);
}

static inline void
c_switch_chain_tx(c_switch_t *sw, struct cbuf **b, size_t nbufs)
{
    int n = 0;
    if (c_switch_is_virtual(sw)) {
        for (n = 0; n < nbufs; n++) {
            free_cbuf(b[n]);
        }
        return;
    } 

    c_thread_chain_tx(&sw->conn, b, nbufs);
}

static void
c_flow_app_ref_free(void *arg UNUSED)
{
    /* Nothing to do */
    return;
}

char *
of_dump_fl_app(c_fl_entry_t *ent)  
{
    c_app_info_t *app;
    GSList *iterator; 
#define FL_APP_BUF_SZ 1024
    char *pbuf = calloc(1, FL_APP_BUF_SZ);
    int len = 0;
    
    len += snprintf(pbuf+len, FL_APP_BUF_SZ-len-1, "Owner: ");
    assert(len < FL_APP_BUF_SZ-1);

    c_rd_lock(&ent->FL_LOCK);
    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app = iterator->data;
        len += snprintf(pbuf+len, FL_APP_BUF_SZ-len-1, "%s ", app->app_name);
        assert(len < FL_APP_BUF_SZ-1);
    }
    c_rd_unlock(&ent->FL_LOCK);

    return pbuf;
}

/* 
 * of_switch_port_valid - 
 *
 * Deprecated function 
 */
bool
of_switch_port_valid(c_switch_t *sw, uint16_t port, uint32_t wc)
{
    if (!(ntohl(wc) & OFPFW_IN_PORT)) {
        return __c_switch_port_valid(sw, port);
    }

    return true;
}

void
c_sw_port_hton(struct c_sw_port *dst, struct c_sw_port *src)
{
    dst->port_no = htonl(src->port_no);
    memcpy(dst->name, src->name, OFP_MAX_PORT_NAME_LEN);
    memcpy(dst->hw_addr, src->hw_addr, OFP_ETH_ALEN);
    dst->config = htonl(src->config);
    dst->state = htonl(src->state);
    dst->of_config = htonl(src->of_config);
    dst->of_state = htonl(src->of_state);

    dst->curr = htonl(src->curr);
    dst->advertised = htonl(src->advertised);
    dst->supported = htonl(src->supported);
    dst->peer = htonl(src->peer);
}

int
of_validate_actions_strict(c_switch_t *sw, void *actions, size_t action_len)
{
    size_t                   parsed_len = 0;
    uint16_t                 act_type;
    struct ofp_action_header *hdr;

    while (action_len) {
        hdr =  (struct ofp_action_header *)actions;
        act_type = ntohs(hdr->type);
        switch (act_type) {
        case OFPAT_OUTPUT:
            {
                struct ofp_action_output *op_act = (void *)hdr;
                if(!ntohs(op_act->port) ||
                   !__c_switch_port_valid(sw, ntohs(op_act->port))) {
                    c_log_err("%s: port 0x%x", FN, ntohs(op_act->port));
                    return -1;
                }
                parsed_len = sizeof(*op_act);
                break;
            }
        case OFPAT_SET_VLAN_VID:
            {
                struct ofp_action_vlan_vid *vid_act = (void *)hdr;    
                parsed_len = sizeof(*vid_act);
                break;
                                 
            } 
        case OFPAT_SET_DL_DST:
        case OFPAT_SET_DL_SRC:
            {
                struct ofp_action_dl_addr *mac_act = (void *)hdr;
                parsed_len = sizeof(*mac_act);
                break;
            }
        case OFPAT_SET_VLAN_PCP:
            {
                struct ofp_action_vlan_pcp *vpcp_act = (void *)hdr;
                parsed_len = sizeof(*vpcp_act);
                break;

            }
        case OFPAT_STRIP_VLAN:
            {
                struct ofp_action_header *strip_vlan_act UNUSED = (void *)hdr;
                parsed_len = sizeof(*strip_vlan_act);
                break;
            }
        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST:
            {
                struct ofp_action_nw_addr *nw_addr_act = (void *)hdr;
                parsed_len = sizeof(*nw_addr_act);
                break;
            }
        default:
            {
                c_log_err("%s:unhandled action %u", FN, act_type);
                return -1;
            }
        }

        action_len -= parsed_len;
        actions = ((uint8_t *)actions + parsed_len);
    }

    return 0;
}



static unsigned int
of_switch_hash_key (const void *p)
{
    c_switch_t *sw = (c_switch_t *) p;

    return (unsigned int)(sw->DPID);
}

static int 
of_switch_hash_cmp (const void *p1, const void *p2)
{
    const c_switch_t *sw1 = (c_switch_t *) p1;
    const c_switch_t *sw2 = (c_switch_t *) p2;

    if (sw1->DPID == sw2->DPID) {
        return 1; /* TRUE */
    } else {
        return 0; /* FALSE */
    }
}

void
c_switch_add(c_switch_t *sw)
{
    struct c_cmn_ctx *cmn_ctx = sw->ctx;
    ctrl_hdl_t *ctrl          = cmn_ctx->c_hdl; 
    c_switch_t *old_sw;

    c_wr_lock(&ctrl->lock);
    if (!ctrl->sw_hash_tbl) {
        ctrl->sw_hash_tbl = g_hash_table_new(of_switch_hash_key, 
                                             of_switch_hash_cmp);
    } else {
        if ((old_sw =__c_switch_get(ctrl, sw->DPID))) {
            c_log_err("%s: switch 0x%llx exists", FN, sw->DPID);
            c_switch_put(old_sw);
            c_wr_unlock(&ctrl->lock);
            return;
        }
    }

    g_hash_table_add(ctrl->sw_hash_tbl, sw);
    if ((sw->alias_id = ipool_get(ctrl->sw_ipool, sw)) < 0) {
        /* Throw a log and continue as we still can continue */
        c_log_err("%s: Cant get alias for switch 0x%llx\n", FN, sw->DPID);
    }

    c_wr_unlock(&ctrl->lock);

}

static int 
c_switch_clone_on_conn(c_switch_t *sw, c_switch_t *old_sw)
{
    if (old_sw == sw) {
        return SW_CLONE_USE;
    }

    if (!(old_sw->switch_state & SW_DEAD)) {
        return SW_CLONE_DENY;
    }

    return SW_CLONE_OLD;
}

void
c_switch_del(c_switch_t *sw)
{
    struct c_cmn_ctx *cmn_ctx = sw->ctx;
    ctrl_hdl_t *ctrl          = cmn_ctx->c_hdl;

    c_conn_destroy(&sw->conn);

    c_wr_lock(&ctrl->lock);
    if (ctrl->sw_hash_tbl) {
       g_hash_table_remove(ctrl->sw_hash_tbl, sw);
    }

    if (ctrl->sw_ipool) {
        if (sw->switch_state & SW_REGISTERED)
            ipool_put(ctrl->sw_ipool, sw->alias_id);
    }
    c_wr_unlock(&ctrl->lock);

    if (sw->switch_state & SW_REGISTERED)
        c_signal_app_event(sw, NULL, C_DP_UNREG, NULL, NULL, false);

    sw->switch_state |= SW_DEAD;
}

void
c_switch_mark_sticky_del(c_switch_t *sw)
{
    sw->last_refresh_time = time(NULL);
    sw->switch_state |= SW_DEAD;
}

static void
c_switch_port_free(void *arg)
{
    free(arg);
}

static void
c_switch_mpart_buf_free(void *arg) 
{
    free_cbuf((struct cbuf *)arg);
}

void *
c_switch_alloc(void *ctx)
{
    c_switch_t *new_switch;

    new_switch = calloc(1, sizeof(c_switch_t));
    assert(new_switch);

    new_switch->switch_state = SW_INIT;
    new_switch->ofp_version = OFP_MUL_SB_VERSION;
    new_switch->ctx = ctx;
    new_switch->last_refresh_time = time(NULL);
    c_rw_lock_init(&new_switch->lock);
    c_rw_lock_init(&new_switch->conn.conn_lock);
    cbuf_list_head_init(&new_switch->conn.tx_q);
    new_switch->ofp_rx_handlers = of_boot_handlers;
    new_switch->ofp_ctors = &of_unk_ctors;
    new_switch->sw_ports =  g_hash_table_new_full(g_int_hash,
                                                  g_int_equal,
                                                  NULL,
                                                  c_switch_port_free);
    new_switch->mpart_bufs =  g_hash_table_new_full(g_int_hash,
                                                  g_int_equal,
                                                  NULL,
                                                  c_switch_mpart_buf_free);
    new_switch->groups =  g_hash_table_new_full(g_int_hash,
                                                g_int_equal,
                                                NULL,
                                                c_switch_group_ent_free);

    return new_switch;
}

c_switch_t *
c_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid)
{
    c_switch_t       key, *sw = NULL; 
    unsigned int     found;

    if (!ctrl->sw_hash_tbl) {
        return NULL;
    }

    key.datapath_id = dpid;

    c_rd_lock(&ctrl->lock);

    found = g_hash_table_lookup_extended(ctrl->sw_hash_tbl, &key, 
                                         NULL, (gpointer*)&sw);
    if (found) {
        atomic_inc(&sw->ref, 1);
    }

    c_rd_unlock(&ctrl->lock);

    return sw;
}

c_switch_t *
c_switch_alias_get(ctrl_hdl_t *ctrl, int alias)
{
    c_switch_t       *sw; 

    c_rd_lock(&ctrl->lock);

    sw = ipool_idx_priv(ctrl->sw_ipool, alias);
    if (sw) {
        atomic_inc(&sw->ref, 1);
    }

    c_rd_unlock(&ctrl->lock);

    return sw;
}

c_switch_t *
__c_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid)
{
    c_switch_t       key, *sw = NULL; 
    unsigned int     found;

    key.datapath_id = dpid;

    if (ctrl->sw_hash_tbl) {
        found = g_hash_table_lookup_extended(ctrl->sw_hash_tbl, &key, 
                                             NULL, (gpointer*)&sw);
        if (found) {
            atomic_inc(&sw->ref, 1);
        }

    }

    return sw;
}

void
c_switch_put(c_switch_t *sw)
{
    if (atomic_read(&sw->ref) == 0){
        c_log_debug("Switch(0x:%llx) FREED", sw->DPID);
        c_switch_flow_tbl_delete(sw);

        if (sw->fp_ops.fp_db_dtor) {
            sw->fp_ops.fp_db_dtor(sw);
        }
        if (sw->sw_ports) g_hash_table_destroy(sw->sw_ports);
        if (sw->mpart_bufs) g_hash_table_destroy(sw->mpart_bufs);
        if (sw->groups) g_hash_table_destroy(sw->groups);
        free(sw);
    } else {
        atomic_dec(&sw->ref, 1);
    }
}

static int 
__c_switch_port_add(c_switch_t *sw, c_sw_port_t *port_desc)
{
    c_sw_port_t *new_port_desc;
    assert(port_desc);
    if (port_desc->port_no && !__c_switch_port_find(sw, port_desc->port_no)) {
        new_port_desc = calloc(1, sizeof(*new_port_desc));
        if (new_port_desc) {
            memcpy(new_port_desc, port_desc, sizeof(*new_port_desc));
            g_hash_table_insert(sw->sw_ports, &new_port_desc->port_no,
                                new_port_desc);
            sw->n_ports++;
            return 0;
        }
    }

    return -1;
}

static void
__c_switch_port_delete(c_switch_t *sw, c_sw_port_t *port_desc)
{
    assert(port_desc);
    if (g_hash_table_remove(sw->sw_ports, &port_desc->port_no)) {
        sw->n_ports--;
    }
}

void
__c_switch_port_traverse_all(c_switch_t *sw, GHFunc iter_fn, void *arg)
{
    if (sw->sw_ports) {
        g_hash_table_foreach(sw->sw_ports,
                             (GHFunc)iter_fn, arg);
    }
}

static void
c_switch_mk_ofp1_0_port_info(void *k UNUSED, void *v, void *arg)
{
    struct ofp_phy_port *port_msg = *(struct ofp_phy_port **)(arg);
    c_sw_port_t *port = v;

    port_msg->port_no = htons(port->port_no);
    port_config_to_ofxlate(&port_msg->config, port->config);
    port_status_to_ofxlate(&port_msg->state, port->state);
    port_msg->curr = htonl(port->curr);
    port_msg->advertised = htonl(port->advertised);
    port_msg->supported = htonl(port->supported);
    port_msg->peer = htonl(port->peer);

    memcpy(port_msg->name, port->name, OFP_MAX_PORT_NAME_LEN);
    memcpy(port_msg->hw_addr, port->hw_addr, OFP_ETH_ALEN);
    port_msg++;

    *(struct ofp_phy_port **)(arg) = port_msg;
}


static struct cbuf *
c_switch_mk_ofp1_0_features(c_switch_t *sw)
{
    struct cbuf *b;
    struct ofp_switch_features *osf;
    struct ofp_phy_port *port_msg;

    c_rd_lock(&sw->lock);
    b = of_prep_msg(sizeof(*osf) + (sw->n_ports * sizeof(struct ofp_phy_port)),
                    OFPT_FEATURES_REPLY, 0);

    osf = (void *)(b->data);
    C_ADD_ALIAS_IN_SWADD(osf, sw->alias_id);
    osf->datapath_id = htonll(sw->DPID);
    osf->n_buffers = htonl(sw->n_buffers);
    osf->n_tables = sw->n_tables;
    osf->capabilities = htonl(sw->capabilities);
    osf->actions = htonl(sw->actions);
    port_msg = osf->ports;
    __c_switch_port_traverse_all(sw, c_switch_mk_ofp1_0_port_info, &port_msg);

    c_rd_unlock(&sw->lock);

    return b;
}

void
of_switch_brief_info(c_switch_t *sw,
                     struct c_ofp_switch_brief *cofp_sb) 
{
    cofp_sb->switch_id.datapath_id = htonll(sw->DPID);
    cofp_sb->n_ports = ntohl(sw->n_ports);
    cofp_sb->state = ntohl(sw->switch_state); 
    strncpy(cofp_sb->conn_str, sw->conn.conn_str, OFP_CONN_DESC_SZ);
    cofp_sb->conn_str[OFP_CONN_DESC_SZ-1] = '\0';
}


void
c_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc iter_fn, void *arg)
{

    c_rd_lock(&hdl->lock);

    if (hdl->sw_hash_tbl) {
        g_hash_table_foreach(hdl->sw_hash_tbl,
                             (GHFunc)iter_fn, arg);
    }

    c_rd_unlock(&hdl->lock);

}

void
__c_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc iter_fn, void *arg)
{

    if (hdl->sw_hash_tbl) {
        g_hash_table_foreach(hdl->sw_hash_tbl,
                             (GHFunc)iter_fn, arg);
    }
}

static unsigned int
c_flow_exm_key(const void *p)
{
    const struct flow *fl = p;

    return hash_words((const uint32_t *) fl,
                      sizeof *fl/sizeof(uint32_t), 1);
}

static int 
c_flow_exm_key_cmp (const void *p1, const void *p2)
{
    struct flow *fl1 = (struct flow *) p1;
    struct flow *fl2 = (struct flow *) p2;

    return !memcmp(fl1, fl2, sizeof(*fl1));
}

static void
c_flow_exm_key_free(void *arg UNUSED)
{
    return;
}

static void
__c_flow_exm_release(void *arg)
{
    c_fl_entry_t *ent = arg;
    c_fl_entry_t *parent = ent->parent;

    if (parent) {
        parent->cloned_list = g_slist_remove(parent->cloned_list, ent);
        c_flow_entry_put(parent);
    }
    c_flow_entry_put(ent);
}

static void
c_flow_exm_release(void *arg, void *u_arg)
{
    c_flow_tbl_t *tbl;
    c_switch_t  *sw = u_arg;
    c_fl_entry_t *ent = arg;

    tbl = &sw->exm_flow_tbl;

    if (tbl->exm_fl_hash_tbl) {
        /* This will lead a call to __c_flow_exm_release() */
        g_hash_table_remove(tbl->exm_fl_hash_tbl, &ent->fl);
    }

    return;
}

static int
c_flow_add_app_owner(c_fl_entry_t *ent, void *new_app)
{
    GSList       *iterator = NULL;
    void         *app;

    c_wr_lock(&ent->FL_LOCK);
    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app = iterator->data;
        if (app == new_app) {
            c_wr_unlock(&ent->FL_LOCK);
            return -EEXIST;
        }
    }

    c_app_ref(new_app); 
    atomic_inc(&ent->app_ref, 1);
    ent->app_owner_list = g_slist_append(ent->app_owner_list, new_app);    
    c_wr_unlock(&ent->FL_LOCK);
 
    return 0;
}

int
__c_flow_find_app_owner(void *key_arg UNUSED, void *ent_arg, void *app)
{
    GSList       *iterator = NULL;
    void         *app_owner;
    c_fl_entry_t *ent = ent_arg;

    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app_owner = iterator->data;
        if (app_owner == app) {
            return 1;
        }
    }

    return 0;
}

/* Ownership needs to be verified before calling */
static int
__c_flow_del_app_owner(c_fl_entry_t *ent, void *app)
{
    ent->app_owner_list = g_slist_remove(ent->app_owner_list, app);    
    atomic_dec(&ent->app_ref, 1);
    c_app_unref(app); 
 
    return 0;
}

static int
c_flow_find_del_app_owner(void *key_arg UNUSED, void *ent_arg, void *app)
{
    c_fl_entry_t *ent = ent_arg;

    c_wr_lock(&ent->FL_LOCK);

    if (__c_flow_find_app_owner(NULL, ent, app) ) {
        __c_flow_del_app_owner(ent, app);

        if (!atomic_read(&ent->app_ref)) {
            c_wr_unlock(&ent->FL_LOCK);
            return 1;
        }

        if (!(ent->FL_FLAGS & C_FL_ENT_LOCAL)) { 
            of_send_flow_del(ent->sw, ent, 0, false, OFPG_ANY);
        }
    }

    c_wr_unlock(&ent->FL_LOCK);

    return 0;
}

static void 
__c_per_switch_del_app_flow_rule(c_switch_t *sw, GSList **list, void *app) 
{
    GSList *tmp, *tmp1, *prev = NULL;
    c_fl_entry_t *ent;
    
    tmp = *list;
    while (tmp) {
        ent = tmp->data;     
        c_wr_lock(&ent->FL_LOCK);
        if (__c_flow_find_app_owner(NULL, ent, app)) { 
            __c_flow_del_app_owner(ent, app);
            tmp1 = tmp;

            if (!atomic_read(&ent->app_ref)) {
                if (prev) {
                    prev->next = tmp->next;
                    tmp = tmp->next;
                } else {
                    *list = tmp->next;
                    tmp = *list;
                }

                if (!ent->parent && !(ent->FL_FLAGS & C_FL_ENT_LOCAL)) { 
                    of_send_flow_del(sw, ent, 0, false, OFPG_ANY);
                }

                c_wr_unlock(&ent->FL_LOCK);
                g_slist_free_1(tmp1);
                c_flow_rule_free(ent, sw);
                continue;
            }
        }

        c_wr_unlock(&ent->FL_LOCK);
        prev = tmp;
        tmp = prev->next;
    }

    return;
}

static void 
__c_per_switch_del_app_flow_exm(c_switch_t *sw, void *app) 
{
    c_flow_tbl_t     *tbl = &sw->exm_flow_tbl;

    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_foreach_remove(tbl->exm_fl_hash_tbl,
                                    c_flow_find_del_app_owner, app);
    }
}

void
__c_per_switch_del_app_flow_owner(c_switch_t *sw, void *app)
{
    int idx = 0;    
    c_flow_tbl_t *tbl;

    for (idx = 0; idx < C_MAX_RULE_FLOW_TBLS; idx++) {
        tbl = &sw->rule_flow_tbls[idx];
        __c_per_switch_del_app_flow_rule(sw, &tbl->rule_fl_tbl, app);
    }

    __c_per_switch_del_app_flow_exm(sw, app);

}

static int  UNUSED
c_flow_exm_add(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
    c_fl_entry_t *new_ent, *ent;
    c_flow_tbl_t  *tbl;
    int ret = 0;
    bool need_hw_sync = FL_EXM_NEED_HW_SYNC(fl_parms);

    if (of_exm_flow_mod_validate_parms(sw, fl_parms)) {
        return -EINVAL;
    }

    new_ent = calloc(1, sizeof(*new_ent));
    assert(new_ent);

    c_rw_lock_init(&new_ent->FL_LOCK);
    new_ent->sw = sw;
    new_ent->FL_ENT_TYPE = C_TBL_EXM;
    new_ent->FL_FLAGS = fl_parms->flags;
    
    new_ent->FL_PRIO = C_FL_PRIO_EXM;
    memcpy(&new_ent->fl, fl_parms->flow, sizeof(struct flow));
    new_ent->action_len = fl_parms->action_len;
    new_ent->actions    = fl_parms->actions;
    atomic_inc(&new_ent->FL_REF, 1);

    tbl = &sw->exm_flow_tbl;

    c_wr_lock(&sw->lock);

    if ((ent = __c_flow_get_exm(sw, fl_parms->flow))) {
        ret = -EEXIST;
        if ((fl_parms->flags & C_FL_ENT_LOCAL) &&
            (ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
           ret = c_flow_add_app_owner(ent, fl_parms->app_owner);
        }

        c_wr_unlock(&sw->lock);
        c_flow_entry_put((void *)ent);
        free(new_ent);
        return ret;
    }

    c_flow_add_app_owner(new_ent, fl_parms->app_owner);

    g_hash_table_insert(tbl->exm_fl_hash_tbl, &new_ent->fl, new_ent);

    c_wr_unlock(&sw->lock);

    if (need_hw_sync) {
        of_send_flow_add(sw, new_ent, fl_parms->buffer_id, true);
    }

    c_flow_entry_put(new_ent);

    return ret;
}

/*
 * Parent should be held before hand 
 */
static c_fl_entry_t * 
c_flow_clone_exm(c_switch_t *sw, struct flow *flow, c_fl_entry_t *parent)
{
    c_fl_entry_t *ent;
    c_flow_tbl_t  *tbl;

    ent = calloc(1, sizeof(*ent));
    assert(ent);

    ent->FL_ENT_TYPE = C_TBL_EXM;
    ent->FL_FLAGS = 0;
    
    ent->FL_ITIMEO = C_FL_IDLE_DFL_TIMEO;
    ent->FL_HTIMEO = C_FL_HARD_DFL_TIMEO;
    ent->FL_PRIO = C_FL_PRIO_EXM;
    memcpy(&ent->fl, flow, sizeof(*flow));
    ent->action_len = parent->action_len;
    ent->actions    = parent->actions;
    ent->parent     = parent;
    atomic_inc(&ent->FL_REF, 1);

    c_wr_lock(&sw->lock);

    tbl = &sw->exm_flow_tbl;

    parent->cloned_list = g_slist_append(parent->cloned_list, ent);
    g_hash_table_insert(tbl->exm_fl_hash_tbl, &ent->fl, ent);

    c_wr_unlock(&sw->lock);

    return ent;
}

static int  UNUSED
c_flow_exm_del(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
    c_flow_tbl_t        *tbl;
    static c_fl_entry_t *fl_ent;

    if (of_exm_flow_mod_validate_parms(sw, fl_parms)) {
        return -EINVAL;   
    }

    tbl = &sw->exm_flow_tbl;

    c_wr_lock(&sw->lock);

    fl_ent = __c_flow_get_exm(sw, fl_parms->flow);
    if (!fl_ent) {
        c_wr_unlock(&sw->lock);
        return -EINVAL;
    }


    c_wr_lock(&fl_ent->FL_LOCK);
    if (__c_flow_find_app_owner(NULL, fl_ent, fl_parms->app_owner)) {
        __c_flow_del_app_owner(fl_ent, fl_parms->app_owner);
        c_wr_unlock(&fl_ent->FL_LOCK);
    } else {
        c_log_err("%s: Ownership mismatch. Flow del failed", FN);
        c_wr_unlock(&fl_ent->FL_LOCK);
        c_wr_unlock(&sw->lock);
        return -EINVAL;
    }

    if (!atomic_read(&fl_ent->app_ref)) {
        g_hash_table_remove(tbl->exm_fl_hash_tbl, fl_parms->flow);
    }

    if (!(fl_ent->FL_FLAGS & C_FL_ENT_LOCAL)) 
        of_send_flow_del(sw, fl_ent, 0, true, OFPG_ANY);


    c_wr_unlock(&sw->lock);

    c_flow_entry_put(fl_ent);

    return 0;
}

static void
c_flow_exm_iter(void *k UNUSED, void *v, void *args)
{
    struct c_iter_args *u_parms = args;
    c_fl_entry_t       *ent = v;
    flow_parser_fn     fn;

    fn = (flow_parser_fn)(u_parms->u_fn);

    fn(u_parms->u_arg, ent); 
}


static void
c_flow_rule_free(void *arg, void *u_arg)
{
    c_fl_entry_t *ent = arg;

    if (ent->cloned_list) {
        g_slist_foreach(ent->cloned_list, (GFunc)c_flow_exm_release, u_arg);
        g_slist_free(ent->cloned_list); 
    }

    c_flow_entry_put(ent);
}

static void
c_flow_rule_iter(void *k, void *args)
{
    struct c_iter_args *u_parms = args;
    c_fl_entry_t       *ent = k;
    flow_parser_fn     fn;

    fn = (flow_parser_fn)(u_parms->u_fn);

    fn(u_parms->u_arg, ent); 
}


static c_fl_entry_t * 
__c_flow_lookup_rule_strict_prio_hint_detail(c_switch_t *sw UNUSED, GSList **list,
                                             struct flow *fl, struct flow *mask, 
                                             uint16_t prio)
{
    GSList *iterator = NULL, *hint = NULL;
    c_fl_entry_t *ent;
    struct flow *ent_fl;
    uint8_t zero_mac[] = { 0, 0, 0, 0, 0, 0};

    for (iterator = *list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        if ((hint && ((c_fl_entry_t *)(hint->data))->FL_PRIO > ent->FL_PRIO) ||
            (prio >= ent->FL_PRIO)) {
            hint = iterator;
        }

        /*if (memcmp(&ent->fl_mask, mask, sizeof(*mask))) continue; */

        ent_fl = &ent->fl;

        if ((fl->nw_dst & mask->nw_dst) == ent_fl->nw_dst &&
            (fl->nw_src & mask->nw_src) == ent_fl->nw_src &&
            (!mask->nw_proto || fl->nw_proto == ent_fl->nw_proto) &&
            (!mask->nw_tos || fl->nw_tos == ent_fl->nw_tos) &&
            (!mask->tp_dst || fl->tp_dst == ent_fl->tp_dst) &&
            (!mask->tp_src || fl->tp_src == ent_fl->tp_src) &&
            (!memcmp(mask->dl_src, zero_mac, 6) || 
             !memcmp(fl->dl_src, ent_fl->dl_src, 6)) &&
            (!memcmp(mask->dl_dst, zero_mac, 6) || 
             !memcmp(fl->dl_dst, ent_fl->dl_dst, 6)) &&
            (!mask->dl_type || fl->dl_type == ent_fl->dl_type) &&
            (!mask->dl_vlan || fl->dl_vlan == ent_fl->dl_vlan) &&
            (!mask->dl_vlan_pcp || fl->dl_vlan_pcp == ent_fl->dl_vlan_pcp) &&
            (!mask->in_port || fl->in_port == ent_fl->in_port) && 
            ent->FL_PRIO == prio)  {
            *list = hint;
            return ent;
        }
    }

    *list = hint;
    return NULL;
}

#if 0
static c_fl_entry_t *
__c_flow_lookup_rule_strict_prio_hint(GSList **list, struct flow *fl, uint32_t wildcards,
                                       uint16_t prio)
{
    GSList *iterator = NULL, *hint = NULL;
    c_fl_entry_t *ent;

    for (iterator = *list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        if ((hint && ((c_fl_entry_t *)(hint->data))->FL_PRIO > ent->FL_PRIO) || 
            (prio >= ent->FL_PRIO)) {
            hint = iterator;
        } 
        if (!memcmp(&ent->fl, fl, sizeof(*fl)) 
            && ent->FL_WILDCARDS == wildcards &&
            ent->FL_PRIO == prio) {
            *list = hint;
            return ent;
        }
    }

    *list = hint;
    return NULL;
}
#else
static c_fl_entry_t *
__c_flow_lookup_rule_strict_prio_hint(GSList **list, struct flow *fl,
                                      struct flow *fl_mask, uint16_t prio)
{
    GSList *iterator = NULL, *hint = NULL;
    c_fl_entry_t *ent;

    for (iterator = *list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        if ((hint && ((c_fl_entry_t *)(hint->data))->FL_PRIO > ent->FL_PRIO) || 
            (prio >= ent->FL_PRIO)) {
            hint = iterator;
        } 
        if (!memcmp(&ent->fl, fl, sizeof(*fl))  &&
            !memcmp(&ent->fl_mask, fl_mask, sizeof(*fl_mask)) &&
            ent->FL_PRIO == prio) {
            *list = hint;
            return ent;
        }
    }

    *list = hint;
    return NULL;
}
#endif

static void UNUSED
of_flow_print_no_match(c_fl_entry_t  *ent, struct flow *fl)
{
    uint32_t      wildcards, ip_wc;
    uint32_t      nw_dst_mask, nw_src_mask;  
    struct flow   *ent_fl;
    char          *miss_str = NULL;

    ent_fl = &ent->fl;
    wildcards = ntohl(ent->FL_WILDCARDS);

    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = ip_wc >= 32 ? 0 :
                                make_inet_mask(32-ip_wc);

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = ip_wc >= 32 ? 0 :
                                make_inet_mask(32-ip_wc);


    /* Move this to generic match for any of version */
    if ((fl->nw_dst & htonl(nw_dst_mask)) != ent_fl->nw_dst) {
        miss_str = "nw dst"; 
        goto out;
    }
    if ((fl->nw_src & htonl(nw_src_mask)) != ent_fl->nw_src) {
        miss_str = "nw src";
        goto out;
    }
    
    if (!(wildcards & OFPFW_NW_PROTO) && fl->nw_proto != ent_fl->nw_proto) {
        miss_str = "nw proto";
        goto out;
    }
    if (!(wildcards & OFPFW_NW_TOS) && fl->nw_tos != ent_fl->nw_tos) {
        miss_str = "nw tos";
        goto out;
    }
    if (!(wildcards & OFPFW_TP_DST) && fl->tp_dst != ent_fl->tp_dst) {
        miss_str = "nw tp dst";
        goto out;
    }
    if (!(wildcards & OFPFW_TP_SRC) && fl->tp_src != ent_fl->tp_src) {
        miss_str = "nw tp src";
        goto out;
    }
    if (!(wildcards & OFPFW_DL_SRC) && memcmp(fl->dl_src, ent_fl->dl_src, 6)) {
        miss_str = "nw dl src";
        goto out;
    } 
    if (!(wildcards & OFPFW_DL_DST) && memcmp(fl->dl_dst, ent_fl->dl_dst, 6)) {
        miss_str = "nw dl dst";
        goto out;

    }
    if (!(wildcards & OFPFW_DL_TYPE) && fl->dl_type != ent_fl->dl_type) {
        miss_str = "nw dl type";
        goto out;

    }
    if (!(wildcards & OFPFW_DL_VLAN) && fl->dl_vlan != ent_fl->dl_vlan) {
        miss_str = "dl_vlan";
        goto out;
    }
    if (!(wildcards & OFPFW_DL_VLAN_PCP) && fl->dl_vlan_pcp != ent_fl->dl_vlan_pcp) { 
        miss_str = "dl_vlan_pcp";
        goto out;
    }    
    if (!(wildcards & OFPFW_IN_PORT) && fl->in_port != ent_fl->in_port)  {
        miss_str = "in port";
        goto out;
    }
out:

    if (miss_str) {
        c_log_debug ("Mismatch @ %s", miss_str); 
    }

    return;
}

static c_fl_entry_t *
__c_flow_lookup_rule(c_switch_t *sw UNUSED, struct flow *fl, c_flow_tbl_t *tbl)
{
    GSList *list, *iterator = NULL;
    c_fl_entry_t  *ent;
    struct flow   *ent_fl, *mask;
    uint8_t       zero_mac[] = { 0, 0, 0, 0, 0, 0};  

    list = tbl->rule_fl_tbl;

    for (iterator = list; iterator; iterator = iterator->next) {
        
        ent = iterator->data;
        ent_fl = &ent->fl;
        mask = &ent->fl_mask;

        if ((fl->nw_dst & mask->nw_dst) == ent_fl->nw_dst &&
            (fl->nw_src & mask->nw_src) == ent_fl->nw_src && 
            (!mask->nw_proto || fl->nw_proto == ent_fl->nw_proto) &&
            (!mask->nw_tos || fl->nw_tos == ent_fl->nw_tos) &&
            (!mask->tp_dst || fl->tp_dst == ent_fl->tp_dst) &&
            (!mask->tp_src || fl->tp_src == ent_fl->tp_src) &&
            (!memcmp(mask->dl_src, zero_mac, 6) || 
             !memcmp(fl->dl_src, ent_fl->dl_src, 6)) &&
            (!memcmp(mask->dl_dst, zero_mac, 0) 
             || !memcmp(fl->dl_dst, ent_fl->dl_dst, 6)) &&
            (!mask->dl_type || fl->dl_type == ent_fl->dl_type) && 
            (!mask->dl_vlan || fl->dl_vlan == ent_fl->dl_vlan) &&
            (!mask->dl_vlan_pcp || fl->dl_vlan_pcp == ent_fl->dl_vlan_pcp) &&
            (!mask->in_port || fl->in_port == ent_fl->in_port))  {
            return ent;
        }

    }

    return NULL;
}

static int
c_flow_rule_add(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
    GSList       *list;
    c_fl_entry_t *new_ent, *ent;
    c_flow_tbl_t *tbl;
    int          ret = 0;
    uint8_t      table_id = fl_parms->flow->table_id;
    bool         hw_sync = FL_NEED_HW_SYNC(fl_parms); 

    new_ent = calloc(1, sizeof(*new_ent));
    assert(new_ent);

    if (c_flow_mod_validate_parms(sw, fl_parms)) {
        return -EINVAL;
    }

    /* FIXME Move allocation and init to common function */
    c_rw_lock_init(&new_ent->FL_LOCK);
    new_ent->sw = sw;
    new_ent->FL_ENT_TYPE = C_TBL_RULE;
    new_ent->FL_FLAGS = fl_parms->flags;
    new_ent->FL_WILDCARDS = fl_parms->wildcards;

    new_ent->FL_PRIO = fl_parms->prio;
    memcpy(&new_ent->fl, fl_parms->flow, sizeof(struct flow));
    memcpy(&new_ent->fl_mask, fl_parms->mask, sizeof(struct flow));
    new_ent->action_len = fl_parms->action_len;
    new_ent->actions    = fl_parms->actions;
    new_ent->cloned_list = NULL;
    new_ent->fl_stats.last_refresh = time(NULL);

    if (hw_sync) {
        atomic_inc(&new_ent->FL_REF, 1); 
    }

    tbl = &sw->rule_flow_tbls[table_id];
    list = tbl->rule_fl_tbl;

    c_wr_lock(&sw->lock);

    /* FIXME : Combine lookup and insert for perf */   
    if ((ent = __c_flow_lookup_rule_strict_prio_hint(&list, fl_parms->flow, 
                                                      fl_parms->mask, 
                                                      fl_parms->prio))) {
        ret = -EEXIST;
        if ((fl_parms->flags & C_FL_ENT_LOCAL) && 
            (ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
           ret = c_flow_add_app_owner(ent, fl_parms->app_owner);
        }

        c_wr_unlock(&sw->lock);
        free(new_ent);
        c_log_debug("%s: Flow already present", FN);
        return ret;
    }

    c_flow_add_app_owner(new_ent, fl_parms->app_owner);

    tbl->rule_fl_tbl = g_slist_insert_before(tbl->rule_fl_tbl, list, new_ent);
    c_wr_unlock(&sw->lock);

    if (hw_sync) {
        of_send_flow_add(sw, new_ent, fl_parms->buffer_id, true);
        c_flow_entry_put(new_ent);
    }

    return ret;
}

#if 0
static bool
__c_flow_rule_del_strict(GSList **list, struct flow **flow, 
                          uint32_t wildcards, uint16_t prio, 
                          void *app)
{
    GSList *tmp, *prev = NULL;
    c_fl_entry_t *ent;
    bool found = false;
    
    tmp = *list;
    while (tmp) {
        ent = tmp->data;     

        c_wr_lock(&ent->FL_LOCK);
        if (!memcmp(&ent->fl, *flow, sizeof(struct flow)) &&
            ent->FL_WILDCARDS == wildcards && 
            ent->FL_PRIO == prio &&
            __c_flow_find_app_owner(NULL, ent, app)) { 
            __c_flow_del_app_owner(ent, app);
            c_wr_unlock(&ent->FL_LOCK);
            *flow = &ent->fl;
            found = TRUE;

            if (atomic_read(&ent->app_ref)) {
                break;
            }

            if (prev)
                prev->next = tmp->next;
            else
                *list = tmp->next;
            g_slist_free_1 (tmp);
            break;
        }
        prev = tmp;
        tmp = prev->next;
        c_wr_unlock(&ent->FL_LOCK);
    }       

    return found;
}
#else
static bool
__c_flow_rule_del_strict(GSList **list, struct flow **flow, 
                         struct flow *mask, uint16_t prio,
                         void *app)
{
    GSList *tmp, *prev = NULL;
    c_fl_entry_t *ent;
    bool found = false;
    
    tmp = *list;
    while (tmp) {
        ent = tmp->data;     

        c_wr_lock(&ent->FL_LOCK);
        if (!memcmp(&ent->fl, *flow, sizeof(struct flow)) &&
            !memcmp(&ent->fl_mask, mask, sizeof(struct flow)) &&
            ent->FL_PRIO == prio &&
            __c_flow_find_app_owner(NULL, ent, app)) { 
            __c_flow_del_app_owner(ent, app);
            c_wr_unlock(&ent->FL_LOCK);
            *flow = &ent->fl;
            found = TRUE;

            if (atomic_read(&ent->app_ref)) {
                break;
            }

            if (prev)
                prev->next = tmp->next;
            else
                *list = tmp->next;
            g_slist_free_1 (tmp);
            break;
        }
        prev = tmp;
        tmp = prev->next;
        c_wr_unlock(&ent->FL_LOCK);
    }       

    return found;
}

#endif

static int
c_flow_rule_del(c_switch_t *sw, struct of_flow_mod_params *fl_parms)
{
    c_fl_entry_t *ent;
    c_flow_tbl_t  *tbl;
    struct flow *flow = fl_parms->flow;

    if (c_flow_mod_validate_parms(sw, fl_parms)) {
        return -1;
    }

    tbl = &sw->rule_flow_tbls[flow->table_id];

    c_wr_lock(&sw->lock);

    if (!__c_flow_rule_del_strict(&tbl->rule_fl_tbl, &flow, 
                                  fl_parms->mask, fl_parms->prio, 
                                  fl_parms->app_owner)) {
        c_log_err("%s: Flow not present", FN);
        c_wr_unlock(&sw->lock);
        return -1;
    }

    /* FIXME : Take this ent and add to a tentative list 
     * If we get negative ack from switch add it back to flow
     * table else free it. 
     */
    ent = container_of(flow, c_fl_entry_t, fl);

    if (!(ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
        of_send_flow_del_strict(sw, ent, 0, OFPG_ANY);
    }

    if (!atomic_read(&ent->app_ref)) {
        c_flow_rule_free(ent, sw);
    }

    c_wr_unlock(&sw->lock);

    return 0;
}

int
c_switch_flow_add(c_switch_t *sw, struct of_flow_mod_params *fl_parms)
{
#ifdef CONFIG_FLOW_EXM
    if (fl_parms->wildcards) {
        return c_flow_rule_add(sw, fl_parms);
    } else {
        return c_flow_exm_add(sw, fl_parms);
    }

    return 0;
#else
    return c_flow_rule_add(sw, fl_parms);
#endif
}

int
c_switch_flow_del(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
#ifdef CONFIG_FLOW_EXM
    if (fl_parms->wildcards) {
        return c_flow_rule_del(sw, fl_parms);
    } else {
        return c_flow_exm_del(sw, fl_parms);
    }

    return 0;
#else
    return c_flow_rule_del(sw, fl_parms);
#endif
}

static void
c_per_flow_resync_hw(void *arg UNUSED, c_fl_entry_t *ent)
{
    if (ent->FL_FLAGS & C_FL_ENT_NOSYNC ||  ent->FL_FLAGS & C_FL_ENT_CLONE ||
        ent->FL_FLAGS & C_FL_ENT_LOCAL ) {
        return;
    }

    of_send_flow_add(ent->sw, ent, 0xffffffff, false);
}

void
c_per_switch_flow_resync_hw(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;

    c_log_info("%s: Resync of-flows switch 0x%llx", FN, sw->DPID);
    c_rd_lock(&sw->lock);
    c_flow_traverse_tbl_all(sw, arg, c_per_flow_resync_hw);
    c_rd_unlock(&sw->lock);
}

void
c_flow_resync_hw_all(ctrl_hdl_t *c_hdl)
{
    c_log_info("%s: ", FN);
    c_switch_traverse_all(c_hdl, c_per_switch_flow_resync_hw,
                          NULL);
}

static void
c_flow_traverse_tbl(c_switch_t *sw, uint8_t tbl_type, uint8_t tbl_idx, 
                    void *u_arg, flow_parser_fn fn)
{
    struct c_iter_args  args;
    c_flow_tbl_t        *tbl;

    if (tbl_type && tbl_idx >= C_MAX_RULE_FLOW_TBLS) {
        c_log_err("%s unknown tbl type", FN);
        return;
    }

    args.u_arg = u_arg;
    args.u_fn  = (void *)fn;

    c_rd_lock(&sw->lock);

    if (!tbl_type) {
        tbl = &sw->exm_flow_tbl;
    } else {
        tbl = &sw->rule_flow_tbls[tbl_idx];
    }

    if (tbl->c_fl_tbl_type == C_TBL_EXM &&
        tbl->exm_fl_hash_tbl) {
        g_hash_table_foreach(tbl->exm_fl_hash_tbl,
                             (GHFunc)c_flow_exm_iter, &args);
    } else if (tbl->c_fl_tbl_type == C_TBL_RULE &&
               tbl->rule_fl_tbl){
        g_slist_foreach(tbl->rule_fl_tbl, 
                        (GFunc)c_flow_rule_iter, &args);
    }

    c_rd_unlock(&sw->lock);
}

void 
c_flow_traverse_tbl_all(c_switch_t *sw, void *u_arg, flow_parser_fn fn)
{
    uint8_t       tbl_idx = 0;

#ifdef CONFIG_FLOW_EXM
    c_flow_traverse_tbl(sw, C_TBL_EXM, tbl_idx, u_arg, fn);
#endif

    for (; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        c_flow_traverse_tbl(sw, C_TBL_RULE, tbl_idx, u_arg, fn);
    }
 
}

static void
c_switch_flow_tbl_create(c_switch_t *sw)
{
    int           tbl_idx = 0;
    c_flow_tbl_t  *tbl;
    
    c_wr_lock(&sw->lock);

    tbl = &sw->exm_flow_tbl;
    if (!tbl->exm_fl_hash_tbl) {
        tbl->exm_fl_hash_tbl =
                    g_hash_table_new_full(c_flow_exm_key,
                                          c_flow_exm_key_cmp,
                                          c_flow_exm_key_free,
                                          __c_flow_exm_release);
        assert(tbl->exm_fl_hash_tbl);
        tbl->c_fl_tbl_type = C_TBL_EXM;
    }

    for (tbl_idx = 0; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        tbl = &sw->rule_flow_tbls[tbl_idx];
        tbl->c_fl_tbl_type = C_TBL_RULE; 
    }
    c_wr_unlock(&sw->lock);
}

void
c_switch_flow_tbl_delete(c_switch_t *sw)
{
    int           tbl_idx = 0;
    c_flow_tbl_t  *tbl;

    c_wr_lock(&sw->lock);

    for (; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        tbl = &sw->rule_flow_tbls[tbl_idx];
        if (tbl->rule_fl_tbl) {
            g_slist_foreach(tbl->rule_fl_tbl, (GFunc)c_flow_rule_free, sw);
            g_slist_free(tbl->rule_fl_tbl);
            tbl->rule_fl_tbl = NULL;
        }
        if (tbl->props) free(tbl->props);
    }

    tbl = &sw->exm_flow_tbl;
    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_destroy(tbl->exm_fl_hash_tbl);
        tbl->exm_fl_hash_tbl = NULL;
    }
    if (tbl->props) free(tbl->props);

    c_wr_unlock(&sw->lock);
}

void
c_switch_flow_tbl_reset(c_switch_t *sw)
{
    int           tbl_idx = 0;
    c_flow_tbl_t  *tbl;

    c_wr_lock(&sw->lock);

    for (; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        tbl = &sw->rule_flow_tbls[tbl_idx];
        if (tbl->rule_fl_tbl) {
            g_slist_foreach(tbl->rule_fl_tbl, (GFunc)c_flow_rule_free, sw);
            g_slist_free(tbl->rule_fl_tbl);
            tbl->rule_fl_tbl = NULL;
        }
    }

    tbl = &sw->exm_flow_tbl;
    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_remove_all(tbl->exm_fl_hash_tbl);
    }

    c_wr_unlock(&sw->lock);
}


static void
c_per_group_iter(void *k UNUSED, void *v, void *args)
{
    struct c_iter_args *u_parms = args;
    c_switch_group_t *grp = v;
    group_parser_fn fn;

    fn = (group_parser_fn)(u_parms->u_fn);

    fn(u_parms->u_arg, grp);
}

void
c_switch_group_traverse_all(c_switch_t *sw, void *u_arg, group_parser_fn fn)
{
    struct c_iter_args args;

    args.u_arg = u_arg;
    args.u_fn = fn;

    c_rd_lock(&sw->lock);
    if (sw->groups) {
        g_hash_table_foreach(sw->groups,
                             (GHFunc)c_per_group_iter, &args);
    }
    c_rd_unlock(&sw->lock);
}

static c_switch_group_t *
c_switch_group_init(c_switch_t *sw, struct of_group_mod_params *gp_parms)
{
    c_switch_group_t *new;
    int act = 0;

    new = calloc(1, sizeof(*new));
    assert(new);

    new->group = gp_parms->group;
    new->type = gp_parms->type;
    new->app_owner = gp_parms->app_owner;
    for (act = 0; act < gp_parms->act_vec_len; act++) {
        new->act_vectors[act] = gp_parms->act_vectors[act];
    }
    new->act_vec_len = gp_parms->act_vec_len;
    c_app_ref(new->app_owner);
    new->sw = sw;

    return new;
}

static void
c_group_act_bucket_free(void *arg)
{
    struct of_act_vec_elem *elem = arg;

    if (elem->actions) free(elem->actions);
    free(elem);
}

static void
c_switch_group_ent_free(void *arg) 
{
    c_switch_group_t *group = arg;
    int acts = 0;

    c_app_put(group->app_owner);
    for(; acts < group->act_vec_len; acts++) {
        c_group_act_bucket_free(group->act_vectors[acts]);
    }
    free(group);
}

static int
c_group_owner_match(void *k_arg UNUSED, void *v_arg, void *u_arg)
{
    c_switch_group_t *group = v_arg;

    if (group->app_owner == u_arg) {
        return 1;
    }
    
    return 0;
}

void
__c_per_switch_del_group_with_owner(c_switch_t *sw, void *app)
{
    g_hash_table_foreach_remove(sw->groups, c_group_owner_match, app);
}

int
c_switch_group_add(c_switch_t *sw, struct of_group_mod_params *gp_parms) 
{
    c_switch_group_t *group;
    struct cbuf *b;

    if (!C_SWITCH_SUPPORTS_GROUP(sw)) {
        return -1;
    }

    if (!sw->ofp_ctors->group_validate(true, gp_parms->group, gp_parms->type,
                                       gp_parms->act_vectors,
                                       gp_parms->act_vec_len)) {
        c_log_err("%s: invalid-args", FN);
        return -1;
    }

    c_wr_lock(&sw->lock);
    if (g_hash_table_lookup(sw->groups, &gp_parms->group)) {
        c_log_err("%s:Switch 0x%llx grp %u existss",
                  FN, sw->DPID, gp_parms->group); 
        c_wr_unlock(&sw->lock);
        return -1;
    }

    group = c_switch_group_init(sw, gp_parms);
    g_hash_table_insert(sw->groups, &group->group, group);
    c_wr_unlock(&sw->lock);

    b = sw->ofp_ctors->group_add(gp_parms->group, gp_parms->type,
                                 gp_parms->act_vectors,
                                 gp_parms->act_vec_len);
    c_switch_tx(sw, b, false);

    return 0;
}

int
c_switch_group_del(c_switch_t *sw, struct of_group_mod_params *gp_parms) 
{
    c_switch_group_t *group;
    struct cbuf *b;

     if (!C_SWITCH_SUPPORTS_GROUP(sw)) {
        return -1;
    }

    if (!sw->ofp_ctors->group_validate(false, gp_parms->group,
                                       gp_parms->type,
                                       gp_parms->act_vectors,
                                       gp_parms->act_vec_len)) {
        c_log_err("%s: Invalid args", FN);
        return -1;
    }

    c_wr_lock(&sw->lock);
    if (!(group = g_hash_table_lookup(sw->groups, &gp_parms->group))) {
        c_log_err("%s:Switch 0x%llx has no grp %u",
                  FN, sw->DPID, gp_parms->group); 
        c_wr_unlock(&sw->lock);
        return -1;
    }

    if (group->app_owner == gp_parms->app_owner) {
        g_hash_table_remove(sw->groups, &gp_parms->group);

        if (sw->ofp_ctors && sw->ofp_ctors->group_del) {
            b = sw->ofp_ctors->group_del(gp_parms->group);
            c_switch_tx(sw, b, false);
        }
    }

    c_wr_unlock(&sw->lock);
    return 0;
}

static inline void
of_prep_msg_on_stack(struct cbuf *b, size_t len, uint8_t type, uint32_t xid)
{
    struct ofp_header *h;

    h = (void *)(b->data);

    h->version = OFP_VERSION;
    h->type = type;
    h->length = htons(len);
    h->xid = xid;

    /* NOTE - No memset of extra data for performance */
    return;
}

void
of_send_features_request(c_switch_t *sw)
{
    if (!sw->ofp_ctors->features) {
        return;
    }
    c_switch_tx(sw, sw->ofp_ctors->features(), true);
}

void
__of_send_features_request(c_switch_t *sw)
{
    of_send_features_request(sw);
    c_thread_sg_tx_sync(&sw->conn);
}

void
of_send_set_config(c_switch_t *sw, uint16_t flags, uint16_t miss_len)
{
    struct cbuf *b;
    
    if (sw->ofp_ctors->set_config) {
        b = sw->ofp_ctors->set_config(flags, miss_len);
        c_switch_tx(sw, b, false);
    }
}

void
__of_send_set_config(c_switch_t *sw, uint16_t flags, uint16_t miss_len)
{
    of_send_set_config(sw, flags, miss_len);
}

void
of_send_echo_request(c_switch_t *sw)
{
    struct cbuf *b = sw->ofp_ctors->echo_req();
    c_switch_tx(sw, b, false);
}

void
__of_send_echo_request(c_switch_t *sw)
{
    of_send_echo_request(sw);
}

void
of_send_echo_reply(c_switch_t *sw, uint32_t xid)
{
    struct cbuf *b = sw->ofp_ctors->echo_rsp(xid);
    c_switch_tx(sw, b, false);
}

void
__of_send_echo_reply(c_switch_t *sw, uint32_t xid)
{
    of_send_echo_reply(sw, xid);
}

void
of_send_hello(c_switch_t *sw)
{
    struct cbuf *b = sw->ofp_ctors->hello();
    c_switch_tx(sw, b, false);
}

void __fastpath
of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms)
{
    struct cbuf *b = sw->ofp_ctors->pkt_out(parms);
    c_switch_tx(sw, b, true);
} 

void __fastpath
of_send_pkt_out_inline(void *arg, struct of_pkt_out_params *parms)
{
    struct cbuf     b;
    size_t          tot_len;
    uint8_t         data[C_INLINE_BUF_SZ];
    struct ofp_packet_out *out;
    c_switch_t *sw = arg;

    tot_len = sizeof(struct ofp_packet_out) + parms->action_len + parms->data_len;
    if (unlikely(tot_len > C_INLINE_BUF_SZ)) return of_send_pkt_out(sw, parms);

    cbuf_init_on_stack(&b, data, tot_len);
    of_prep_msg_on_stack(&b, tot_len, OFPT_PACKET_OUT, 
                         (unsigned long)parms->data);

    out = (void *)b.data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htons(parms->in_port);
    out->actions_len = htons(parms->action_len);
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy((uint8_t *)out->actions + parms->action_len, 
            parms->data, parms->data_len);

    c_switch_tx(sw, &b, false);
} 

void __fastpath
__of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms)
{
    of_send_pkt_out(sw, parms);
    c_thread_sg_tx_sync(&sw->conn);
}

static void
of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, uint32_t buffer_id,
                 bool ha_sync UNUSED)
{
    struct cbuf *b = sw->ofp_ctors->flow_add(&ent->fl, &ent->fl_mask, 
                                             buffer_id, ent->actions, 
                                             ent->action_len, ent->FL_ITIMEO,
                                             ent->FL_HTIMEO, ent->FL_PRIO); 
    c_switch_tx(sw, b, true);
} 

static void UNUSED
__of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, uint32_t buffer_id,
                   bool ha_sync)
{
    of_send_flow_add(sw, ent, buffer_id, ha_sync);
    c_thread_sg_tx_sync(&sw->conn);
}

int __fastpath
of_send_flow_add_direct(c_switch_t *sw, struct flow *fl, struct flow *mask, 
                        uint32_t buffer_id, void *actions, size_t action_len,
                        uint16_t itimeo, uint16_t htimeo, uint16_t prio)
{
    struct cbuf *b = sw->ofp_ctors->flow_add(fl, mask,
                                             buffer_id, actions, 
                                             action_len, itimeo, htimeo,
                                             prio);
    c_switch_tx(sw, b, true);
    return 0;
} 

int __fastpath
__of_send_flow_add_direct(c_switch_t *sw, struct flow *fl, struct flow *mask, 
                          uint32_t buffer_id, void *actions, size_t action_len,
                          uint16_t itimeo, uint16_t htimeo, uint16_t prio)
{
    int ret;
    ret = of_send_flow_add_direct(sw, fl, mask, buffer_id,
                                  actions, action_len,
                                  itimeo, htimeo, prio);
    c_thread_sg_tx_sync(&sw->conn);
    return ret;
}

static void
of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent, uint16_t oport,
                 bool strict, uint32_t group)
{
    struct cbuf *b = sw->ofp_ctors->flow_del(&ent->fl, &ent->fl_mask,
                                             oport, strict,
                                             ent->FL_PRIO, group);
    c_switch_tx(sw, b, true);
}

static void
of_send_flow_del_strict(c_switch_t *sw, c_fl_entry_t *ent, uint16_t oport, 
                        uint32_t group)
{
    struct cbuf *b = sw->ofp_ctors->flow_del(&ent->fl, &ent->fl_mask, 
                                             oport, true, ent->FL_PRIO,
                                             group);
    c_switch_tx(sw, b, true);
}

static void UNUSED
__of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent, uint16_t oport,
                   bool strict, uint32_t group)
{
    of_send_flow_del(sw, ent, oport, strict, group);
    c_thread_sg_tx_sync(&sw->conn);
}

int
of_send_flow_del_direct(c_switch_t *sw, struct flow *fl, struct flow *mask,
                         uint16_t oport, bool strict, uint16_t prio, 
                         uint32_t group)
{
    struct cbuf *b = sw->ofp_ctors->flow_del(fl, mask, 
                                             oport, strict,
                                             prio, group);
    c_switch_tx(sw, b, true);
    return 0;
}

int
__of_send_flow_del_direct(c_switch_t *sw, struct flow *fl, struct flow *mask,
                         uint16_t oport, bool strict, uint16_t prio,
                         uint32_t group)
{
    of_send_flow_del_direct(sw, fl, mask, oport, strict, prio, group);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

int
of_send_flow_stat_req(c_switch_t *sw, const struct flow *flow, 
                      const struct flow *mask, uint32_t oport,
                      uint32_t group)
{
    struct cbuf *b;

    if (sw->ofp_ctors->flow_stat_req) {
        b = sw->ofp_ctors->flow_stat_req(flow, mask, oport, group);
        c_switch_tx(sw, b, true);
    } else {
        return -1;
    } 

    return 0;
}

int
__of_send_flow_stat_req(c_switch_t *sw, const struct flow *flow, 
                        const struct flow *mask, uint32_t oport,
                        uint32_t group)
{
    of_send_flow_stat_req(sw, flow, mask, oport, group);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

void
__of_send_clear_all_groups(c_switch_t *sw)
{
    struct cbuf *b;

    if (sw->ofp_ctors && sw->ofp_ctors->group_del) {
        b = sw->ofp_ctors->group_del(OFPG_ALL);
        c_switch_tx(sw, b, false);
    }
}

bool
of_switch_table_supported(c_switch_t *sw, uint8_t table)
{
    
    if (table < C_MAX_RULE_FLOW_TBLS && 
        sw->ofp_ctors && sw->ofp_ctors->multi_table_support &&
        sw->ofp_ctors->multi_table_support(sw->n_tables, table)) {
        return true;
    } else {
        if (table == C_TBL_HW_IDX_DFL) return true;
        return false;
    }
}

/* 
 * __c_switch_port_update -
 * 
 * Update a switch port attributes
 */ 
static void 
__c_switch_port_update(c_switch_t *sw, c_sw_port_t *port_desc, 
                       uint8_t  chg_reason,
                       struct c_port_cfg_state_mask *chg_mask)
{
    c_sw_port_t    *port = NULL;
    uint32_t        port_no;

    port_no = port_desc->port_no;

    switch (chg_reason) {
    case OFPPR_DELETE:
        //c_log_err("%s: %llx port(%u) delete", FN, sw->DPID, port_no);
        __c_switch_port_delete(sw, port_desc);
        break;
    case OFPPR_ADD:
        //c_log_err("%s: %llx port(%u) add", FN, sw->DPID, port_no);
        if (!__c_switch_port_add(sw, port_desc) && chg_mask) {
            chg_mask->config_mask = port_desc->config;
            chg_mask->state_mask = port_desc->state;
        }
        break;
    case OFPPR_MODIFY:
        //c_log_err("%s: %llx port(%u) mod", FN, sw->DPID, port_no);
        if ((port = __c_switch_port_find(sw, port_desc->port_no))) {
            memcpy(port, port_desc, sizeof(c_sw_port_t));
            if (chg_mask) {
                chg_mask->config_mask = port_desc->config ^ port_desc->config;
                chg_mask->state_mask = port_desc->state ^ port_desc->state;
            }
        }
        break;
    default:
        c_log_err("%s: Unknown port(%u) change reason(%u)", FN, port_no, chg_reason);
        return;
    }

    return;
}

static void
port_status_to_cxlate(uint32_t *status, uint32_t of_port_status)
{
    *status = 0;
    if (of_port_status & OFPPS_LINK_DOWN) {
        *status |= C_MLPS_DOWN;
    }
}

static void
port_config_to_cxlate(uint32_t *config, uint32_t of_port_config)
{
    *config= 0;
    if (of_port_config & OFPPC_PORT_DOWN) {
        *config |= C_MLPC_DOWN;
    }
}

static void
port_status_to_ofxlate(uint32_t *of_port_status, uint32_t status)
{
    *of_port_status = 0;
    if (status & C_MLPS_DOWN) {
        *of_port_status |= OFPPS_LINK_DOWN;   
    }

    *of_port_status = htonl(*of_port_status);
}

static void
port_config_to_ofxlate(uint32_t *of_port_config, uint32_t config)
{
    *of_port_config= 0;
    if (config & C_MLPC_DOWN) {
        *of_port_config |= OFPPC_PORT_DOWN;
    }
    
    *of_port_config = htonl(*of_port_config);
}

static c_sw_port_t * 
of10_process_phy_port(c_switch_t *sw UNUSED, void *opp_)
{
    const struct ofp_phy_port   *opp;
    c_sw_port_t                *port_desc;

    opp     = opp_;
    port_desc = calloc(sizeof(c_sw_port_t), 1);
    assert(port_desc);

    port_desc->port_no = ntohs(opp->port_no);
    port_config_to_cxlate(&port_desc->config, ntohl(opp->config));
    port_status_to_cxlate(&port_desc->state, ntohl(opp->state));
    port_desc->curr = ntohl(opp->curr);
    port_desc->advertised = ntohl(opp->advertised);
    port_desc->supported = ntohl(opp->supported);
    port_desc->peer      = ntohl(opp->peer);
    port_desc->of_config = ntohl(opp->config);
    port_desc->of_state  = ntohl(opp->state);

    memcpy(port_desc->name, opp->name, OFP_MAX_PORT_NAME_LEN);
    port_desc->name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
    memcpy(port_desc->hw_addr, opp->hw_addr, OFP_ETH_ALEN);

    return port_desc;
}

static void
of10_recv_port_status(c_switch_t *sw, struct cbuf *b)
{
    struct c_port_chg_mdata mdata;
    struct c_port_cfg_state_mask chg_mask = { 0, 0 };
    struct ofp_port_status *ops = (void *)(b->data);
    c_sw_port_t *phy_port_desc = NULL;

    phy_port_desc = sw->ofp_priv_procs->xlate_port_desc(sw, &ops->desc);
    assert(phy_port_desc);

    c_wr_lock(&sw->lock);
    __c_switch_port_update(sw, phy_port_desc, ops->reason, &chg_mask);
    c_wr_unlock(&sw->lock);

    mdata.reason = ops->reason;
    mdata.chg_mask = &chg_mask;
    mdata.port_desc = phy_port_desc;
    c_signal_app_event(sw, b, C_PORT_CHANGE, NULL, &mdata, false);

    free(phy_port_desc);
}

static bool 
c_switch_features_check(c_switch_t *sw, uint64_t dpid)
{
    c_switch_t *old_sw = NULL;

    old_sw = c_switch_get(sw->c_hdl, dpid);
    if (old_sw) {
        switch (c_switch_clone_on_conn(sw, old_sw)) {
        case SW_CLONE_USE: 
            c_log_debug("%s: Use new switch conn", FN);
            c_switch_put(old_sw);
            return true;
        case SW_CLONE_DENY:
            c_log_debug("%s: Denied new switch conn", FN);
            sw->conn.dead = true; /* Indication to close the conn on switch delete */
            c_switch_mark_sticky_del(sw); /* eventually switch should go */
            c_switch_put(old_sw);
            return false;
        case SW_CLONE_OLD:
            c_log_debug("%s: Clone old switch conn", FN);
            c_conn_events_del(&sw->conn);
            c_switch_mark_sticky_del(sw);
            old_sw->reinit_fd = sw->conn.fd;
            old_sw->switch_state |= c_switch_is_virtual(sw) ?
                                   SW_REINIT_VIRT:
                                   SW_REINIT;
            old_sw->switch_state &= ~SW_DEAD;
            c_switch_put(old_sw);
            return false;
        default:
            c_log_err("%s: Unknown clone state", FN);
            c_switch_put(old_sw);
            return false;
        }
    }
    return true;
}

static void
c_init_switch_features(c_switch_t *sw, uint64_t datapath_id, uint8_t ofp_version,
                       uint8_t n_tables, uint32_t n_bufs, uint32_t ofp_acts,
                       uint32_t cap)
{
    sw->datapath_id = datapath_id;
    sw->version     = ofp_version;
    sw->n_buffers   = n_bufs;
    sw->n_ports     = 0; /* Will be updated separately */
    sw->n_tables    = n_tables;
    sw->actions     = ofp_acts;
    sw->capabilities = cap;
}

static void
c_register_switch(c_switch_t *sw, struct cbuf *reg_pkt)
{
    struct flow  flow;
    struct flow  mask;

    memset(&flow, 0, sizeof(flow));
    of_mask_set_dc_all(&mask);
    if (!(sw->switch_state & SW_REGISTERED)) {
        c_switch_flow_tbl_create(sw);
        c_switch_add(sw);
        sw->switch_state |= SW_REGISTERED;
        sw->last_sample_time = time(NULL);
        if (sw->version == OFP_VERSION) {
            sw->ofp_rx_handlers = of_handlers;
        } else if (sw->version == OFP_VERSION_131) {
            sw->ofp_rx_handlers = of131_handlers;
        } else {
            NOT_REACHED();
        }
        sw->fp_ops.fp_fwd = of_dfl_fwd;
        sw->fp_ops.fp_port_status = of_dfl_port_status;

        __of_send_flow_del_direct(sw, &flow, &mask, 0, 
                                  false, C_FL_PRIO_DFL, OFPG_ANY);
        __of_send_clear_all_groups(sw);
        __of_send_set_config(sw, 0x3, OF_MAX_MISS_SEND_LEN);
        c_signal_app_event(sw, reg_pkt, C_DP_REG, NULL, NULL, false);
    }
}

static void
of10_recv_features_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_switch_features  *osf = (void *)(b->data);
    size_t                       n_ports, i;

    if (!c_switch_features_check(sw, ntohll(osf->datapath_id))) {
        return;
    }

    n_ports = ((ntohs(osf->header.length)
                - offsetof(struct ofp_switch_features, ports))
            / sizeof *osf->ports);

    c_init_switch_features(sw, ntohll(osf->datapath_id), osf->header.version,
                           osf->n_tables, ntohl(osf->n_buffers), ntohl(osf->actions),
                           ntohl(osf->capabilities));                           

    for (i = 0; i < n_ports; i++) {
        c_sw_port_t *port_info = NULL;
        assert(sw->ofp_priv_procs->xlate_port_desc);
        port_info = sw->ofp_priv_procs->xlate_port_desc(sw, &osf->ports[i]);
        __c_switch_port_update(sw, port_info, OFPPR_ADD, NULL);
        free(port_info);
    }

    c_register_switch(sw, b);
}

int __fastpath
of_flow_extract(uint8_t *pkt, struct flow *flow, 
                uint16_t in_port, size_t pkt_len,
                bool only_l2)
{
    struct eth_header *eth;
    int    retval = 0;
    size_t rem_len = pkt_len;

    memset(flow, 0, sizeof *flow);
    flow->dl_vlan = 0;  //htons(OFP_VLAN_NONE);
    flow->in_port = htonl(in_port);

    if (unlikely(rem_len < sizeof(*eth))) {
        return -1;
    }

    eth = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
    rem_len -= sizeof(*eth);
    if (likely(ntohs(eth->eth_type) >= OFP_DL_TYPE_ETH2_CUTOFF)) {
        /* This is an Ethernet II frame */
        flow->dl_type = eth->eth_type;
    } else {
        /* This is an 802.2 frame */
        if (!c_rlim(&crl))
            c_log_err("802.2 recvd. Not handled");
        return -1;
    }

    /* Check for a VLAN tag */
    if (unlikely(flow->dl_type == htons(ETH_TYPE_VLAN))) {
        struct vlan_header *vh;
        if (rem_len < sizeof(*vh)) {
            return -1;
        }
        vh =  OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
        rem_len -= sizeof(*vh);
        flow->dl_type = vh->vlan_next_type;
        flow->dl_vlan = vh->vlan_tci & htons(VLAN_VID_MASK);
        flow->dl_vlan_pcp = (uint8_t)((ntohs(vh->vlan_tci)  >>  
                                        VLAN_PCP_SHIFT) & VLAN_PCP_BITMASK);
    }

    memcpy(flow->dl_dst, eth->eth_dst, 2*ETH_ADDR_LEN);

    if (likely(only_l2)) {
        return 0;
    }

    if (likely(flow->dl_type == htons(ETH_TYPE_IP))) {
        const struct ip_header *nh;

        if (rem_len < sizeof(*nh)) {
            return -1;
        }
        nh = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
        rem_len -= sizeof(*nh);

        flow->nw_tos = nh->ip_tos & 0xfc;
        flow->nw_proto = nh->ip_proto;
        flow->nw_src = nh->ip_src;
        flow->nw_dst = nh->ip_dst;
        if (likely(!IP_IS_FRAGMENT(nh->ip_frag_off))) {
            if (flow->nw_proto == IP_TYPE_TCP) {
                const struct tcp_header *tcp;
                if (rem_len < sizeof(*tcp)) {
                    flow->nw_proto = 0;
                    return 0;
                }
                tcp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);;
                rem_len -= sizeof(*tcp);

                flow->tp_src = tcp->tcp_src;
                flow->tp_dst = tcp->tcp_dst;
            } else if (flow->nw_proto == IP_TYPE_UDP) {
                const struct udp_header *udp;
                if (rem_len < sizeof(*udp)) {
                    flow->nw_proto = 0;
                    return 0;
                }
                udp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
                rem_len -= sizeof(*udp);

                flow->tp_src = udp->udp_src;
                flow->tp_dst = udp->udp_dst;
            } else if (flow->nw_proto == IP_TYPE_ICMP) {
                const struct icmp_header *icmp;
                if (rem_len < sizeof(*icmp)) {
                    flow->nw_proto = 0;
                    return 0;
                }
                icmp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
                rem_len -= sizeof(*icmp);

                flow->tp_src = htons(icmp->icmp_type);
                flow->tp_dst = htons(icmp->icmp_code);
            }
       } else {
                retval = 1;
       }
    } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
        const struct arp_eth_header *arp;
        if (rem_len < sizeof(*arp)) {
            return -1;
        }
        arp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len); 
        rem_len -= sizeof(*arp);

        if (arp->ar_pro == htons(ARP_PRO_IP) && 
            arp->ar_pln == IP_ADDR_LEN) {
                flow->nw_src = arp->ar_spa;
                flow->nw_dst = arp->ar_tpa;
        }
        flow->nw_proto = ntohs(arp->ar_op) && 0xff;
    }
    return retval;
}

static c_fl_entry_t * UNUSED 
c_flow_get_exm(c_switch_t *sw, struct flow *fl)
{
    c_flow_tbl_t     *tbl = &sw->exm_flow_tbl;
    c_fl_entry_t     *ent = NULL;
    unsigned int     found;

    c_rd_lock(&sw->lock);

    found = g_hash_table_lookup_extended(tbl->exm_fl_hash_tbl, fl,
                                         NULL, (gpointer*)&ent);
    if (found) {
        atomic_inc(&ent->FL_REF, 1);
    }

    c_rd_unlock(&sw->lock);

    return ent;

}

static c_fl_entry_t *
__c_flow_get_exm(c_switch_t *sw, struct flow *fl)
{
    c_flow_tbl_t     *tbl = &sw->exm_flow_tbl;
    c_fl_entry_t     *ent = NULL;
    unsigned int     found;

    found = g_hash_table_lookup_extended(tbl->exm_fl_hash_tbl, fl,
                                         NULL, (gpointer*)&ent);
    if (found) {
        atomic_inc(&ent->FL_REF, 1);
    }

    return ent;
}

static inline c_fl_entry_t *
c_do_flow_lookup_slow(c_switch_t *sw, struct flow *fl)
{
    c_flow_tbl_t     *tbl;
    c_fl_entry_t     *ent = NULL;
    
    c_rd_lock(&sw->lock);
    tbl = &sw->rule_flow_tbls[fl->table_id];
    if (tbl && (ent = __c_flow_lookup_rule(sw, fl, tbl))) {
        atomic_inc(&ent->FL_REF, 1);
        c_rd_unlock(&sw->lock);
        return ent;
    }
    c_rd_unlock(&sw->lock);

    return NULL;
}

static c_fl_entry_t *
c_do_rule_lookup_with_detail(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t prio)
{
    c_flow_tbl_t     *tbl;
    c_fl_entry_t     *ent = NULL;
    GSList           *list = NULL;

    c_rd_lock(&sw->lock);
    tbl = &sw->rule_flow_tbls[fl->table_id];
    list = tbl->rule_fl_tbl;
    if (tbl &&
        (ent = __c_flow_lookup_rule_strict_prio_hint_detail
                       (sw, &list, fl, mask, prio))) {
       atomic_inc(&ent->FL_REF, 1);
       c_rd_unlock(&sw->lock);
       return ent;
    }
    c_rd_unlock(&sw->lock);

    return NULL;
}

static inline c_fl_entry_t *
c_do_flow_lookup(c_switch_t *sw, struct flow *fl)
{

#ifdef CONFIG_FLOW_EXM
    c_fl_entry_t *ent = NULL;

    if ((ent = c_flow_get_exm(sw, fl))) {
        return ent;
    }
#endif
    return c_do_flow_lookup_slow(sw, fl);
}

static inline c_fl_entry_t *
c_do_flow_lookup_with_detail(c_switch_t *sw, struct flow *fl,
                             struct flow *mask, uint16_t prio)
{
#ifdef CONFIG_FLOW_EXM
    c_fl_entry_t *ent = NULL;

    if ((ent = c_flow_get_exm(sw, fl))) {
        return ent;
    }
#endif
    return c_do_rule_lookup_with_detail(sw, fl, mask, prio);
}

void
c_flow_entry_put(c_fl_entry_t *ent)
{
    if (atomic_read(&ent->FL_REF) == 0) {
        if (ent->actions &&
            !(ent->FL_FLAGS & C_FL_ENT_CLONE))  {
            /* Cloned entry refs parent action list */
            free(ent->actions);
        }

        if (ent->app_owner_list) {
            g_slist_free_full(ent->app_owner_list, c_flow_app_ref_free);
            ent->app_owner_list = NULL;
        }

        free(ent);
        //c_log_debug("%s: Freed", FN);
    } else {
        atomic_dec(&ent->FL_REF, 1);
        //c_log_debug("%s: Ref dec", FN);
    }
}


static inline void
c_mcast_app_packet_in(c_switch_t *sw, struct cbuf *b,
                      c_fl_entry_t *fl_ent,
                      struct c_pkt_in_mdata *mdata)
{
    void    *app;
    GSList  *iterator;

    c_sw_hier_rdlock(sw);

    c_rd_lock(&fl_ent->FL_LOCK);
    for (iterator = fl_ent->app_owner_list;
         iterator;
         iterator = iterator->next) {
        app = iterator->data;
        c_signal_app_event(sw, b, C_PACKET_IN, app, mdata, true);
    }

    c_rd_unlock(&fl_ent->FL_LOCK);

    c_sw_hier_unlock(sw);
}

int 
of_dfl_fwd(struct c_switch *sw, struct cbuf *b, void *data, size_t pkt_len,
           struct c_pkt_in_mdata *mdata, uint32_t in_port)
{
    struct of_pkt_out_params parms;
    c_fl_entry_t  *fl_ent;
    struct ofp_packet_in *opi = (void *)(b->data);
    struct flow *fl = mdata->fl; 

    if(!(fl_ent = c_do_flow_lookup(sw, fl))) {
        //c_log_debug("Flow lookup fail");
        return 0;
    }

    if (fl_ent->FL_ENT_TYPE != C_TBL_EXM &&
        fl_ent->FL_FLAGS & C_FL_ENT_CLONE) {
        fl_ent = c_flow_clone_exm(sw, fl, fl_ent);
    }

    if (fl_ent->FL_FLAGS & C_FL_ENT_LOCAL) {
        c_mcast_app_packet_in(sw, b, fl_ent, mdata);

        c_flow_entry_put(fl_ent);
        return 0;
    }

    of_send_flow_add(sw, fl_ent, ntohl(opi->buffer_id), true);

    parms.data       = 0;
    parms.data_len   = 0;
    parms.buffer_id  = ntohl(opi->buffer_id);
    parms.in_port    = in_port;
    parms.action_len = fl_ent->action_len;
    parms.action_list = fl_ent->actions;
    parms.data_len = pkt_len;
    parms.data = data;

    of_send_pkt_out(sw, &parms);
    c_flow_entry_put(fl_ent);

    return 0;
}

int
of_dfl_port_status(c_switch_t *sw UNUSED, uint32_t cfg UNUSED,
                   uint32_t state UNUSED)
{
    /* Nothing to do for now */
    return 0;
}

static void __fastpath
of10_recv_packet_in(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_packet_in *opi __aligned = (void *)(b->data);
    size_t pkt_ofs, pkt_len;
    struct flow fl;
    struct c_pkt_in_mdata mdata;
    uint16_t in_port = ntohs(opi->in_port);
    bool only_l2 = sw->fp_ops.fp_fwd == c_l2_lrn_fwd ? true : false;

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;

    if(!sw->fp_ops.fp_fwd ||
        of_flow_extract(opi->data, &fl, in_port, pkt_len, only_l2) < 0) {
        return;
    }

    mdata.fl = &fl;
    mdata.pkt_ofs = pkt_ofs;
    mdata.pkt_len = pkt_len;
    mdata.buffer_id = ntohl(opi->buffer_id);

    sw->fp_ops.fp_fwd(sw, b, opi->data, pkt_len, &mdata, in_port);

    return;
}

static void
of_recv_hello(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_header *h = (void *)(b->data);

    if (sw->switch_state & SW_OFP_NEGOTIATED)
        return;

    if (h->version == OFP_VERSION) {
        sw->ofp_rx_handlers = of_init_handlers;
        sw->ofp_ctors = &of10_ctors;
        sw->ofp_priv_procs = &ofp_priv_procs;
        sw->switch_state |= SW_OFP_NEGOTIATED;
        of_send_features_request(sw);
    } else if (h->version == OFP_VERSION_131) {
        sw->ofp_rx_handlers = of131_init_handlers; 
        sw->ofp_ctors = &of131_ctors;
        sw->ofp_priv_procs = &ofp131_priv_procs;
        sw->switch_state |= SW_OFP_NEGOTIATED;
        of_send_features_request(sw);
    } else {
        c_log_err("%s: OFP version unsupported %u", FN, h->version);
        of_send_hello(sw);
    }
}

static void
of10_recv_echo_request(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_header *h = (void *)(b->data);

    return of_send_echo_reply(sw, h->xid);
}

static void
of10_recv_echo_reply(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    /* Nothing to do as timestamp is already updated */
}

static void
of_recv_init_echo_request(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_header *h = (void *)(b->data);
    of_send_echo_reply(sw, h->xid);
    __of_send_features_request(sw);
}

static void
of_recv_init_echo_reply(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    __of_send_features_request(sw);
    /* Nothing else to-do as timestamp is already updated */
}

static void
of10_flow_removed(c_switch_t *sw, struct cbuf *b)
{
    struct flow                 flow, mask;
    struct ofp_flow_removed     *ofm = (void *)(b->data);
    struct of_flow_mod_params   fl_parms;

    memset(&fl_parms, 0, sizeof(fl_parms));
    memset(&flow, 0, sizeof(flow));
    memset(&mask, 0, sizeof(flow));

    of10_wc_to_mask(ofm->match.wildcards, &mask);
    fl_parms.prio = ntohs(ofm->priority);

    flow.in_port = ofm->match.in_port;
    memcpy(flow.dl_src, ofm->match.dl_src, sizeof ofm->match.dl_src);
    memcpy(flow.dl_dst, ofm->match.dl_dst, sizeof ofm->match.dl_dst);
    flow.dl_vlan = ofm->match.dl_vlan;
    flow.dl_type = ofm->match.dl_type;
    flow.dl_vlan_pcp = ofm->match.dl_vlan_pcp;
    flow.nw_src = ofm->match.nw_src;
    flow.nw_dst = ofm->match.nw_dst;
    flow.nw_proto = ofm->match.nw_proto;
    flow.tp_src = ofm->match.tp_src;
    flow.tp_dst = ofm->match.tp_dst;

    fl_parms.flow = &flow;
    fl_parms.mask = &mask;
    fl_parms.flow->table_id = C_TBL_HW_IDX_DFL; 
    fl_parms.reason = ofm->reason;
    
    /*
     * It is upto the application to check what flows are removed
     * by the switch and inform the controller so the controller 
     * itself does not take any action 
     */
    c_signal_app_event(sw, b, C_FLOW_REMOVED, NULL, &fl_parms, false);
}

static void
of10_recv_flow_mod_failed(c_switch_t *sw, struct cbuf *b)
{
    struct flow                 flow;
    struct flow                 mask;
    struct ofp_error_msg        *ofp_err = (void *)(b->data);
    struct ofp_flow_mod         *ofm = (void *)(ofp_err->data);
    struct of_flow_mod_params   fl_parms;
    void                        *app;
    char                        *print_str;

    memset(&flow, 0, sizeof(flow));
    memset(&mask, 0, sizeof(flow));

    of10_wc_to_mask(ofm->match.wildcards, &mask);
    flow.in_port = ofm->match.in_port;
    memcpy(flow.dl_src, ofm->match.dl_src, sizeof ofm->match.dl_src);
    memcpy(flow.dl_dst, ofm->match.dl_dst, sizeof ofm->match.dl_dst);
    flow.dl_vlan = ofm->match.dl_vlan;
    flow.dl_type = ofm->match.dl_type;
    flow.dl_vlan_pcp = ofm->match.dl_vlan_pcp;
    flow.nw_src = ofm->match.nw_src;
    flow.nw_dst = ofm->match.nw_dst;
    flow.nw_proto = ofm->match.nw_proto;
    flow.tp_src = ofm->match.tp_src;
    flow.tp_dst = ofm->match.tp_dst;

    fl_parms.mask = &mask;
    fl_parms.flow = &flow;
    fl_parms.prio = ntohs(ofm->priority);
    fl_parms.flow->table_id = C_TBL_HW_IDX_DFL;
    fl_parms.command = ntohs(ofm->command);

    /* Controller owns only vty intalled static flows */
    if (!(app = c_app_get(sw->c_hdl, C_VTY_NAME))) {
        goto app_signal_out;
    }

    fl_parms.app_owner = app;
    c_switch_flow_del(sw, &fl_parms);
    c_app_put(app);
    fl_parms.app_owner = NULL;

app_signal_out:
    /* We take a very conservative approach here and multicast
     * flow mod failed to all apps irrespective of whether they are owners
     * of this flow or not, to maintain sanity because some apps
     * may implicitly use this flow for some operation
     */
    c_signal_app_event(sw, b, C_FLOW_MOD_FAILED, NULL, &fl_parms, false);

    if (sw->ofp_ctors->dump_flow) {
        print_str=  sw->ofp_ctors->dump_flow(&flow, &mask); 
        c_log_err("%s: flow-mod failed for flow:", FN);
        c_log_err("%s", print_str);
        free(print_str);
    }

    return;
} 

static void
of10_recv_err_msg(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_error_msg *ofp_err = (void *)(b->data);

    c_log_err("%s: switch 0x%llx sent error type %hu code %hu", FN, 
               sw->DPID, ntohs(ofp_err->type), ntohs(ofp_err->code));

    switch(ntohs(ofp_err->type)) {
    case OFPET_FLOW_MOD_FAILED:
        return of10_recv_flow_mod_failed(sw, b);
    default:
        break;
    }
}

static void 
c_flow_stats_update(c_switch_t *sw, struct flow *flow, struct flow *mask,
                    void *flow_acts, size_t act_len, uint16_t prio,
                    uint64_t pkt_count, uint64_t byte_count)
{
    c_fl_entry_t    *ent;
    time_t          curr_time, time_diff;

    ent = c_do_flow_lookup_with_detail(sw, flow, mask, prio);
    if (!ent ||
        act_len != ent->action_len ||
        (act_len && memcmp(flow_acts, ent->actions, ent->action_len))) {
        if (sw->ofp_ctors->dump_flow) {
            char *fl_str;
            fl_str = sw->ofp_ctors->dump_flow(flow, mask);
            c_log_err("%s: 0x%llx Unknown flow (%s) in stats reply",
                      FN, sw->DPID, fl_str);
            free(fl_str);
        }
        if (ent) c_flow_entry_put(ent);
        return;
    }

    curr_time = time(NULL);
    time_diff = curr_time - ent->fl_stats.last_refresh; 

    if (ent->fl_stats.last_refresh && time_diff) {
        if (byte_count >= ent->fl_stats.byte_count) {
            ent->fl_stats.bps = (double)(byte_count
                                 - ent->fl_stats.byte_count)/time_diff;
        } else {
            c_log_err("%s: Byte count wrap around", FN);
        }
        if (pkt_count >= ent->fl_stats.pkt_count) {
            ent->fl_stats.pps = (double)(pkt_count
                                 - ent->fl_stats.pkt_count)/time_diff;
        } else {
            c_log_err("%s: Pkt count wrap around", FN);
        }
    }

    ent->fl_stats.byte_count = byte_count;
    ent->fl_stats.pkt_count = pkt_count;
    ent->fl_stats.last_refresh = curr_time;
    c_flow_entry_put(ent);
}

static int
of10_proc_one_flow_stats(c_switch_t *sw, void *ofps)
{
    struct flow             flow, mask;
    struct ofp_flow_stats   *ofp_stats = ofps;
    int                     act_len = ntohs(ofp_stats->length) - sizeof(*ofp_stats);;

    memset(&flow, 0, sizeof(flow));

    /* Table-id is 0 */
    flow.in_port = ofp_stats->match.in_port;
    memcpy(flow.dl_src, ofp_stats->match.dl_src, sizeof ofp_stats->match.dl_src);
    memcpy(flow.dl_dst, ofp_stats->match.dl_dst, sizeof ofp_stats->match.dl_dst);
    flow.dl_vlan = ofp_stats->match.dl_vlan;
    flow.dl_type = ofp_stats->match.dl_type;
    flow.dl_vlan_pcp = ofp_stats->match.dl_vlan_pcp;
    flow.nw_src = ofp_stats->match.nw_src;
    flow.nw_dst = ofp_stats->match.nw_dst;
    flow.nw_proto = ofp_stats->match.nw_proto;
    flow.tp_src = ofp_stats->match.tp_src;
    flow.tp_dst = ofp_stats->match.tp_dst;
    of10_wc_to_mask(ofp_stats->match.wildcards, &mask);

    c_flow_stats_update(sw, &flow, &mask, 
                        ofp_stats->actions,
                        act_len,
                        htons(ofp_stats->priority), 
                        ntohll(ofp_stats->packet_count),
                        ntohll(ofp_stats->byte_count));
    return act_len;
}

static void
c_per_flow_stats_scan(void *time_arg, c_fl_entry_t *ent)
{
    time_t time = *(time_t *)time_arg;

    if ((ent->FL_ENT_TYPE != C_TBL_EXM &&
        ent->FL_FLAGS & C_FL_ENT_CLONE) || 
        ent->FL_FLAGS & C_FL_ENT_LOCAL) {
        return;
    }

    if (ent->FL_FLAGS & C_FL_ENT_GSTATS) {
        if (ent->fl_stats.last_scan &&
            time - ent->fl_stats.last_refresh > 5 * C_FL_STAT_TIMEO) {
            ent->FL_FLAGS |= C_FL_ENT_EXPIRED;
            return;
        }
        if (!ent->fl_stats.last_scan || 
            ((time - ent->fl_stats.last_scan) > C_FL_STAT_TIMEO)) {
            __of_send_flow_stat_req(ent->sw, &ent->fl, &ent->fl_mask, 
                                    0, OFPG_ANY);
            ent->fl_stats.last_scan = time;
        }
    } 
}

void
c_per_switch_flow_stats_scan(c_switch_t *sw, time_t curr_time)
{
    c_flow_traverse_tbl_all(sw, (void *)&curr_time, c_per_flow_stats_scan);
}

static void 
c_switch_tbl_prop_update(c_switch_t *sw, uint8_t tbl_id, 
                         uint32_t *bmask, uint16_t type) 
{
    c_flow_tbl_t  *tbl;

    c_rd_lock(&sw->lock);
    tbl = &sw->rule_flow_tbls[tbl_id];

    if (!tbl->props) {
        tbl->props = calloc(1, sizeof(c_flow_tbl_props_t));
    }
    assert(tbl->props);

    switch (type) {
    case C_FL_TBL_FEAT_INSTRUCTIONS:
        tbl->props->bm_inst = *bmask;
        break;
    case C_FL_TBL_FEAT_INSTRUCTIONS_MISS:
        tbl->props->bm_inst_miss = *bmask;
        break;
    case C_FL_TBL_FEAT_NTABLE:
        memcpy(tbl->props->bm_next_tables, bmask,
               sizeof(tbl->props->bm_next_tables));
        break;
    case C_FL_TBL_FEAT_NTABLE_MISS:
         memcpy(tbl->props->bm_next_tables_miss, bmask,
               sizeof(tbl->props->bm_next_tables_miss));
        break;
    case C_FL_TBL_FEAT_WR_ACT:
        tbl->props->bm_wr_actions = *bmask;
        break;
    case C_FL_TBL_FEAT_WR_ACT_MISS:
        tbl->props->bm_wr_actions_miss = *bmask;
        break;
    case C_FL_TBL_FEAT_APP_ACT:
        tbl->props->bm_app_actions = *bmask;
        break;
    case C_FL_TBL_FEAT_APP_ACT_MISS:
        tbl->props->bm_app_actions_miss = *bmask;
        break;
    case C_FL_TBL_FEAT_WR_SETF:
        memcpy(tbl->props->bm_wr_set_field, bmask,
               sizeof(tbl->props->bm_wr_set_field));
        break;
    case C_FL_TBL_FEAT_WR_SETF_MISS:
        memcpy(tbl->props->bm_wr_set_field_miss, bmask,
               sizeof(tbl->props->bm_wr_set_field_miss));
        break;
    case C_FL_TBL_FEAT_APP_SETF:
        memcpy(tbl->props->bm_app_set_field, bmask,
               sizeof(tbl->props->bm_app_set_field));
        break;
    case C_FL_TBL_FEAT_APP_SETF_MISS:
        memcpy(tbl->props->bm_app_set_field_miss, bmask,
               sizeof(tbl->props->bm_app_set_field_miss));
        break;
    default:
        break;
    }
    
    c_rd_unlock(&sw->lock);
}
 
static void
c_switch_flow_table_enable(c_switch_t *sw, uint8_t table_id)
{
    struct flow flow, mask;
    c_flow_tbl_t  *tbl;
    bool en = false;
    mul_act_mdata_t mdata;

    memset(&flow, 0, sizeof(flow));
    of_mask_set_dc_all(&mask);
     
    c_rd_lock(&sw->lock);
    tbl = &sw->rule_flow_tbls[table_id];

    if (!tbl->hw_tbl_active) {
        tbl->hw_tbl_active = 1;
        en = true; 
    }
    c_rd_unlock(&sw->lock);

    if (!en) return;

    flow.table_id = table_id;
    mask.table_id = table_id;

    assert(sw->ofp_ctors->act_output);

    of_mact_alloc(&mdata);
    if (sw->ofp_ctors->act_output) {
        sw->ofp_ctors->act_output(&mdata, 0); /* 0 -> Send to controller */
    }

    __of_send_flow_add_direct(sw, &flow, &mask, OFP_NO_BUFFER,
                              mdata.act_base, of_mact_len(&mdata),
                              0, 0, C_FL_PRIO_DFL); 
    of_mact_free(&mdata);
}

static void
of10_recv_flow_mod(c_switch_t *sw, struct cbuf *b)
{
    struct flow                 flow;
    struct ofp_flow_mod         *ofm = (void *)(b->data);
    struct of_flow_mod_params   fl_parms;
    void                        *app;
    uint16_t                    command = ntohs(ofm->command);
    bool                        flow_add;

    if (!c_switch_is_virtual(sw)) {
        c_log_err("%s: Unexpected msg", FN);
        return;
    }

    switch (command) {
    case OFPFC_MODIFY_STRICT:
        flow_add = true;
        break;
    case OFPFC_DELETE:
    case OFPFC_DELETE_STRICT: 
        flow_add = false;
        break;
    default:
        c_log_err("%s: Unexpected flow mod command", FN);
        return;
    }

    memset(&flow, 0, sizeof(flow));
    flow.in_port = ofm->match.in_port;
    memcpy(flow.dl_src, ofm->match.dl_src, sizeof ofm->match.dl_src);
    memcpy(flow.dl_dst, ofm->match.dl_dst, sizeof ofm->match.dl_dst);
    flow.dl_vlan = ofm->match.dl_vlan;
    flow.dl_type = ofm->match.dl_type;
    flow.dl_vlan_pcp = ofm->match.dl_vlan_pcp;
    flow.nw_src = ofm->match.nw_src;
    flow.nw_dst = ofm->match.nw_dst;
    flow.nw_proto = ofm->match.nw_proto;
    flow.tp_src = ofm->match.tp_src;
    flow.tp_dst = ofm->match.tp_dst;

    fl_parms.wildcards = ofm->match.wildcards;
    fl_parms.flow = &flow;
    fl_parms.flags = (uint8_t)ntohl(ofm->buffer_id);
    fl_parms.prio = ntohs(ofm->priority);

    if (flow_add) {
        fl_parms.action_len = ntohs(ofm->header.length) - sizeof(*ofm); 
        fl_parms.actions = calloc(1, fl_parms.action_len);
        memcpy(fl_parms.actions, ofm->actions, fl_parms.action_len);
    }

    /* Controller owns only vty intalled static flows */
    if (!(app = c_app_get(sw->c_hdl, C_VTY_NAME))) {
        c_log_err("%s: |PANIC| Native vty app not found", FN);
        return;
    }

    fl_parms.app_owner = app;
    if (flow_add) {
        c_switch_flow_add(sw, &fl_parms);
    } else {
        c_switch_flow_del(sw, &fl_parms);
    }
    c_app_put(app);
}
 
static void
of10_recv_stats_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_stats_reply *ofp_sr = (void *)(b->data);
    int act_len = 0;

    switch(ntohs(ofp_sr->type)) {
    case OFPST_FLOW:
        {
            struct ofp_flow_stats *ofp_stats = (void *)(ofp_sr->body);
            size_t stat_length = ntohs(ofp_sr->header.length) - sizeof(*ofp_sr);

            while (stat_length) {
                assert(sw->ofp_priv_procs->proc_one_flow_stats);
                act_len = sw->ofp_priv_procs->proc_one_flow_stats(sw,
                                                        (void *)(ofp_stats));
                if (!act_len) break;
                ofp_stats = (void *)((uint8_t *)(ofp_stats + 1) + act_len);
                stat_length -= (sizeof(*ofp_stats) + act_len);
            }
            break;
        }
    default:
        c_log_err("%s: Unhandled stats reply 0x%x", FN, ntohs(ofp_sr->type));
        break;
    }

    return;
}

void __fastpath
of131_send_pkt_out_inline(void *arg, struct of_pkt_out_params *parms)
{
    struct cbuf     b;
    size_t          tot_len;
    uint8_t         data[C_INLINE_BUF_SZ];
    struct ofp131_packet_out *out;
    c_switch_t *sw = arg;

    tot_len = sizeof(struct ofp131_packet_out) +
                parms->action_len + parms->data_len;
    if (unlikely(tot_len > C_INLINE_BUF_SZ)) return of_send_pkt_out(sw, parms);

    cbuf_init_on_stack(&b, data, tot_len);
    of_prep_msg_on_stack(&b, tot_len, OFPT131_PACKET_OUT, 
                         (unsigned long)parms->data);

    out = (void *)b.data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htonl(parms->in_port);
    out->actions_len = htons(parms->action_len);
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy((uint8_t *)out->actions + parms->action_len, 
            parms->data, parms->data_len);

    c_switch_tx(sw, &b, false);
} 


static c_sw_port_t * 
of131_process_port(c_switch_t *sw UNUSED, void *opp_)
{
    const struct ofp131_port *opp;
    c_sw_port_t *port_desc;

    opp = opp_;
    port_desc = calloc(sizeof(c_sw_port_t), 1);
    assert(port_desc);

    port_desc->port_no = ntohl(opp->port_no);
    port_config_to_cxlate(&port_desc->config, ntohl(opp->config));
    port_status_to_cxlate(&port_desc->state, ntohl(opp->state));
    port_desc->curr = ntohl(opp->curr);
    port_desc->advertised = ntohl(opp->advertised);
    port_desc->supported = ntohl(opp->supported);
    port_desc->peer      = ntohl(opp->peer);
    port_desc->of_config = ntohl(opp->config);
    port_desc->of_state  = ntohl(opp->state);

    memcpy(port_desc->name, opp->name, OFP_MAX_PORT_NAME_LEN);
    port_desc->name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
    memcpy(port_desc->hw_addr, opp->hw_addr, OFP_ETH_ALEN);

    return port_desc;
}

static void
of131_recv_err_msg(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_error_msg *ofp_err = (void *)(b->data);

    c_log_err("%s: switch 0x%llx sent error type %hu code %hu", FN, 
               sw->DPID, ntohs(ofp_err->type), ntohs(ofp_err->code));

    switch(ntohs(ofp_err->type)) {
    case OFPET131_FLOW_MOD_FAILED:
        /* FIXME */
        c_log_err("Flow mod failed");
        break;
    default:
        break;
    }

}
 
static void
of131_recv_features_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp131_switch_features  *osf = CBUF_DATA(b);

    if (!c_switch_features_check(sw, ntohll(osf->datapath_id))) {
        return;
    }

    c_init_switch_features(sw, ntohll(osf->datapath_id), osf->header.version,
                           osf->n_tables, ntohl(osf->n_buffers), 0,
                           ntohl(osf->capabilities));                           

    c_register_switch(sw, b);

    /* There is no port info in features reply. Get it! */
    c_switch_tx(sw, of131_prep_mpart_msg(OFPMP_PORT_DESC, 0, 0), false);

    /* Get all the table features */
    c_switch_tx(sw, of131_prep_mpart_msg(OFPMP_TABLE_FEATURES, 0, 0), false);
}

static void
of131_mpart_process(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_multipart_reply *ofp_mr = CBUF_DATA(b);
    uint16_t body_len = ntohs(ofp_mr->header.length) - sizeof(*ofp_mr);
    int loops; /* Will not support more than this */
    int ret = -1;

    if (ntohs(ofp_mr->header.length) < sizeof(*ofp_mr)) {
        return;
    }

    switch (htons(ofp_mr->type)) {
    case OFPMP_PORT_DESC:
        {
            struct ofp131_port *port = (void *)(ofp_mr->body);
            struct c_port_chg_mdata mdata;
            c_sw_port_t *port_desc = NULL;
            struct c_port_cfg_state_mask chg_mask = { 0, 0 };
            loops = OFSW_MAX_REAL_PORTS; /* Will not support more than this */

            while (body_len && (loops-- > 0)) {
                port_desc = sw->ofp_priv_procs->xlate_port_desc(sw, port);
                assert(port_desc);

                c_wr_lock(&sw->lock);
                __c_switch_port_update(sw, port_desc, OFPPR_ADD, &chg_mask);
                c_wr_unlock(&sw->lock);

                mdata.reason = OFPPR_ADD;
                mdata.chg_mask = &chg_mask;
                mdata.port_desc = port_desc;
                c_signal_app_event(sw, b, C_PORT_CHANGE, NULL, &mdata, false);

                free(port_desc);
                body_len -= sizeof(*port);
                port = INC_PTR8(port, sizeof(*port));
            } 
            break;
        }
    case OFPMP_FLOW:
        {
            struct ofp131_flow_stats *ofp_stats = (void *)(ofp_mr->body);
            size_t stat_length = ntohs(ofp_mr->header.length) - sizeof(*ofp_mr);
            loops = OFSW_MAX_FLOW_STATS_COLL;

            while (stat_length && (loops-- > 0) &&
                   stat_length >= ntohs(ofp_stats->length)) {
                assert(sw->ofp_priv_procs->proc_one_flow_stats);
                ret = sw->ofp_priv_procs->proc_one_flow_stats(sw,
                                                        (void *)(ofp_stats));
                if (ret < 0) break;
                stat_length -= ntohs(ofp_stats->length);
                ofp_stats = INC_PTR8(ofp_stats, ntohs(ofp_stats->length));
            }
            break;
        }
    case OFPMP_TABLE_FEATURES: 
        {
            struct ofp_table_features *ofp_tf = (void *)(ofp_mr->body);
            size_t table_feat_len = ntohs(ofp_mr->header.length) - sizeof(*ofp_mr);
            loops = C_MAX_RULE_FLOW_TBLS;

            while (table_feat_len && loops-- > 0) {
                if (sw->ofp_priv_procs->proc_one_tbl_feature) {
                    sw->ofp_priv_procs->proc_one_tbl_feature(sw, (void *)ofp_tf);
                }
                c_switch_flow_table_enable(sw, ofp_tf->table_id);
                table_feat_len -= ntohs(ofp_tf->length);
                ofp_tf = INC_PTR8(ofp_tf, ntohs(ofp_tf->length));
            }
            break;
        }
    default:
        c_log_err("%s: mpart not handled", FN);
        break; 
    } 
}

static void
of131_recv_mpart_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_multipart_reply *ofp_mr = CBUF_DATA(b);

    if (1/*!(ntohs(ofp_mr->flags) & OFPMPF_REPLY_MORE)*/) {
        return of131_mpart_process(sw, b);
    } else {
        /* FIXME : Buffering logic required ?? */
        return;
    }
}

static void __fastpath
of131_recv_packet_in(c_switch_t *sw, struct cbuf *b)
{
    struct ofp131_packet_in *opi __aligned = CBUF_DATA(b);
    size_t pkt_len, pkt_ofs;
    struct flow fl[2]; /*Flow and mask pair */
    bool only_l2 = sw->fp_ops.fp_fwd == c_l2_lrn_fwd ? true : false;
    uint8_t *data;
    ssize_t match_len;
    struct c_pkt_in_mdata mdata; 

    match_len = C_ALIGN_8B_LEN(htons(opi->match.length)); /* Aligned match-length */
    match_len -= sizeof(opi->match);

    if (of131_ofpx_match_to_flow(&opi->match, &fl[0], &fl[1])) {
        return;
    }
    pkt_ofs = (sizeof(*opi) + match_len + 2);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    data = INC_PTR8(opi, pkt_ofs);

    if(!sw->fp_ops.fp_fwd ||
        of_flow_extract(data, &fl[0], ntohl(fl[0].in_port), 
                        pkt_len, only_l2) < 0) {
        return;
    }

    fl[0].table_id = opi->table_id;

    mdata.fl = &fl[0];
    mdata.pkt_ofs = pkt_ofs;
    mdata.pkt_len = pkt_len;
    mdata.buffer_id = ntohl(opi->buffer_id);
    
    sw->fp_ops.fp_fwd(sw, b, data, pkt_len, &mdata, ntohl(fl[0].in_port));
    return;
}

static void
of131_recv_flow_mod(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    /* TODO */
}

static void
of131_flow_removed(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    /* TODO */
} 

static void
of131_recv_port_status(c_switch_t *sw, struct cbuf *b)
{
    struct c_port_chg_mdata mdata;
    struct c_port_cfg_state_mask chg_mask = { 0, 0 };
    struct ofp131_port_status *ops = CBUF_DATA(b);
    c_sw_port_t *port_desc = NULL;

    port_desc = sw->ofp_priv_procs->xlate_port_desc(sw, &ops->desc);
    assert(port_desc);

    c_wr_lock(&sw->lock);
    __c_switch_port_update(sw, port_desc, ops->reason, &chg_mask);
    c_wr_unlock(&sw->lock);

    mdata.reason = ops->reason;
    mdata.chg_mask = &chg_mask; 
    mdata.port_desc = port_desc;
    c_signal_app_event(sw, b, C_PORT_CHANGE, NULL, &mdata, false);
    free(port_desc);
}

static void
of131_proc_tbl_feat_instructions(c_switch_t *sw, void *prop,
                                    uint8_t table_id,
                                    bool miss, size_t buf_len)
{
    struct ofp_table_feature_prop_instructions *ofp_tfi = prop;
    struct ofp_instruction *ofp_i;
    uint32_t inst_supp_bmask = 0;
    size_t len = ntohs(ofp_tfi->length); 
    size_t ilen;
    int loops = 0xffff;

    if (len > buf_len || buf_len < sizeof(*ofp_tfi)) {
        c_log_err("%s:  len-err", FN);
        return;
    }

    len -= sizeof(struct ofp_table_feature_prop_header);
    ofp_i = ofp_tfi->instruction_ids;
    while (loops-- > 0 &&
           len > sizeof(*ofp_i)) {

        ilen = ntohs(ofp_i->len);
        if (len < ilen  || ilen < sizeof(*ofp_i)) {
            c_log_err("%s parse-err", FN);
            break;
        }

        if (ntohs(ofp_i->type) <= OFPIT_METER) {
            inst_supp_bmask |= (1 << ntohs(ofp_i->type));
        }

        len -= ilen;
        ofp_i = INC_PTR8(ofp_i, ilen); 
    }

    c_switch_tbl_prop_update(sw, table_id, &inst_supp_bmask,
                             miss ? C_FL_TBL_FEAT_INSTRUCTIONS_MISS :
                             C_FL_TBL_FEAT_INSTRUCTIONS);
}

static void
of131_proc_tbl_feat_next_tables(c_switch_t *sw, void *prop,
                                   uint8_t table_id,
                                   bool miss, size_t buf_len)
{
    struct ofp_table_feature_prop_next_tables *ofp_tfn = prop;
    uint8_t *n_tbl;
    uint32_t tbl_supp_bmask[C_MAX_TABLE_BMASK_SZ];
    size_t len = ntohs(ofp_tfn->length); 
    int loops = 0xff;

    if (len > buf_len || buf_len < sizeof(*ofp_tfn)) {
        c_log_err("%s:  len-err", FN);
        return;
    }

    memset(tbl_supp_bmask, 0, sizeof(tbl_supp_bmask));

    len -= sizeof(struct ofp_table_feature_prop_header);
    n_tbl = ofp_tfn->next_table_ids;
    while (loops-- > 0 &&
           len > sizeof(*n_tbl)) {
        SET_BIT_IN_32MASK(tbl_supp_bmask, *n_tbl);
        len -= sizeof(*n_tbl);
        n_tbl = INC_PTR8(n_tbl, sizeof(*n_tbl)); 
    }

    c_switch_tbl_prop_update(sw, table_id, tbl_supp_bmask,
                             miss ? C_FL_TBL_FEAT_NTABLE_MISS:
                             C_FL_TBL_FEAT_NTABLE);
}

static void
of131_proc_tbl_feat_actions(c_switch_t *sw, void *prop,
                               uint8_t table_id,
                               bool write, bool miss, size_t buf_len)
{
    struct ofp_table_feature_prop_actions *ofp_tfa = prop;
    struct ofp_action_header *ofp_a = ofp_tfa->action_ids; 
    uint32_t act_supp_bmask = 0;
    size_t len = ntohs(ofp_tfa->length); 
    size_t alen;
    int loops = 32;

    if (len > buf_len || buf_len < sizeof(*ofp_tfa)) {
        c_log_err("%s:  len-err", FN);
        return;
    }

    len -= sizeof(struct ofp_table_feature_prop_header);
    while (loops-- > 0 && len > OFP_ACT_HDR_SZ) {

        alen = ntohs(ofp_a->len);
        if (alen > len || alen < OFP_ACT_HDR_SZ) {
            c_log_err("%s: Parse-err", FN);
            break;
        }

        if (ntohs(ofp_a->type) <= OFPAT131_POP_PBB) {
            act_supp_bmask |= (1 << htons(ofp_a->type));
        }

        len -= alen;
        ofp_a = INC_PTR8(ofp_a, alen); 
    }

    c_switch_tbl_prop_update(sw, table_id, &act_supp_bmask,
                             miss ? (write ? 
                                     C_FL_TBL_FEAT_WR_ACT_MISS: 
                                     C_FL_TBL_FEAT_APP_ACT_MISS):
                             (write ?
                              C_FL_TBL_FEAT_WR_ACT:
                              C_FL_TBL_FEAT_APP_ACT));
}

static void
of131_proc_tbl_feat_set_field(c_switch_t *sw, void *prop,
                                 uint8_t table_id,
                                 bool write, bool miss, size_t buf_len)
{
    struct ofp_table_feature_prop_oxm *ofp_tfx = prop;
    struct ofp_oxm_header *ofp_oxm = ASSIGN_PTR(ofp_tfx->oxm_ids); 
    struct ofp_oxm_header oxm;
    uint32_t set_field_bmask[C_MAX_SET_FIELD_BMASK_SZ];
    size_t len = ntohs(ofp_tfx->length); 
    int loops = 32;
    size_t xlen;

    if (len > buf_len || buf_len < sizeof(*ofp_tfx)) {
        c_log_err("%s:  len-err", FN);
        return;
    }

    memset(set_field_bmask, 0, sizeof(set_field_bmask));
    len -= sizeof(struct ofp_table_feature_prop_header);
    while (loops-- > 0  && len > sizeof(oxm)) {

        ASSIGN_OXM_HDR(&oxm, ofp_oxm);
        NTOH_OXM_HDR(&oxm);

        xlen = oxm.length; 
        if (xlen > len || xlen < sizeof(oxm)) {
            c_log_err("%s Parse-err", FN);
            break;
        }

        if (OFP_OXM_GHDR_FIELD(&oxm) <= OFPXMT_OFB_IPV6_EXTHDR) {
            SET_BIT_IN_32MASK(set_field_bmask, OFP_OXM_GHDR_FIELD(&oxm));
        }
        len -= xlen;
        ofp_oxm = INC_PTR8(ofp_oxm, xlen); 
    }

    c_switch_tbl_prop_update(sw, table_id, set_field_bmask,
                             miss ? (write ? 
                                     C_FL_TBL_FEAT_WR_SETF_MISS: 
                                     C_FL_TBL_FEAT_APP_SETF_MISS):
                             (write ?
                              C_FL_TBL_FEAT_WR_SETF:
                              C_FL_TBL_FEAT_APP_SETF));
}

static int
of131_proc_one_tbl_feature(c_switch_t *sw, void *tbf)
{
    struct ofp_table_features *ofp_tbf = tbf;
    struct ofp_table_feature_prop_header *prop = ofp_tbf->properties;
    size_t tot_len = ntohs(ofp_tbf->length);
    size_t prop_len;
    uint8_t table = ofp_tbf->table_id;
    int loops = OFP_MAX_TABLE_PROPS; 

    while (loops-- > 0 && tot_len >= C_ALIGN_8B_LEN(sizeof(*prop))) {

        prop_len = C_ALIGN_8B_LEN(ntohs(prop->length));
        if (prop_len > tot_len || prop_len < C_ALIGN_8B_LEN(sizeof(*prop))) {
            c_log_err("%s: Parse-err", FN);
            break;
        }

        switch(htons(prop->type)) {
        case OFPTFPT_INSTRUCTIONS:
            of131_proc_tbl_feat_instructions(sw, prop, table, false, tot_len);
            break;
        case OFPTFPT_INSTRUCTIONS_MISS:
            of131_proc_tbl_feat_instructions(sw, prop, table, true, tot_len);
            break;
        case OFPTFPT_NEXT_TABLES:
            of131_proc_tbl_feat_next_tables(sw, prop, table, false, tot_len);
            break; 
        case OFPTFPT_NEXT_TABLES_MISS:
            of131_proc_tbl_feat_next_tables(sw, prop, table, true, tot_len);
            break;
        case OFPTFPT_WRITE_ACTIONS:
            of131_proc_tbl_feat_actions(sw, prop, table, true, false, tot_len);
            break;
        case OFPTFPT_WRITE_ACTIONS_MISS:
            of131_proc_tbl_feat_actions(sw, prop, table, true, true, tot_len);
            break;
        case OFPTFPT_APPLY_ACTIONS:
            of131_proc_tbl_feat_actions(sw, prop, table, false, false, tot_len);
            break;
        case OFPTFPT_APPLY_ACTIONS_MISS:
            of131_proc_tbl_feat_actions(sw, prop, table, false, true, tot_len);
            break;
        case OFPTFPT_WRITE_SETFIELD:
            of131_proc_tbl_feat_set_field(sw, prop, table, true, false, tot_len);
            break;
        case OFPTFPT_WRITE_SETFIELD_MISS:
            of131_proc_tbl_feat_set_field(sw, prop, table, true, true, tot_len);
            break;
         case OFPTFPT_APPLY_SETFIELD:
            of131_proc_tbl_feat_set_field(sw, prop, table, false, false, tot_len);
            break;
        case OFPTFPT_APPLY_SETFIELD_MISS:
            of131_proc_tbl_feat_set_field(sw, prop, table, false, true, tot_len);
            break;
        case OFPTFPT_EXPERIMENTER:
        case OFPTFPT_EXPERIMENTER_MISS:
            break;
        default:
            goto out;
        }

        tot_len -= prop_len;
        prop = INC_PTR8(prop, prop_len);
    }

out:  
    return 0;
}

static int
of131_proc_one_flow_stats(c_switch_t *sw, void *ofps)
{
    struct flow flow, mask;
    struct ofp131_flow_stats *ofp_stats = ofps;
    struct ofpx_match *match = &ofp_stats->match;
    uint8_t *inst_list = NULL;
    ssize_t inst_len, match_len;

    match_len = C_ALIGN_8B_LEN(htons(match->length)); /* Aligned match-length */

    inst_list = INC_PTR8(match, match_len);
    inst_len = ntohs(ofp_stats->length) - DIFF_PTR8(inst_list, ofp_stats);
    if (inst_len < 0) {
        c_log_err("%s: Can't parse flow-stats", FN);
        return -1;
    }

    memset(&flow, 0, sizeof(flow));
    memset(&mask, 0, sizeof(flow));

    if (of131_ofpx_match_to_flow(&ofp_stats->match, &flow, &mask)) {
        c_log_err("%s: Can't parse OXM TLVs", FN);
        return -1;
    }
    flow.table_id = ofp_stats->table_id;
    mask.table_id = 0xff;  /* Inconsequential */

    c_flow_stats_update(sw, &flow, &mask, 
                        inst_list, inst_len,
                        htons(ofp_stats->priority), 
                        ntohll(ofp_stats->packet_count),
                        ntohll(ofp_stats->byte_count));
    return inst_len;
}

struct c_ofp_rx_handler of_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT_HELLO */
    { of10_recv_err_msg, sizeof(struct ofp_error_msg), NULL }, /* OFPT_ERROR */
    { of10_recv_echo_request, OFP_HDR_SZ, NULL }, /* OFPT_ECHO_REQUEST */
    { of10_recv_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER, /* OFPT_VENDOR */
    NULL_OF_HANDLER, /* OFPT_FEATURES_REQUEST */
    { of10_recv_features_reply, OFP_HDR_SZ, NULL },
                     /* OFPT_FEATURES_REPLY */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT_SET_CONFIG */
    { of10_recv_packet_in, sizeof(struct ofp_packet_in), NULL},
                     /* OFPT_PACKET_IN */
    { of10_flow_removed, sizeof(struct ofp_flow_removed), NULL}, 
                     /* OFPT_FLOW_REMOVED */
    { of10_recv_port_status, sizeof(struct ofp_port_status), NULL },
                     /* OFPT_PORT_STATUS */
    NULL_OF_HANDLER, /* OFPT_PACKET_OUT */
    { of10_recv_flow_mod, sizeof(struct ofp_flow_mod), NULL },                                       /* OFPT_FLOW_MOD */
    NULL_OF_HANDLER, /* OFPT_PORT_MOD */
    NULL_OF_HANDLER, /* OFPT_STATS_REQUEST */
    { of10_recv_stats_reply, sizeof(struct ofp_stats_reply), NULL },
                     /* OFPT_STATS_REPLY */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REQUEST */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REPLY */
};

struct c_ofp_rx_handler of_boot_handlers[] __aligned = {
    { of_recv_hello, OFP_HDR_SZ, NULL }, /* OFPT_HELLO */
    NULL_OF_HANDLER, /* OFPT_ERROR */
    NULL_OF_HANDLER, /* OFPT_ECHO_REQUEST */
    NULL_OF_HANDLER, /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER, /* OFPT_VENDOR */
    NULL_OF_HANDLER, /* OFPT_FEATURES_REQUEST */
    NULL_OF_HANDLER, /* OFPT_FEATURES_REPLY */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT_SET_CONFIG */
    NULL_OF_HANDLER, /* OFPT_PACKET_IN */
    NULL_OF_HANDLER, /* OFPT_FLOW_REMOVED */
    NULL_OF_HANDLER, /* OFPT_PORT_STATUS */
    NULL_OF_HANDLER, /* OFPT_PACKET_OUT */
    NULL_OF_HANDLER, /* OFPT_FLOW_MOD */
    NULL_OF_HANDLER, /* OFPT_PORT_MOD */
    NULL_OF_HANDLER, /* OFPT_STATS_REQUEST */
    NULL_OF_HANDLER, /* OFPT_STATS_REPLY */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REQUEST */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REPLY */
};

struct c_ofp_rx_handler of_init_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT_HELLO */
    NULL_OF_HANDLER, /* OFPT_ERROR */
    { of_recv_init_echo_request, OFP_HDR_SZ, NULL }, /* OFPT_ECHO_REQUEST */
    { of_recv_init_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER, /* OFPT_VENDOR */
    NULL_OF_HANDLER, /* OFPT_FEATURES_REQUEST */
    { of10_recv_features_reply, OFP_HDR_SZ, NULL },
                     /* OFPT_FEATURES_REPLY */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT_SET_CONFIG */
    NULL_OF_HANDLER, /* OFPT_PACKET_IN */
    NULL_OF_HANDLER, /* OFPT_FLOW_REMOVED */
    NULL_OF_HANDLER, /* OFPT_PORT_STATUS */
    NULL_OF_HANDLER, /* OFPT_PACKET_OUT */
    NULL_OF_HANDLER, /* OFPT_FLOW_MOD */
    NULL_OF_HANDLER, /* OFPT_PORT_MOD */
    NULL_OF_HANDLER, /* OFPT_STATS_REQUEST */
    NULL_OF_HANDLER, /* OFPT_STATS_REPLY */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REQUEST */
    NULL_OF_HANDLER, /* OFPT_BARRIER_REPLY */
};

struct c_ofp_rx_handler of131_init_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT131_HELLO */
    NULL_OF_HANDLER, /* OFPT131_ERROR */
    { of_recv_init_echo_request, OFP_HDR_SZ, NULL }, /* OFPT_ECHO_REQUEST */
    { of_recv_init_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER, /* OFPT131_EXPERIMENTER */
    NULL_OF_HANDLER, /* OFPT131_FEATURES_REQUEST */
    { of131_recv_features_reply, OFP_HDR_SZ, NULL },
                     /* OFPT131_FEATURES_REPLY */
    NULL_OF_HANDLER, /* OFPT131_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT131_SET_CONFIG */
    NULL_OF_HANDLER, /* OFPT131_PACKET_IN */
    NULL_OF_HANDLER, /* OFPT131_FLOW_REMOVED */
    NULL_OF_HANDLER, /* OFPT131_PORT_STATUS */
    NULL_OF_HANDLER, /* OFPT131_PACKET_OUT */
    NULL_OF_HANDLER, /* OFPT131_FLOW_MOD */
    NULL_OF_HANDLER, /* OFPT131_GROUP_MOD */
    NULL_OF_HANDLER, /* OFPT131_PORT_MOD */
    NULL_OF_HANDLER, /* OFPT131_TABLE_MOD */
    NULL_OF_HANDLER, /* OFPT131_MULTIPART_REQUEST */
    { of131_recv_mpart_reply, sizeof(struct ofp_multipart_reply), NULL },
                     /* OFPT131_MULTIPART_REPLY */
    NULL_OF_HANDLER, /* OFPT131_BARRIER_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_BARRIER_REPLY */
    NULL_OF_HANDLER, /* OFPT131_QUEUE_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_QUEUE_GET_CONFIG_REPLY */
    NULL_OF_HANDLER, /* OFPT131_ROLE_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_ROLE_REPLY */
    NULL_OF_HANDLER, /* OFPT131_GET_ASYNC_REQUEST */
    NULL_OF_HANDLER, /* OFPT131_GET_ASYNC_REPLY */
    NULL_OF_HANDLER, /* OFPT131_SET_ASYNC */
    NULL_OF_HANDLER, /* OFPT131_METER_MOD */    
};

struct c_ofp_rx_handler of131_handlers[] __aligned = {
    NULL_OF_HANDLER, /* OFPT131_HELLO */
    { of131_recv_err_msg, sizeof(struct ofp_error_msg), NULL },
                      /* OFPT131_ERROR */
    { of10_recv_echo_request, OFP_HDR_SZ, NULL },  /* OFPT131_ECHO_REQUEST */
    { of10_recv_echo_reply, OFP_HDR_SZ, NULL}, /* OFPT131_ECHO_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_EXPERIMENTER */
    NULL_OF_HANDLER,  /* OFPT131_FEATURES_REQUEST */
    { of131_recv_features_reply, OFP_HDR_SZ, NULL },
                      /* OFPT131_FEATURES_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER,  /* OFPT131_GET_CONFIG_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_SET_CONFIG */
    { of131_recv_packet_in, sizeof(struct ofp131_packet_in), NULL},
                      /* OFPT131_PACKET_IN */
    { of131_flow_removed, sizeof(struct ofp131_flow_removed), NULL},
                      /* OFPT131_FLOW_REMOVED */
    { of131_recv_port_status, sizeof(struct ofp131_port_status), NULL },
                      /* OFPT131_PORT_STATUS */
    NULL_OF_HANDLER,  /* OFPT131_PACKET_OUT */
    { of131_recv_flow_mod, sizeof(struct ofp131_flow_mod), NULL },
                      /* OFPT131_FLOW_MOD */
    NULL_OF_HANDLER,  /* OFPT131_GROUP_MOD */
    NULL_OF_HANDLER,  /* OFPT131_PORT_MOD */
    NULL_OF_HANDLER,  /* OFPT131_TABLE_MOD */
    NULL_OF_HANDLER,  /* OFPT131_MULTIPART_REQUEST */
    { of131_recv_mpart_reply, sizeof(struct ofp_multipart_reply), NULL },
                      /* OFPT131_MULTIPART_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_BARRIER_REQUEST */
    NULL_OF_HANDLER,  /* OFPT131_BARRIER_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_QUEUE_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER,  /* OFPT131_QUEUE_GET_CONFIG_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_ROLE_REQUEST */
    NULL_OF_HANDLER,  /* OFPT131_ROLE_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_GET_ASYNC_REQUEST */
    NULL_OF_HANDLER,  /* OFPT131_GET_ASYNC_REPLY */
    NULL_OF_HANDLER,  /* OFPT131_SET_ASYNC */
    NULL_OF_HANDLER,  /* OFPT131_METER_MOD */    
};

struct c_ofp_proc_helpers ofp_priv_procs __aligned = {
    .xlate_port_desc = of10_process_phy_port,
    .mk_ofp_features = c_switch_mk_ofp1_0_features,
    .proc_one_flow_stats = of10_proc_one_flow_stats
};

struct c_ofp_proc_helpers ofp131_priv_procs __aligned = {
    .xlate_port_desc = of131_process_port,
    .mk_ofp_features =  NULL, /* TODO */
    .proc_one_flow_stats = of131_proc_one_flow_stats, 
    .proc_one_tbl_feature = of131_proc_one_tbl_feature
};

void __fastpath
c_switch_recv_msg(void *sw_arg, struct cbuf *b)
{
    c_switch_t        *sw = sw_arg;
    struct ofp_header *oh;

    prefetch(&of_handlers[OFPT_PACKET_IN]);

    oh = (void *)b->data;

    //c_log_debug("OF MSG RX TYPE (%d)(%hu)", oh->type, ntohs(oh->length));
    //c_hex_dump(oh, ntohs(oh->length));

    sw->last_refresh_time = time(NULL);
    sw->conn.rx_pkts++;

    RET_OF_MSG_HANDLER(sw, sw->ofp_rx_handlers, b, oh->type, b->len);
}
