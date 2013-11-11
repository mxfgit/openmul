/*
 *  mul_app_infra.h: MUL application infrastructre headers
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

#ifndef __MUL_APP_INFRA_H__
#define __MUL_APP_INFRA_H__ 1

struct mul_switch
{
    void        *hdl;
    c_rw_lock_t lock;
    c_atomic_t  ref;
    uint64_t    dpid;
    int         alias_id;
    GSList      *port_list;
    uint8_t     n_stale;
#define MUL_PRIV_SWITCH(X) (X->priv)
    void        *priv;

    uint32_t    ofp_version;
    uint32_t    n_buffers;
    uint8_t     n_tables;
    uint8_t     ofp_ver;
};
typedef struct mul_switch mul_switch_t;

struct mul_port
{
    mul_switch_t *owner;
    uint16_t     port_no;
    uint32_t     config;
    uint32_t     state;
    uint8_t      hw_addr[6];
    uint8_t      n_stale;
#define MUL_PRIV_PORT(X) (x->priv)
    void         *priv;
};
typedef struct mul_port mul_port_t;

struct mul_app_client_cb
{
    int  (*switch_priv_alloc)(void **switch_ptr);
    void (*switch_priv_free)(void *switch_ptr);
    void (*switch_add_cb)(mul_switch_t *sw); 
    void (*switch_del_cb)(mul_switch_t *sw); 
    int  (*switch_priv_port_alloc)(void **port_ptr);
    void (*switch_priv_port_free)(void **port_ptr);
    void (*switch_port_add_cb)(mul_switch_t *sw, mul_port_t *port); 
    void (*switch_port_del_cb)(mul_switch_t *sw, mul_port_t *port); 
    void (*switch_port_chg)(mul_switch_t *sw, mul_port_t *port, bool adm, 
                            bool link); 
    void (*switch_port_link_chg)(mul_switch_t *sw, mul_port_t *port, bool link); 
    void (*switch_port_adm_chg)(mul_switch_t *sw, mul_port_t *port, bool adm); 
    void (*switch_packet_in)(mul_switch_t *sw, struct flow *fl, uint32_t port,
                            uint32_t buffer_id,  uint8_t *raw, size_t pkt_len);
    void (*switch_error)(mul_switch_t *sw, uint16_t type, uint16_t code,
                         uint8_t *raw, size_t raw_len);
    void (*core_conn_closed)(void);
    void (*core_conn_reconn)(void);
    void (*app_ha_state)(uint32_t sysid, uint32_t ha_state);
};
typedef struct mul_app_client_cb mul_app_client_cb_t;

void mul_app_free_buf(void *b);
int mul_register_app(void *app, char *app_name, uint32_t app_flags,
                     uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
                     void  (*ev_cb)(void *app_arg, void *pkt_arg));
int mul_register_app_cb(void *app_arg, char *app_name, uint32_t app_flags,
                    uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
                    struct mul_app_client_cb *app_cbs);
int mul_unregister_app(char *app_name);
int mul_app_command_handler(void *app_name,void *b);

int mul_app_send_flow_add(void *app_name, void *sw_arg,
                      uint64_t dpid, struct flow *fl, struct flow *mask,
                      uint32_t buffer_id, void *actions, size_t action_len,
                      uint16_t itimeo, uint16_t htimeo, uint16_t prio,
                      uint8_t flags);
int mul_service_send_flow_add(void *service,
                          uint64_t dpid, struct flow *fl, struct flow *mask,
                          uint32_t buffer_id, void *actions, size_t action_len,
                          uint16_t itimeo, uint16_t htimeo, uint16_t prio,
                          uint8_t flags);
int mul_app_send_flow_del(void *app_name, void *sw_arg, uint64_t dpid,
                          struct flow *fl, struct flow *mask,
                          uint32_t port, uint16_t prio, uint8_t flag,
                          uint32_t group);
int mul_service_send_flow_del(void *service,
                      uint64_t dpid, struct flow *fl,
                      struct flow *mask, uint32_t oport,
                      uint16_t prio, uint8_t flags,
                      uint32_t group);
int mul_service_send_group_add(void *service,
                           uint64_t dpid,
                           struct of_group_mod_params *g_parms);
int mul_service_send_group_del(void *service,
                           uint64_t dpid, struct of_group_mod_params *g_parms);
void mul_app_send_pkt_out(void *sw_arg, uint64_t dpid, void *parms);
void *mul_app_create_service(char *name,
                             void (*service_handler)(void *service,
                                                     struct cbuf *msg));
void *mul_app_get_service(char *name, const char *server);
void *mul_app_get_service_notify(char *name,
                          void (*conn_update)(void *service,
                                              unsigned char conn_event),
                          bool retry_conn, const char *server);
void mul_app_destroy_service(void *service);
bool mul_app_is_master(void);

mul_switch_t *c_app_switch_get_with_id(uint64_t dpid);
uint8_t c_app_switch_get_version_with_id(uint64_t dpid);
void c_app_switch_put(mul_switch_t *sw);

void mul_app_act_alloc(mul_act_mdata_t *mdata);
void mul_app_act_free(mul_act_mdata_t *mdata);
size_t mul_app_act_len(mul_act_mdata_t *mdata);
size_t mul_app_act_buf_room(mul_act_mdata_t *mdata);
void mul_app_act_set_ctors(mul_act_mdata_t *mdata, uint64_t dpid);
void mul_app_action_output(mul_act_mdata_t *mdata, uint32_t oport);
void mul_app_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid);
void mul_app_action_strip_vlan(mul_act_mdata_t *mdata);
void mul_app_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac);
void mul_app_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac);
void mul_app_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp);
void mul_app_action_set_nw_saddr(mul_act_mdata_t *mdata, uint32_t nw_saddr); 
void mul_app_action_set_nw_daddr(mul_act_mdata_t *mdata, uint32_t nw_daddr);
void mul_app_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos);
void mul_app_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port);
void mul_app_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port);
void mul_app_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port);
void mul_app_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port);

#endif
