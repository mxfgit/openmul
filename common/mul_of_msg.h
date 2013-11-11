/*
 *  mul_of_msg.h: MUL openflow message handling 
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
#ifndef __MUL_OF_MSG_H__
#define __MUL_OF_MSG_H__

#define OF_DUMP_INST_SZ 4096
#define OF_DUMP_ACT_SZ 4096
#define OF_DUMP_WC_SZ 4096
#define FL_PBUF_SZ 4096

#define OF_MAX_MISS_SEND_LEN (1518)

#define OF_MAX_FLOW_MOD_BUF_SZ (4096) 
#define OF_ALL_TABLES (0xff) 

#define OF_NO_PORT (0) 
#define OF_SEND_IN_PORT (OFPP131_IN_PORT)
#define OF_ALL_PORTS (OFPP131_ALL)

struct ofp_act_parsers {
    int (*act_output)(struct ofp_action_header *act, void *arg);
    int (*act_push_vlan)(struct ofp_action_header *act, void *arg);
    int (*act_pop_vlan)(struct ofp_action_header *act, void *arg);
    int (*act_push_mpls)(struct ofp_action_header *act, void *arg);
    int (*act_pop_mpls)(struct ofp_action_header *act, void *arg);
    int (*act_set_mpls_ttl)(struct ofp_action_header *act, void *arg);
    int (*act_dec_mpls_ttl)(struct ofp_action_header *act, void *arg);
    int (*act_push_pbb)(struct ofp_action_header *act, void *arg);
    int (*act_pop_pbb)(struct ofp_action_header *act, void *arg);
    int (*act_set_queue)(struct ofp_action_header *act, void *arg);
    int (*act_set_grp)(struct ofp_action_header *act, void *arg);
    int (*act_set_nw_ttl)(struct ofp_action_header *act, void *arg);
    int (*act_dec_nw_ttl)(struct ofp_action_header *act, void *arg);
    int (*act_set_vlan)(struct ofp_action_header *act, void *arg);     // OF1.0 Excl
    int (*act_set_vlan_pcp)(struct ofp_action_header *act, void *arg); // OF1.0 Excl
    int (*act_set_dl_dst)(struct ofp_action_header *act, void *arg);   // OF1.0 Excl
    int (*act_set_dl_src)(struct ofp_action_header *act, void *arg);   // OF1.0 Excl
    int (*act_set_nw_src)(struct ofp_action_header *act, void *arg);   // OF1.0 Excl
    int (*act_set_nw_dst)(struct ofp_action_header *act, void *arg);   // OF1.0 Excl
    int (*act_set_field)(struct ofp_action_header *act, void *arg);
    int (*act_setf_in_port)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_dst)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_src)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_vlan)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_vlan_pcp)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_type)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_ipv4_src)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_ipv4_dst)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_ipv4_dscp)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_tcp_src)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_tcp_dst)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_udp_dst)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_udp_src)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_cp_ttl_out)(struct ofp_action_header *act, void *arg);
    int (*act_cp_ttl_in)(struct ofp_action_header *act, void *arg);
    int (*act_exp)(struct ofp_action_header *act, void *arg);
};

struct ofp_inst_parsers {
    void *(*prep_inst_parser)(void *arg, struct ofp_inst_parsers *parsers,
                              struct ofp_act_parsers *act_parsers);
    void (*pre_proc)(void *arg);
    void (*post_proc)(void *arg);
    void (*no_inst)(void *arg);
    int (*goto_inst)(struct ofp_instruction *inst, void *arg);
    int (*wr_meta_inst)(struct ofp_instruction *inst, void *arg);
    int (*wr_act_inst)(struct ofp_instruction *inst, void *arg);
    int (*apply_act_inst)(struct ofp_instruction *inst, void *arg);
    int (*clear_act_inst)(struct ofp_instruction *inst, void *arg);
    int (*meter_inst)(struct ofp_instruction *inst, void *arg);
    int (*exp_inst)(struct ofp_instruction *inst, void *arg);
    struct ofp_inst_parser_arg *(*fini_inst_parser)(void *arg);
};

struct ofp_inst_parser_arg
{
    struct flow *m_fl;
    int res;
    char *pbuf;
    size_t len;
    void *u_arg;
    struct ofp_inst_parsers *parsers;
    struct ofp_act_parsers *act_parsers;
};

struct ofpx_oxm_parser_arg
{
    struct flow *flow;
    struct flow *mask;
};

struct of_act_vec_elem
{
    uint16_t weight;
    void *actions;
    size_t action_len;
};

struct mul_act_mdata
{
    uint8_t *act_base;
    uint8_t *act_wr_ptr;
    uint8_t *act_inst_ptr;
    uint8_t n_wracts;
    uint8_t n_appacts;
    uint8_t n_clracts;
#define MUL_ACT_BUF_SZ (4096)
    size_t  buf_len;
    bool only_acts;
    void *ofp_ctors;
};
typedef struct mul_act_mdata mul_act_mdata_t;

static void inline
of_mact_mdata_reset(mul_act_mdata_t *mdata)
{
    mdata->act_wr_ptr = mdata->act_base;
    mdata->act_inst_ptr = NULL;
    mdata->n_wracts = 0;
    mdata->n_appacts = 0;
    mdata->n_clracts = 0;
    mdata->only_acts = 0;
    mdata->ofp_ctors = NULL;
}

static void inline
of_mact_mdata_init(mul_act_mdata_t *mdata, size_t len)
{
    of_mact_mdata_reset(mdata);
    mdata->buf_len = len;
}

static void inline
of_mact_mdata_reset_act_inst(mul_act_mdata_t *mdata)
{
    mdata->act_inst_ptr = NULL;
}

static inline size_t
of_mact_buf_room(mul_act_mdata_t *mdata)
{
    size_t len;

    assert(mdata->act_base <= mdata->act_wr_ptr);
    len = (size_t)(mdata->act_wr_ptr - mdata->act_base);
    return (len > mdata->buf_len ? 0 : mdata->buf_len - len);
}

static inline size_t
of_mact_len(mul_act_mdata_t *mdata)
{
    assert(mdata->act_base <= mdata->act_wr_ptr);
    return (size_t)(mdata->act_wr_ptr - mdata->act_base);
}

static inline size_t
of_mact_inst_act_len(mul_act_mdata_t *mdata)
{
    assert(mdata->act_inst_ptr <= mdata->act_wr_ptr);
    return (size_t)(mdata->act_wr_ptr - mdata->act_inst_ptr);
}

static inline void
of_mask_set_dc_all(struct flow *mask)
{
    memset(mask, 0, sizeof(*mask));
}

static inline void
of_mask_set_no_dc(struct flow *mask)
{
    memset(mask, 0xff, sizeof(*mask));
}

static inline void
of_mask_set_dl_dst(struct flow *mask)
{
    memset(mask->dl_dst, 0xff, 6);
}

static inline void
of_mask_clr_dl_dst(struct flow *mask)
{
    memset(mask->dl_dst, 0, 6);
}

static inline void
of_mask_set_dl_src(struct flow *mask)
{
    memset(mask->dl_src, 0xff, 6);
}

static inline void
of_mask_clr_dl_src(struct flow *mask)
{
    memset(mask->dl_src, 0x0, 6);
}

static inline void
of_mask_set_nw_src(struct flow *mask, size_t prefixlen)
{
    assert(prefixlen <= 32);
    mask->nw_src = make_inet_mask(prefixlen);
}

static inline void
of_mask_clr_nw_src(struct flow *mask)
{
    mask->nw_src = 0x0;
}

static inline void
of_mask_set_nw_dst(struct flow *mask, size_t prefixlen)
{
    assert(prefixlen <= 32);
    mask->nw_dst = make_inet_mask(prefixlen);
}

static inline void
of_mask_clr_nw_dst(struct flow *mask)
{
    mask->nw_dst = 0x0;
}

static inline void
of_mask_set_dl_type(struct flow *mask)
{
    mask->dl_type = 0xffff;
}

static inline void
of_mask_clr_dl_type(struct flow *mask)
{
    mask->dl_type = 0x0;
}

static inline void
of_mask_set_dl_vlan(struct flow *mask)
{
    mask->dl_vlan = 0xffff;
}

static inline void
of_mask_clr_dl_vlan(struct flow *mask)
{
    mask->dl_vlan = 0x0;
}

static inline void
of_mask_set_in_port(struct flow *mask)
{
    mask->in_port = 0xffffffff;
}

static inline void
of_mask_clr_in_port(struct flow *mask)
{
    mask->in_port = 0x0;
}

static inline void
of_mask_set_nw_proto(struct flow *mask)
{
    mask->nw_proto = 0xff;
}

static inline void
of_mask_clr_nw_proto(struct flow *mask)
{
    mask->nw_proto = 0x0;
}

static inline int 
of_get_data_len(void *h)
{
    return ntohs(((struct ofp_header *)h)->length);
}

static inline bool 
__of_hdr_valid(void *h_arg, int len)
{
    struct ofp_header *h = h_arg;
    return (len <= OFP_MAX_PAYLOAD &&
           (h->version == OFP_VERSION || h->version == OFP_VERSION_131) && 
            h->type < OFP_MAX_TYPE);
}

static inline bool 
of_hdr_valid(void *h_arg)
{
    return __of_hdr_valid(h_arg, of_get_data_len(h_arg));
}

struct of_flow_mod_params {
    void *app_owner;
    struct flow *flow;
    struct flow *mask;
    void *actions;
    size_t action_len;
    uint32_t wildcards;
    uint32_t buffer_id;
    uint16_t prio;
    uint16_t itimeo; 
    uint16_t htimeo;
    uint32_t oport;
    uint8_t flags;
    uint8_t reason;
    uint16_t command;
    uint32_t ogroup;
};

struct of_group_mod_params {
    void *app_owner;
    uint32_t group;
    uint8_t type;
#define OF_MAX_ACT_VECTORS (16)
    struct of_act_vec_elem *act_vectors[OF_MAX_ACT_VECTORS];
    size_t act_vec_len;
};

struct of_pkt_out_params {
    uint32_t buffer_id;
    uint32_t in_port;
    uint16_t action_len;
    void *action_list;
    void *data;
    uint16_t data_len;
    uint8_t pad[2];
};  

struct c_ofp_ctors {
    struct cbuf *(*hello)(void);
    struct cbuf *(*echo_req)(void);
    struct cbuf *(*echo_rsp)(uint32_t xid);
    struct cbuf *(*set_config)(uint16_t flags, uint16_t miss_len);
    struct cbuf *(*features)(void);
    struct cbuf *(*pkt_out)(struct of_pkt_out_params *parms);
    void (*pkt_out_fast)(void *arg, struct of_pkt_out_params *parms);
    struct cbuf *(*flow_add)(const struct flow *flow,
                             const struct flow *mask,
                             uint32_t buffer_id, void *actions,
                             size_t actions_len, uint16_t i_timeo,
                             uint16_t h_timeo,
                             uint16_t prio);
    struct cbuf *(*flow_del)(const struct flow *flow,
                             const struct flow *mask,
                             uint32_t oport, bool strict,
                             uint16_t prio, uint32_t group);
    struct cbuf *(*flow_stat_req)(const struct flow *flow,
                                  const struct flow *mask,
                                  uint32_t oport, uint32_t group);
    bool (*group_validate)(bool add, uint32_t group, uint8_t type,
                           struct of_act_vec_elem *act_vectors[],
                           size_t act_vec_len);
    struct cbuf *(*group_add)(uint32_t group, uint8_t type,
                              struct of_act_vec_elem *act_vectors[],
                              size_t act_vec_len);
    struct cbuf *(*group_del)(uint32_t group);
    struct cbuf *(*port_mod)(void); /* FIXME */
    struct cbuf *(*tbl_mod)(void);  /* FIXME */
    struct cbuf *(*meter_mod)(void);  /* FIXME */

    /* Action Ctors */

    size_t (*act_init)(struct mul_act_mdata *mdata, uint16_t act_type);
    void   (*act_fini)(struct mul_act_mdata *mdata);
    size_t (*inst_goto)(struct mul_act_mdata *mdata, uint8_t table_id);
    size_t (*act_output)(struct mul_act_mdata *mdata, uint32_t oport);
    size_t (*act_set_vid)(struct mul_act_mdata *mdata, uint16_t vid);
    size_t (*act_strip_vid)(struct mul_act_mdata *mdata);
    size_t (*act_set_dmac)(struct mul_act_mdata *mdata, uint8_t *dmac);
    size_t (*act_set_smac)(struct mul_act_mdata *mdata, uint8_t *dmac);
    size_t (*act_set_nw_saddr)(struct mul_act_mdata *mdata, uint32_t nw_saddr);
    size_t (*act_set_nw_daddr)(struct mul_act_mdata *mdata, uint32_t nw_daddr);
    size_t (*act_set_vlan_pcp)(struct mul_act_mdata *mdata, uint8_t vlan_pcp);
    size_t (*act_set_nw_tos)(struct mul_act_mdata *mdata, uint8_t tos);
    size_t (*act_set_tp_udp_dport)(struct mul_act_mdata *mdata, uint16_t port);
    size_t (*act_set_tp_udp_sport)(struct mul_act_mdata *mdata, uint16_t port);
    size_t (*act_set_tp_tcp_dport)(struct mul_act_mdata *mdata, uint16_t port);
    size_t (*act_set_tp_tcp_sport)(struct mul_act_mdata *mdata, uint16_t port);
    size_t (*act_set_group)(struct mul_act_mdata *mdata, uint32_t group);

    int (*validate_acts)(void *actions, size_t action_len);
    int (*normalize_flow)(struct flow *flow, struct flow *mask);

    /* Dump Helpers */
    char *(*dump_flow)(struct flow *fl, struct flow *mask);
    char *(*dump_acts)(void *actions, size_t action_len, bool acts_only);

    /* Supported features */
    bool (*multi_table_support)(uint8_t n_tables, uint8_t table_id);
};
typedef struct c_ofp_ctors c_ofp_ctors_t;
void of_mact_alloc(mul_act_mdata_t *mdata);
void of_mact_free(mul_act_mdata_t *mdata);
char *of_dump_flow_generic(struct flow *fl, struct flow *mask);
char *of_dump_flow_all(struct flow *fl);
void *of_prep_msg_common(uint8_t ver, size_t len, uint8_t type, uint32_t xid);
size_t of_make_action_output(mul_act_mdata_t *mdata, uint32_t oport);
size_t of_make_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid);
size_t of_make_action_strip_vlan(mul_act_mdata_t *mdata);
size_t of_make_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac);
size_t of_make_action_set_nw_saddr(mul_act_mdata_t *mdata, uint32_t nw_saddr);
size_t of_make_action_set_nw_daddr(mul_act_mdata_t *mdata, uint32_t nw_saddr);
size_t of_make_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp);
size_t of_make_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac);
size_t of_make_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos);
size_t of_make_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port);
size_t of_make_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port);
size_t of_make_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port);
size_t of_make_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port);
struct ofp_inst_parser_arg *of10_parse_actions(void *actions, size_t action_len,
                                               struct ofp_inst_parsers *inst_parsers,
                                               struct ofp_act_parsers *act_parsers,
                                               void *u_arg);
char *of_dump_actions(void *actions, size_t action_len);
char *of10_dump_actions(void *actions, size_t action_len, bool acts_only);
char *of_dump_flow(struct flow *fl, uint32_t wildcards);
char *of10_dump_flow(struct flow *fl, struct flow *mask);
int of_flow_correction(struct flow *fl, uint32_t *wildcards);
int of10_flow_correction(struct flow *fl, struct flow *mask);
int of_validate_actions(void *actions, size_t action_len);
char *of_dump_wildcards(uint32_t wildcards);
void *of_prep_msg(size_t len, uint8_t type, uint32_t xid);
struct cbuf *of_prep_hello(void);
struct cbuf *of_prep_echo(void);
struct cbuf *of_prep_echo_reply(uint32_t xid);
struct cbuf *of_prep_features_request(void);
struct cbuf *of_prep_set_config(uint16_t flags, uint16_t miss_len);
struct cbuf *of_prep_flow_mod(uint16_t command, const struct flow *flow, 
                              const struct flow *mask, size_t actions_len);
struct cbuf *of_prep_flow_add_msg(const struct flow *flow, 
                                  const struct flow *mask,
                                  uint32_t buffer_id,
                                  void *actions, size_t actions_len, 
                                  uint16_t i_timeo, uint16_t h_timeo, 
                                  uint16_t prio);
struct cbuf *of_prep_flow_del_msg(const struct flow *flow, 
                                  const struct flow *mask,
                                  uint32_t oport,
                                  bool strict, uint16_t prio,
                                  uint32_t group);
struct cbuf *of_prep_pkt_out_msg(struct of_pkt_out_params *parms);
struct cbuf *of_prep_flow_stat_msg(const struct flow *flow, 
                                   const struct flow *mask,
                                   uint32_t oport,
                                   uint32_t group);
uint32_t of10_mask_to_wc(const struct flow *mask);
void of10_wc_to_mask(uint32_t wildcards, struct flow *mask);

struct cbuf *of131_prep_hello_msg(void);
struct cbuf *of131_prep_echo_msg(void);
struct cbuf *of131_prep_echo_reply_msg(uint32_t xid);
struct cbuf *of131_prep_features_request_msg(void);
struct cbuf *of131_prep_pkt_out_msg(struct of_pkt_out_params *parms);
struct cbuf *of131_prep_flow_add_msg(const struct flow *flow,
                                     const struct flow *mask,
                                     uint32_t buffer_id, void *ins_list,
                                     size_t ins_len, uint16_t i_timeo,
                                     uint16_t h_timeo, uint16_t prio);
struct cbuf *of131_prep_mpart_msg(uint16_t type, uint16_t flags, size_t len);
struct cbuf *of131_prep_flow_del_msg(const struct flow *flow,
                                     const struct flow *mask,
                                     uint32_t oport, bool strict,
                                     uint16_t prio, uint32_t group);
struct cbuf *of131_prep_flow_stat_msg(const struct flow *flow,
                                      const struct flow *mask,
                                      uint32_t eoport,
                                      uint32_t group);
struct cbuf *of131_prep_group_add_msg(uint32_t group, uint8_t type,
                                      struct of_act_vec_elem *act_vectors[],
                                      size_t act_vec_len);
struct cbuf *of131_prep_group_del_msg(uint32_t group);
bool of131_group_validate(bool add, uint32_t group, uint8_t type,
                          struct of_act_vec_elem *act_vectors[],
                          size_t act_vec_len);
int of131_ofpx_match_to_flow(struct ofpx_match *ofx,
                             struct flow *flow, struct flow *mask);
struct cbuf *of131_prep_set_config_msg(uint16_t flags, uint16_t miss_len);
size_t of131_make_inst_actions(mul_act_mdata_t *mdata, uint16_t type);
void of131_fini_inst_actions(mul_act_mdata_t *mdata);
size_t of131_make_inst_goto(mul_act_mdata_t *mdata, uint8_t tbl_id);
size_t of131_make_action_output(mul_act_mdata_t *mdata, uint32_t oport);
size_t of131_make_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid);
size_t of131_make_action_strip_vlan(mul_act_mdata_t *mdata);
size_t of131_make_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp);
size_t of131_make_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac);
size_t of131_make_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac);
size_t of131_make_action_set_ipv4_src(mul_act_mdata_t *mdata, uint32_t nw_saddr);
size_t of131_make_action_set_ipv4_dst(mul_act_mdata_t *mdata, uint32_t nw_daddr);
size_t of131_make_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos);
size_t of131_make_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port);
size_t of131_make_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port);
size_t of131_make_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port);
size_t of131_make_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port);
size_t of131_make_action_group(mul_act_mdata_t *mdata, uint32_t group);
void of131_parse_actions(void *actions, size_t act_len,
                         void *parse_ctx);
void of131_parse_act_set_field_tlv(struct ofp_action_set_field *ofp_sf,
                              struct ofp_act_parsers *act_parsers,
                              void *parse_ctx);
struct ofp_inst_parser_arg *of131_parse_instructions(void *inst_list, size_t inst_len,
                                struct ofp_inst_parsers *inst_handlers,
                                struct ofp_act_parsers *act_handlers,
                                void *u_arg, bool acts_only);
char *of131_dump_actions(void *inst_list, size_t inst_len, bool acts_only);
bool of131_supports_multi_tables(uint8_t n_tables, uint8_t table_id);

#endif
