/*
 *  mul_of_msg.c: MUL openflow message handling 
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
#include "random.h"

C_RL_DEFINE(rl, 100, 100);

static uint8_t zero_mac_addr[OFP_ETH_ALEN] = { 0, 0, 0, 0, 0, 0};

static void *
of_inst_parser_alloc(void *u_arg, struct ofp_inst_parsers *parsers,
                     struct ofp_act_parsers *act_parsers)
{
    struct ofp_inst_parser_arg *ofp_dp = calloc(1, sizeof(*ofp_dp));

    assert(ofp_dp);

    ofp_dp->pbuf = calloc(1, OF_DUMP_INST_SZ);
    assert(ofp_dp->pbuf);

    ofp_dp->u_arg = u_arg;
    ofp_dp->parsers = parsers;
    ofp_dp->act_parsers = act_parsers;

    return ofp_dp;
}

static void
of_inst_parser_free(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    if (dp) {
        if (dp->pbuf) free(dp->pbuf);
        free(dp);
    }
}

static struct ofp_inst_parser_arg * 
of_inst_parser_fini(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    return dp;
}

static void
of_inst_parser_pre_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len,
                        OF_DUMP_INST_SZ - dp->len - 1,
                        "instructions: ");
    assert(dp->len < OF_DUMP_INST_SZ-1);
}

static void
of_inst_parser_post_proc(void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "\r\n");
    assert(dp->len < OF_DUMP_INST_SZ-1);
}

void
of_mact_alloc(mul_act_mdata_t *mdata)
{
    mdata->act_base = calloc(1, MUL_ACT_BUF_SZ);
    assert(mdata->act_base);
    of_mact_mdata_init(mdata, MUL_ACT_BUF_SZ);
}

void
of_mact_free(mul_act_mdata_t *mdata)
{
    if (mdata->act_base)
        free(mdata->act_base);
}

static void
of_check_realloc_act(mul_act_mdata_t *mdata, size_t  len)
{
    uint8_t *new_base;
    size_t old_room = of_mact_buf_room(mdata);

    if (old_room < len) {
        new_base = calloc(1, old_room + len);
        assert(new_base);
        memcpy(new_base, mdata->act_base, old_room);
        of_mact_free(mdata);
        mdata->act_base = new_base;
        mdata->act_wr_ptr = mdata->act_base + old_room;
        mdata->buf_len = old_room + len;
    }
}

size_t
of_make_action_output(mul_act_mdata_t *mdata, uint32_t eoport)
{
    struct ofp_action_output *op_act;
    uint16_t oport;

    if (eoport == OF_ALL_PORTS) {
        oport = OFPP_ALL;
    } else if (eoport == OF_SEND_IN_PORT) {
        oport = OFPP_IN_PORT;
    } else {
        oport = (uint16_t)(eoport);
    }

    of_check_realloc_act(mdata, sizeof(*op_act));

    oport = oport?: OFPP_CONTROLLER;
    
    op_act = (void *)(mdata->act_wr_ptr);

    op_act->type = htons(OFPAT_OUTPUT);
    op_act->len  = htons(sizeof(*op_act));
    op_act->port = htons(oport);

    mdata->act_wr_ptr += (sizeof(*op_act));
    return (sizeof(*op_act));
}

size_t
of_make_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid)
{
    struct ofp_action_vlan_vid *vid_act;

    of_check_realloc_act(mdata, sizeof(*vid_act));
    
    vid_act = (void *)(mdata->act_wr_ptr);
    vid_act->type = htons(OFPAT_SET_VLAN_VID);
    vid_act->len  = htons(sizeof(*vid_act));
    vid_act->vlan_vid = htons(vid);

    mdata->act_wr_ptr += sizeof(*vid_act);
    return (sizeof(*vid_act));
}

size_t
of_make_action_strip_vlan(mul_act_mdata_t *mdata)
{
    struct ofp_action_header *vid_strip_act;

    of_check_realloc_act(mdata, sizeof(*vid_strip_act));
    
    vid_strip_act = (void *)(mdata->act_wr_ptr);
    vid_strip_act->type = htons(OFPAT_STRIP_VLAN);
    vid_strip_act->len  = htons(sizeof(*vid_strip_act));

    mdata->act_wr_ptr += sizeof(*vid_strip_act);
    return (sizeof(*vid_strip_act));
}

size_t
of_make_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac)
{
    struct ofp_action_dl_addr *dmac_act;

    of_check_realloc_act(mdata, sizeof(*dmac_act));

    dmac_act = (void *)(mdata->act_wr_ptr);

    dmac_act->type = htons(OFPAT_SET_DL_DST);
    dmac_act->len  = htons(sizeof(*dmac_act));
    memcpy(dmac_act->dl_addr, dmac, OFP_ETH_ALEN);

    mdata->act_wr_ptr += sizeof(*dmac_act);
    return (sizeof(*dmac_act));
}

size_t
of_make_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac)
{
    struct ofp_action_dl_addr *smac_act;

    of_check_realloc_act(mdata, sizeof(*smac_act));

    smac_act = (void *)(mdata->act_wr_ptr);
    smac_act->type = htons(OFPAT_SET_DL_SRC);
    smac_act->len  = htons(sizeof(*smac_act));
    memcpy(smac_act->dl_addr, smac, OFP_ETH_ALEN);

    mdata->act_wr_ptr += sizeof(*smac_act);
    return (sizeof(*smac_act));
}

size_t
of_make_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp)
{
    struct ofp_action_vlan_pcp *vpcp_act;

    of_check_realloc_act(mdata, sizeof(*vpcp_act));

    vpcp_act = (void *)(mdata->act_wr_ptr);
    vpcp_act->type = htons(OFPAT_SET_VLAN_PCP);
    vpcp_act->len = htons(sizeof(*vpcp_act));
    vpcp_act->vlan_pcp = (vlan_pcp & 0x7);

    mdata->act_wr_ptr += sizeof(*vpcp_act);
    return (sizeof(*vpcp_act));
}

static size_t
of_make_action_set_nw_ip(mul_act_mdata_t *mdata, uint32_t ip, 
                         uint16_t type)
{
    struct ofp_action_nw_addr *nw_addr_act;

    of_check_realloc_act(mdata, sizeof(*nw_addr_act));

    nw_addr_act = (void *)(mdata->act_wr_ptr);
    nw_addr_act->type = htons(type);
    nw_addr_act->len  = htons(sizeof(*nw_addr_act));
    nw_addr_act->nw_addr = htonl(ip);

    mdata->act_wr_ptr += sizeof(*nw_addr_act);
    return (sizeof(*nw_addr_act));
}

size_t
of_make_action_set_nw_saddr(mul_act_mdata_t *mdata, uint32_t nw_saddr) 
{
    return of_make_action_set_nw_ip(mdata, nw_saddr, OFPAT_SET_NW_SRC); 
}

size_t
of_make_action_set_nw_daddr(mul_act_mdata_t *mdata, uint32_t nw_daddr) 
{
    return of_make_action_set_nw_ip(mdata, nw_daddr, OFPAT_SET_NW_DST); 
}

size_t
of_make_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos) 
{
    struct ofp_action_nw_tos *nw_tos_act;

    of_check_realloc_act(mdata, sizeof(*nw_tos_act));

    nw_tos_act = (void *)(mdata->act_wr_ptr);
    nw_tos_act->type = htons(OFPAT_SET_NW_TOS);
    nw_tos_act->len  = htons(sizeof(*nw_tos_act));
    nw_tos_act->nw_tos = tos & ((0x1<<7) - 1);

    mdata->act_wr_ptr += sizeof(*nw_tos_act);
    return (sizeof(*nw_tos_act));
}

static size_t
of_make_action_set_tp_port(mul_act_mdata_t *mdata, uint8_t ip_proto UNUSED,
                           bool is_src, uint16_t port)
{
    struct ofp_action_tp_port *tp_port_act;
    uint16_t type = is_src ? OFPAT_SET_TP_SRC : OFPAT_SET_TP_DST;

    of_check_realloc_act(mdata, sizeof(*tp_port_act));

    tp_port_act = (void *)(mdata->act_wr_ptr);
    tp_port_act->type = htons(type);
    tp_port_act->len  = htons(sizeof(*tp_port_act));
    tp_port_act->tp_port = htons(port);

    mdata->act_wr_ptr += sizeof(*tp_port_act);
    return (sizeof(*tp_port_act));
}

size_t
of_make_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of_make_action_set_tp_port(mdata, IP_TYPE_UDP, true, port);
}

size_t
of_make_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of_make_action_set_tp_port(mdata, IP_TYPE_UDP, false, port);
}

size_t
of_make_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of_make_action_set_tp_port(mdata, IP_TYPE_TCP, true, port);
}

size_t
of_make_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of_make_action_set_tp_port(mdata, IP_TYPE_TCP, false, port);
}

char *
of_dump_wildcards(uint32_t wildcards)
{
    uint32_t                 nw_dst_mask, nw_src_mask;   
    char                     *pbuf;
    size_t                   len = 0;
    uint32_t                 ip_wc;

    pbuf = calloc(1, OF_DUMP_WC_SZ);
    assert(pbuf);

    wildcards = ntohl(wildcards);

    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = ip_wc >= 32 ? 0 : 
                           make_inet_mask(32-ip_wc); 

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = ip_wc >= 32 ? 0 : 
                           make_inet_mask(32-ip_wc);
    
    /* Reduce this to a line please.... */
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "Wildcards:\r\n");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "smac", (wildcards & OFPFW_DL_SRC) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "dmac", (wildcards & OFPFW_DL_DST) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "eth-type", (wildcards & OFPFW_DL_TYPE) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "vlan-id", (wildcards & OFPFW_DL_VLAN) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "vlan-pcp", (wildcards & OFPFW_DL_VLAN_PCP) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: 0x%08x\r\n",
                    "dst-ip-mask", nw_dst_mask);
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: 0x%08x\r\n",
                    "src-ip-mask", nw_src_mask);
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "ip-proto", (wildcards & OFPFW_NW_PROTO) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "src-port", (wildcards & OFPFW_TP_SRC) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "dst-port", (wildcards & OFPFW_TP_DST) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "in-port", (wildcards & OFPFW_IN_PORT) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);

    return pbuf;
}

char *
of_dump_flow_all(struct flow *fl)
{
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow tuple:\r\n");
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%-10s:%02x:%02x:%02x:%02x:%02x:%02x\r\n"
                   "%-10s:%02x:%02x:%02x:%02x:%02x:%02x\r\n",
                   "smac", fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5],
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%-10s:0x%04x\r\n%-10s:0x%04x\r\n%-10s:0x%04x\r\n",
                     "eth-type", ntohs(fl->dl_type),
                     "vlan-id",  ntohs(fl->dl_vlan),
                     "vlan-pcp", ntohs(fl->dl_vlan_pcp));
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%-10s:0x%08x\r\n%-10s:0x%08x\r\n%-10s:0x%02x\r\n%-10s:0x%x\r\n",
                     "dest-ip", ntohl(fl->nw_dst),
                     "src-ip", ntohl(fl->nw_src),
                     "ip-proto", fl->nw_proto,
                     "ip-tos", fl->nw_tos);
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%-10s:0x%04x\r\n%-10s:0x%04x\r\n%-10s:0x%x\r\n",
                    "src-port", ntohs(fl->tp_src),
                    "dst-port", ntohs(fl->tp_dst),
                    "in-port", ntohs(fl->in_port));

    return pbuf;
}


struct ofp_inst_parser_arg *
of10_parse_actions(void *actions, size_t action_len,
                   struct ofp_inst_parsers *inst_parsers, 
                   struct ofp_act_parsers *act_parsers,
                   void *u_arg)                            
{
    struct ofp_action_header *hdr;
    void *parse_ctx;
    uint16_t act_type;
    size_t parsed_len = 0;

    if (!act_parsers || !inst_parsers ) {
        c_log_err("%s: No parser specified", FN);
        return NULL;
    }

    parse_ctx = inst_parsers->prep_inst_parser(u_arg, inst_parsers, 
                                               act_parsers);
    if (!action_len) {
        if (inst_parsers->no_inst) {
            inst_parsers->no_inst(parse_ctx);
            goto done;
        }
    }

    if (inst_parsers->pre_proc)
        inst_parsers->pre_proc(parse_ctx);

    while (action_len) {
        hdr =  (struct ofp_action_header *)actions;
        act_type = ntohs(hdr->type);
        switch (act_type) {
        case OFPAT_OUTPUT:
            if (act_parsers->act_output)
                act_parsers->act_output(hdr, parse_ctx); 
            parsed_len += sizeof(struct ofp_action_output);
            break;
        case OFPAT_SET_VLAN_VID:
            if (act_parsers->act_set_vlan)
                act_parsers->act_set_vlan(hdr, parse_ctx);
            parsed_len += sizeof(struct ofp_action_vlan_vid);
            break;
        case OFPAT_SET_DL_DST:
            if (act_parsers->act_set_dl_dst)
                act_parsers->act_set_dl_dst(hdr, parse_ctx);
            parsed_len += sizeof(struct ofp_action_dl_addr);
            break;
        case OFPAT_SET_DL_SRC:
            if (act_parsers->act_set_dl_src)
                act_parsers->act_set_dl_src(hdr, parse_ctx);
            parsed_len += sizeof(struct ofp_action_dl_addr);
            break;    
        case OFPAT_SET_VLAN_PCP:
            if (act_parsers->act_set_vlan_pcp)
                act_parsers->act_set_vlan_pcp(hdr, parse_ctx);
            parsed_len += sizeof(struct ofp_action_vlan_pcp);
            break;
        case OFPAT_STRIP_VLAN:
            if (act_parsers->act_pop_vlan)
                act_parsers->act_pop_vlan(hdr, parse_ctx);
            parsed_len += sizeof(struct ofp_action_header);
            break;
        case OFPAT_SET_NW_SRC:
            if (act_parsers->act_set_nw_src)
                act_parsers->act_set_nw_src(hdr, parse_ctx);
            parsed_len += sizeof(struct ofp_action_nw_addr);
            break;
        case OFPAT_SET_NW_DST:
            if (act_parsers->act_set_nw_dst)
                act_parsers->act_set_nw_dst(hdr, parse_ctx);
            parsed_len += sizeof(struct ofp_action_nw_addr);
            break;
        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST:
            /* FIXME */
            parsed_len += sizeof(struct ofp_action_tp_port);
            break;
        default:
            c_log_err("%s:unhandled action %u", FN, act_type);
            goto done;
        }

        action_len -= parsed_len;
        actions = INC_PTR8(actions, parsed_len);
    }
done:
    if (inst_parsers->post_proc)
        inst_parsers->post_proc(parse_ctx);

    if (inst_parsers->fini_inst_parser)
        inst_parsers->fini_inst_parser(parse_ctx);

    return parse_ctx;
}

static int 
of_validate_act_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_output *op_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    if (!ntohs(op_act->port)) {
        dp->res = -1;
    }

    return sizeof(*op_act);
}

static int 
of_dump_act_out(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_output *of_ao = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-Port(%u),",
                        "act-output", ntohs(of_ao->port));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int 
of_dump_act_set_vlan(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_vid *vid_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-vid 0x%04x,", "set-vid",
                        ntohs(vid_act->vlan_vid));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*vid_act);
}

static int 
of_dump_act_set_vlan_pcp(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_vlan_pcp *vlan_pcp_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s 0x%04x,", "set-vlan-pcp", vlan_pcp_act->vlan_pcp);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*vlan_pcp_act);
}

static int 
of_dump_act_set_nw_dst(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_addr *nw_addr_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s 0x%08x,", "set-nw-dst", ntohl(nw_addr_act->nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_addr_act);
}

static int 
of_dump_act_set_nw_src(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_nw_addr *nw_addr_act= (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s 0x%08x,", "set-nw-src", ntohl(nw_addr_act->nw_addr));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*nw_addr_act);
}

static int 
of_dump_act_set_dl_dst(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_dl_addr *dmac_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-%02x:%02x:%02x:%02x:%02x:%02x,",
                        "set-dmac", dmac_act->dl_addr[0], dmac_act->dl_addr[1],
                        dmac_act->dl_addr[2], dmac_act->dl_addr[3],
                        dmac_act->dl_addr[4], dmac_act->dl_addr[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*dmac_act);
}

static int 
of_dump_act_set_dl_src(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_dl_addr *smac_act = (void *)action;
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-%02x:%02x:%02x:%02x:%02x:%02x,",
                        "set-smac", smac_act->dl_addr[0], smac_act->dl_addr[1],
                        smac_act->dl_addr[2], smac_act->dl_addr[3],
                        smac_act->dl_addr[4], smac_act->dl_addr[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return sizeof(*smac_act);
}

struct ofp_act_parsers of10_dump_act_parsers = {
    .act_output = of_dump_act_out,
    .act_set_vlan = of_dump_act_set_vlan,
    .act_set_vlan_pcp = of_dump_act_set_vlan_pcp,
    .act_set_dl_dst = of_dump_act_set_dl_dst,
    .act_set_dl_src = of_dump_act_set_dl_src, 
    .act_set_nw_src = of_dump_act_set_nw_src,
    .act_set_nw_dst = of_dump_act_set_nw_dst
};

struct ofp_inst_parsers of10_dump_inst_parsers = {
    .prep_inst_parser = of_inst_parser_alloc,
    .pre_proc = of_inst_parser_pre_proc,
    .post_proc = of_inst_parser_post_proc,
    .fini_inst_parser = of_inst_parser_fini,
};

char *
of10_dump_actions(void *actions, size_t action_len, bool acts_only UNUSED)
{
    struct ofp_inst_parser_arg *dp;
    char *pbuf = NULL;

    dp = of10_parse_actions(actions, action_len,
                            &of10_dump_inst_parsers,
                            &of10_dump_act_parsers, NULL);
    pbuf =  dp && dp->pbuf ? dp->pbuf : NULL;
    if (dp) free(dp);
    return pbuf;
}

struct ofp_act_parsers of10_validate_act_parsers = {
    .act_output = of_validate_act_out,
};

struct ofp_inst_parsers of10_cmn_inst_parsers = {
    .prep_inst_parser = of_inst_parser_alloc,
    .fini_inst_parser = of_inst_parser_fini,
};

int
of_validate_actions(void *actions, size_t action_len)
{
    struct ofp_inst_parser_arg *dp;
    int ret = -1;

    dp = of10_parse_actions(actions, action_len,
                            &of10_dump_inst_parsers,
                            &of10_dump_act_parsers, NULL);
    ret =  dp ? dp->res : -1;
    of_inst_parser_free(dp);

    return ret;
}

char *
of_dump_flow(struct flow *fl, uint32_t wildcards)
{
#define FL_PBUF_SZ 4096
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;
    uint32_t nw_dst_mask, nw_src_mask;
    uint32_t dip_wc, sip_wc;
    struct in_addr in_addr;

    wildcards = ntohl(wildcards);
    dip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = dip_wc >= 32 ? 0 :
                           make_inet_mask(32-dip_wc);

    sip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = sip_wc >= 32 ? 0 :
                           make_inet_mask(32-sip_wc);

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow: ");
    assert(len < FL_PBUF_SZ-1);

    if (wildcards == OFPFW_ALL) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "All Fields Wildcards");
        assert(len < FL_PBUF_SZ-1);
        return pbuf;
    }

    if (!(wildcards & OFPFW_DL_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "smac", fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5]);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "eth-type", ntohs(fl->dl_type));
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_VLAN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-id",  ntohs(fl->dl_vlan));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_VLAN_PCP)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-pcp", fl->dl_vlan_pcp);
        assert(len < FL_PBUF_SZ-1);

    }
    if (nw_dst_mask) {
        in_addr.s_addr = fl->nw_dst & htonl(nw_dst_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:%s/%d ",
                     "dst-ip", inet_ntoa(in_addr),
                     dip_wc >= 32 ? 0 : 32 - dip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (nw_src_mask) {
        in_addr.s_addr = fl->nw_src & htonl(nw_src_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                     "%s:%s/%d ", 
                     "src-ip", inet_ntoa(in_addr),
                     sip_wc >= 32 ? 0 : 32-sip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_PROTO)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-proto", fl->nw_proto);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_TOS)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-tos", fl->nw_tos);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "src-port", ntohs(fl->tp_src));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "dst-port", ntohs(fl->tp_dst));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_IN_PORT)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "in-port", ntohs(fl->in_port));
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "\r\n");

    return pbuf;
}

char *
of10_dump_flow(struct flow *fl, struct flow *mask)
{
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;
    uint32_t nw_dst_mask, nw_src_mask;
    uint32_t dip_wc, sip_wc;
    struct in_addr in_addr;
    uint32_t wildcards = 0;

    wildcards = ntohl(of10_mask_to_wc(mask));
    dip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = dip_wc >= 32 ? 0 :
                           make_inet_mask(32-dip_wc);

    sip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = sip_wc >= 32 ? 0 :
                           make_inet_mask(32-sip_wc);

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow: ");
    assert(len < FL_PBUF_SZ-1);

    if (wildcards == OFPFW_ALL) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "All Fields Wildcards");
        assert(len < FL_PBUF_SZ-1);
        return pbuf;
    }

    if (!(wildcards & OFPFW_DL_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "smac", fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5]);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "eth-type", ntohs(fl->dl_type));
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_VLAN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-id",  ntohs(fl->dl_vlan));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_VLAN_PCP)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-pcp", fl->dl_vlan_pcp);
        assert(len < FL_PBUF_SZ-1);

    }
    if (nw_dst_mask) {
        in_addr.s_addr = fl->nw_dst & htonl(nw_dst_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:%s/%d ",
                     "dst-ip", inet_ntoa(in_addr),
                     dip_wc >= 32 ? 0 : 32 - dip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (nw_src_mask) {
        in_addr.s_addr = fl->nw_src & htonl(nw_src_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                     "%s:%s/%d ", 
                     "src-ip", inet_ntoa(in_addr),
                     sip_wc >= 32 ? 0 : 32-sip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_PROTO)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-proto", fl->nw_proto);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_TOS)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-tos", fl->nw_tos);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "src-port", ntohs(fl->tp_src));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "dst-port", ntohs(fl->tp_dst));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_IN_PORT)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "in-port", ntohs(fl->in_port));
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "\r\n");

    return pbuf;
}

char *
of_dump_flow_generic(struct flow *fl, struct flow *mask)
{
    char *pbuf = calloc(1, FL_PBUF_SZ);
    int len = 0;
    struct in_addr in_addr, in_mask;
    int i = 0;

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow: ");
    assert(len < FL_PBUF_SZ-1);

    if (memcmp(mask->dl_src, zero_mac_addr, OFP_ETH_ALEN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, " smac:");
        assert(len < FL_PBUF_SZ-1);
        for (i = 0; i < OFP_ETH_ALEN; i++) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "%02x:",
                            fl->dl_src[i] & mask->dl_src[i]);
            assert(len < FL_PBUF_SZ-1);
        }
    }
    if (memcmp(mask->dl_dst, zero_mac_addr, OFP_ETH_ALEN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, " dmac:");
        assert(len < FL_PBUF_SZ-1);
        for (i = 0; i < OFP_ETH_ALEN; i++) {
            len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "%02x:",
                            fl->dl_dst[i] & mask->dl_dst[i]);
            assert(len < FL_PBUF_SZ-1);
        }
    }

    if (mask->dl_type) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%s:0x%x ", " eth-type", ntohs(fl->dl_type));
        assert(len < FL_PBUF_SZ-1);
    }
    if (mask->dl_vlan) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%s:0x%x ", " vlan-id", ntohs(fl->dl_vlan));
        assert(len < FL_PBUF_SZ-1);
    }

    if (mask->dl_vlan_pcp) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                        "%s:0x%x ", " vlan-pcp", fl->dl_vlan_pcp);
        assert(len < FL_PBUF_SZ-1);

    }
    if (mask->nw_dst) {
        in_addr.s_addr = fl->nw_dst & mask->nw_dst;
        in_mask.s_addr = mask->nw_dst;
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                "%s:%s (0x%04x) ", " dst-ip",
                inet_ntoa(in_addr), ntohl(in_mask.s_addr));
        assert(len < FL_PBUF_SZ-1);
    }
    if (mask->nw_src) {
        in_addr.s_addr = fl->nw_src & mask->nw_src;
        in_mask.s_addr = mask->nw_src;
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                "%s:%s (0x%04x) ", " src-ip", 
                inet_ntoa(in_addr), ntohl(in_mask.s_addr));
        assert(len < FL_PBUF_SZ-1);
    }

    if (mask->nw_proto) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ", " ip-proto", fl->nw_proto);
        assert(len < FL_PBUF_SZ-1);
    }
    if (mask->nw_tos) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ", " ip-tos", fl->nw_tos);
        assert(len < FL_PBUF_SZ-1);
    }

    if (mask->tp_src) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ", " src-port", ntohs(fl->tp_src));
        assert(len < FL_PBUF_SZ-1);
    }

    if (mask->tp_dst) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ", " dst-port", ntohs(fl->tp_dst));
        assert(len < FL_PBUF_SZ-1);
    }

    if (mask->in_port) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ", " in-port", ntohl(fl->in_port));
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "\r\n");
    return pbuf;
}

int
of10_flow_correction(struct flow *fl, struct flow *mask)
{
    uint16_t eth_proto;
    uint32_t wildcards;
    uint32_t ip_wc;

    if (!fl || !mask) return -1;

    wildcards = ntohl(of10_mask_to_wc(mask));

    if (!(wildcards & OFPFW_IN_PORT) &&
        (!fl->in_port)) {
        return -1;    
    }

    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    if (ip_wc >= 32) {
        wildcards &= ~OFPFW_NW_DST_MASK;
        wildcards |= OFPFW_NW_DST_ALL;
    }

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    if (ip_wc >= 32) {
        wildcards &= ~OFPFW_NW_SRC_MASK;
        wildcards |= OFPFW_NW_SRC_ALL;
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        eth_proto = ntohs(fl->dl_type);

        if (eth_proto == ETH_TYPE_ARP) {
            fl->nw_proto = 0;
            fl->nw_tos = 0;
            fl->tp_src = 0;
            fl->tp_dst = 0;
            wildcards |= OFPFW_NW_PROTO | OFPFW_NW_TOS |
                         OFPFW_TP_DST | OFPFW_TP_SRC;
        } else if (eth_proto == ETH_TYPE_IP) {
            if (wildcards & OFPFW_NW_PROTO) {
                fl->tp_src = 0;
                fl->tp_dst = 0;
                wildcards |= OFPFW_TP_DST | OFPFW_TP_SRC;
            }
        } else {
            fl->tp_src = 0;
            fl->tp_dst = 0;
            fl->nw_src = 0;
            fl->nw_dst = 0;
            fl->nw_tos = 0;
            fl->nw_proto = 0;
            wildcards |= OFPFW_NW_DST_ALL | OFPFW_NW_SRC_ALL | OFPFW_NW_PROTO |
                         OFPFW_NW_TOS | OFPFW_TP_DST | OFPFW_TP_SRC;
        }
    } else {
        fl->tp_src = 0;
        fl->tp_dst = 0;
        fl->nw_src = 0;
        fl->nw_dst = 0;
        fl->nw_tos = 0;
        fl->nw_proto = 0;
        wildcards |= OFPFW_NW_DST_ALL | OFPFW_NW_SRC_ALL | OFPFW_NW_PROTO |
                     OFPFW_NW_TOS | OFPFW_TP_DST | OFPFW_TP_SRC;
    }

    of10_wc_to_mask(htonl(wildcards), mask);

    return 0;
}


int
of_flow_correction(struct flow *fl, uint32_t *wc)
{
    uint16_t eth_proto;
    uint32_t wildcards;
    uint32_t ip_wc;

    if (!fl || !wc) return -1;

    wildcards = ntohl(*wc);

    if (!(wildcards & OFPFW_IN_PORT) &&
        (!fl->in_port)) {
        return -1;    
    }

    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    if (ip_wc >= 32) {
        wildcards &= ~OFPFW_NW_DST_MASK;
        wildcards |= OFPFW_NW_DST_ALL;
    }

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    if (ip_wc >= 32) {
        wildcards &= ~OFPFW_NW_SRC_MASK;
        wildcards |= OFPFW_NW_SRC_ALL;
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        eth_proto = ntohs(fl->dl_type);

        if (eth_proto == ETH_TYPE_ARP) {
            fl->nw_proto = 0;
            fl->nw_tos = 0;
            fl->tp_src = 0;
            fl->tp_dst = 0;
            wildcards |= OFPFW_NW_PROTO | OFPFW_NW_TOS |
                         OFPFW_TP_DST | OFPFW_TP_SRC;
        } else if (eth_proto == ETH_TYPE_IP) {
            if (wildcards & OFPFW_NW_PROTO) {
                fl->tp_src = 0;
                fl->tp_dst = 0;
                wildcards |= OFPFW_TP_DST | OFPFW_TP_SRC;
            }
        } else {
            fl->tp_src = 0;
            fl->tp_dst = 0;
            fl->nw_src = 0;
            fl->nw_dst = 0;
            fl->nw_tos = 0;
            fl->nw_proto = 0;
            wildcards |= OFPFW_NW_DST_ALL | OFPFW_NW_SRC_ALL | OFPFW_NW_PROTO |
                         OFPFW_NW_TOS | OFPFW_TP_DST | OFPFW_TP_SRC;
        }
    } else {
        fl->tp_src = 0;
        fl->tp_dst = 0;
        fl->nw_src = 0;
        fl->nw_dst = 0;
        fl->nw_tos = 0;
        fl->nw_proto = 0;
        wildcards |= OFPFW_NW_DST_ALL | OFPFW_NW_SRC_ALL | OFPFW_NW_PROTO |
                     OFPFW_NW_TOS | OFPFW_TP_DST | OFPFW_TP_SRC;
    }

    *wc = htonl(wildcards);

    return 0;
}

static inline uint32_t
of_alloc_xid(void)
{
    return random_uint32();
}

void *__fastpath
of_prep_msg_common(uint8_t ver, size_t len, uint8_t type, uint32_t xid)
{
    struct cbuf *b;
    struct ofp_header *h;

    b = alloc_cbuf(len);
    h = cbuf_put(b, len);

    h->version = ver;
    h->type = type;
    h->length = htons(len);

    if (xid) {
        h->xid = xid;
    } else {
        h->xid = of_alloc_xid();
    }

    memset(h + 1, 0, len - sizeof(*h));

    return b;

}

void * __fastpath
of_prep_msg(size_t len, uint8_t type, uint32_t xid)
{
    return of_prep_msg_common(OFP_VERSION, len, type, xid);
}

static void * __fastpath
of131_prep_msg(size_t len, uint8_t type, uint32_t xid)
{
    return of_prep_msg_common(OFP_VERSION_131, len, type, xid);
}

struct cbuf *
of_prep_hello(void)
{
    return of_prep_msg(sizeof(struct ofp_header), OFPT_HELLO, 0);
}

struct cbuf *
of_prep_echo(void)
{
    return of_prep_msg(sizeof(struct ofp_header), OFPT_ECHO_REQUEST, 0);
}

struct cbuf *
of_prep_echo_reply(uint32_t xid)
{
    return of_prep_msg(sizeof(struct ofp_header), OFPT_ECHO_REPLY, xid);
}

struct cbuf *
of_prep_features_request(void)
{
    return of_prep_msg(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, 0);
}

struct cbuf *
of_prep_set_config(uint16_t flags, uint16_t miss_len)
{
    struct cbuf *b;
    struct ofp_switch_config *ofp_sc;

    /* Send OFPT_SET_CONFIG. */
    b = of_prep_msg(sizeof(struct ofp_switch_config), OFPT_SET_CONFIG, 0);
    ofp_sc = (void *)(b->data);
    ofp_sc->flags = htons(flags);
    ofp_sc->miss_send_len = htons(miss_len);

    return b;
}

uint32_t 
of10_mask_to_wc(const struct flow *mask)
{
    size_t pref_len;    
    uint32_t wildcards = 0;

    assert(mask);

    /* Mixed IP masks are not allowed */
    pref_len = c_count_one_bits(mask->nw_dst);
    if (pref_len) {
        wildcards |= ((32 - pref_len) & ((1 << OFPFW_NW_DST_BITS)-1))
                              << OFPFW_NW_DST_SHIFT;
    } else {
        wildcards |= OFPFW_NW_DST_ALL;
    }

    pref_len = c_count_one_bits(mask->nw_src);
    if (pref_len) {
        wildcards |= ((32 - pref_len) & ((1 << OFPFW_NW_SRC_BITS)-1))
                              << OFPFW_NW_SRC_SHIFT;
    } else {
        wildcards |= OFPFW_NW_SRC_ALL;
    }
    if (!(mask->in_port)) {
        wildcards |= OFPFW_IN_PORT;
    } 
    if (!(mask->dl_vlan)) {
        wildcards |= OFPFW_DL_VLAN;
    }
    if (!(mask->dl_vlan_pcp)) {
        wildcards |= OFPFW_DL_VLAN_PCP;
    }
    if (!(mask->dl_type)) {
        wildcards |= OFPFW_DL_TYPE;
    }
    if (!(mask->tp_src)) {
        wildcards |= OFPFW_TP_SRC;
    }
    if (!(mask->tp_dst)) {
        wildcards |= OFPFW_TP_DST;
    }
    if (!(mask->nw_tos)) {
        wildcards |= OFPFW_NW_TOS;
    }
    if (!(mask->nw_proto)) {
        wildcards |= OFPFW_NW_PROTO;
    }

    if (!memcmp(mask->dl_dst, zero_mac_addr, 6)) {
        wildcards |= OFPFW_DL_DST;
    }
    if (!memcmp(mask->dl_src, zero_mac_addr, 6)) {
        wildcards |= OFPFW_DL_SRC;
    }

    return htonl(wildcards);
}

void 
of10_wc_to_mask(uint32_t wildcards, struct flow *mask)
{
    size_t pref_len;    

    assert(mask);
    wildcards = ntohl(wildcards);
    memset(mask, 0xff, sizeof(*mask));

    /* Mixed IP masks are not allowed */
    if (wildcards & OFPFW_NW_DST_ALL) {
        pref_len = 0;
    } else {
        pref_len = 32 - ((wildcards >> OFPFW_NW_DST_SHIFT) & 
                        ((1 << OFPFW_NW_DST_BITS)-1));
    }
    mask->nw_dst = htonl(make_inet_mask(pref_len));

    if (wildcards & OFPFW_NW_SRC_ALL) {
        pref_len = 0;
    } else {
        pref_len = 32 - ((wildcards >> OFPFW_NW_SRC_SHIFT) & 
                        ((1 << OFPFW_NW_SRC_BITS)-1));
    }
    mask->nw_src = htonl(make_inet_mask(pref_len));

    if (wildcards & OFPFW_IN_PORT) {
        mask->in_port = 0;
    } 

    if (wildcards & OFPFW_DL_VLAN) {
        mask->dl_vlan = 0;
    }

    if (wildcards & OFPFW_DL_VLAN_PCP) {
        mask->dl_vlan_pcp = 0;
    }

    if (wildcards & OFPFW_DL_TYPE) {
        mask->dl_type = 0;
    }

    if (wildcards & OFPFW_TP_SRC) {
        mask->tp_src = 0;
    }

    if (wildcards & OFPFW_TP_DST) {
        mask->tp_dst = 0;
    }

    if (wildcards & OFPFW_NW_TOS) {
        mask->nw_tos = 0;
    }

    if (wildcards & OFPFW_NW_PROTO) {
        mask->nw_proto = 0;
    }

    if (wildcards & OFPFW_DL_DST) {
        memcpy(mask->dl_dst, zero_mac_addr, 6);
    }

    if (wildcards & OFPFW_DL_SRC) {
        memcpy(mask->dl_src, zero_mac_addr, 6);
    }

    return;
}

struct cbuf * __fastpath
of_prep_flow_mod(uint16_t command, const struct flow *flow, 
                 const struct flow *mask, size_t actions_len)
{
    struct ofp_flow_mod *ofm;
    size_t len = sizeof *ofm + actions_len;
    struct cbuf *b;
    uint16_t inport = (uint16_t)ntohl(flow->in_port);

    b = alloc_cbuf(len);
    ofm = cbuf_put(b, len);

    memset(ofm, 0, len);
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(len);
    ofm->match.wildcards = of10_mask_to_wc(mask);
    ofm->match.in_port = htons(inport);
    memcpy(ofm->match.dl_src, flow->dl_src, sizeof ofm->match.dl_src);
    memcpy(ofm->match.dl_dst, flow->dl_dst, sizeof ofm->match.dl_dst);
    ofm->match.dl_vlan = flow->dl_vlan;
    ofm->match.dl_type = flow->dl_type;
    ofm->match.dl_vlan_pcp = flow->dl_vlan_pcp;
    ofm->match.nw_src = flow->nw_src;
    ofm->match.nw_dst = flow->nw_dst;
    ofm->match.nw_proto = flow->nw_proto;
    ofm->match.tp_src = flow->tp_src;
    ofm->match.tp_dst = flow->tp_dst;
    ofm->command = htons(command);

    return b;
}

struct cbuf * __fastpath
of_prep_flow_add_msg(const struct flow *flow, const struct flow *mask,
                     uint32_t buffer_id, void *actions, size_t actions_len,
                     uint16_t i_timeo, uint16_t h_timeo, uint16_t prio)
{
    struct cbuf *b = of_prep_flow_mod(OFPFC_MODIFY_STRICT, flow, mask, 
                                      actions_len);
    struct ofp_flow_mod *ofm = CBUF_DATA(b);
    struct ofp_action_header *ofp_actions;

    ofm->idle_timeout = htons(i_timeo);
    ofm->hard_timeout = htons(h_timeo);
    ofm->priority = htons(prio);
    ofm->buffer_id = htonl(buffer_id);
    ofp_actions = (void *)(ofm + 1);
    memcpy(ofp_actions, actions, actions_len);

    return b;
}

struct cbuf *
of_prep_flow_del_msg(const struct flow *flow, 
                     const struct flow *mask, 
                     uint32_t oport, bool strict,
                     uint16_t prio, uint32_t group UNUSED)
{
    struct cbuf *b = of_prep_flow_mod(strict ? OFPFC_DELETE_STRICT:OFPFC_DELETE, 
                                      flow, mask, 0);
    struct ofp_flow_mod *ofm = CBUF_DATA(b);
    ofm->priority = htons(prio);
    ofm->out_port = htons(oport?:OFPP_NONE);
    return b;
}

struct cbuf * __fastpath
of_prep_pkt_out_msg(struct of_pkt_out_params *parms)
{
    size_t                tot_len;
    struct ofp_packet_out *out;
    struct cbuf           *b;
    void                  *data;

    tot_len = sizeof(struct ofp_packet_out) + parms->action_len
                        + parms->data_len;

    b = of_prep_msg(tot_len, OFPT_PACKET_OUT, (unsigned long)parms->data);

    out = (void *)b->data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htons(parms->in_port);
    out->actions_len = htons(parms->action_len);

    data = (uint8_t *)out->actions + parms->action_len;
    /* Hate it !! */
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy(data, parms->data, parms->data_len);


    return b;
}

struct cbuf * 
of_prep_flow_stat_msg(const struct flow *flow, 
                      const struct flow *mask,
                      uint32_t eoport,
                      uint32_t group UNUSED)
{
    struct ofp_stats_request *osr;
    struct ofp_flow_stats_request *ofsr;
    size_t len = sizeof *osr + sizeof *ofsr;
    struct cbuf *b;
    uint16_t oport = *(uint16_t *)(&eoport);

    b = of_prep_msg(len, OFPT_STATS_REQUEST, 0);
    osr = (void *)(b->data);

    osr->type = htons(OFPST_FLOW);

    ofsr = (void *)(osr->body);

    ofsr->table_id = flow->table_id;
    ofsr->out_port = htons(oport?:OFPP_NONE);

    ofsr->match.wildcards = of10_mask_to_wc(mask);
    ofsr->match.in_port = flow->in_port;
    memcpy(ofsr->match.dl_src, flow->dl_src, sizeof ofsr->match.dl_src);
    memcpy(ofsr->match.dl_dst, flow->dl_dst, sizeof ofsr->match.dl_dst);
    ofsr->match.dl_vlan = flow->dl_vlan;
    ofsr->match.dl_type = flow->dl_type;
    ofsr->match.dl_vlan_pcp = flow->dl_vlan_pcp;
    ofsr->match.nw_src = flow->nw_src;
    ofsr->match.nw_dst = flow->nw_dst;
    ofsr->match.nw_proto = flow->nw_proto;
    ofsr->match.tp_src = flow->tp_src;
    ofsr->match.tp_dst = flow->tp_dst;
 
    return b;
}

struct cbuf *
of131_prep_hello_msg(void)
{
    uint32_t v_bmap = htonl(0x12); 
    size_t hello_len = sizeof(struct ofp_hello) + 
                       C_ALIGN_8B_LEN(sizeof(struct ofp_hello_elem_versionbitmap) +
                       sizeof(v_bmap));
    struct cbuf *b;
    struct ofp_hello_elem_versionbitmap *ofp_hemv;

    b = of131_prep_msg(hello_len, OFPT131_HELLO, 0);
    ofp_hemv = (void *)(((struct ofp_hello *)(b->data))->elements);
    ofp_hemv->type = htons(OFPHET_VERSIONBITMAP);
    ofp_hemv->length = htons(sizeof(*ofp_hemv) + sizeof(v_bmap));
    
    ofp_hemv->bitmaps[1] = v_bmap;

    return b;
}

struct cbuf *
of131_prep_echo_msg(void)
{
    return of131_prep_msg(sizeof(struct ofp_header), OFPT131_ECHO_REQUEST, 0);
}

struct cbuf *
of131_prep_echo_reply_msg(uint32_t xid)
{
    return of131_prep_msg(sizeof(struct ofp_header), OFPT131_ECHO_REQUEST, xid);
}

struct cbuf *
of131_prep_set_config_msg(uint16_t flags, uint16_t miss_len)
{
    struct cbuf *b;
    struct ofp_switch_config *ofp_sc;

    /* Send OFPT_SET_CONFIG. */
    b = of131_prep_msg(sizeof(struct ofp_switch_config), OFPT131_SET_CONFIG, 0);
    ofp_sc = (void *)(b->data);
    ofp_sc->flags = htons(flags);
    ofp_sc->miss_send_len = htons(miss_len);

    return b;
}

struct cbuf *
of131_prep_features_request_msg(void)
{
    return of131_prep_msg(sizeof(struct ofp_header), OFPT131_FEATURES_REQUEST, 0);
}

struct cbuf * __fastpath
of131_prep_pkt_out_msg(struct of_pkt_out_params *parms)
{
    size_t                   tot_len;
    struct ofp131_packet_out *out;
    struct cbuf              *b;
    void                     *data;

    tot_len = sizeof(struct ofp131_packet_out) + parms->action_len
                        + parms->data_len;

    b = of131_prep_msg(tot_len, OFPT131_PACKET_OUT, (unsigned long)parms->data);

    out = (void *)b->data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htonl(parms->in_port);
    out->actions_len = htons(parms->action_len);

    data = (uint8_t *)out->actions + parms->action_len;
    /* Hate it !! */
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy(data, parms->data, parms->data_len);

    return b;
}


struct cbuf *
of131_prep_mpart_msg(uint16_t type, uint16_t flags, size_t body_len)
{
    struct cbuf *b;
    struct ofp_multipart_request *ofp_mr;
    
    b = of131_prep_msg(sizeof(*ofp_mr) + body_len, 
                       OFPT131_MULTIPART_REQUEST, 0);

    ofp_mr = CBUF_DATA(b);
    ofp_mr->type = htons(type);
    ofp_mr->flags = htons(flags);
    
    return b;
}

static size_t
of131_add_oxm_fields(uint8_t *buf,
                     size_t buf_len UNUSED,
                     const struct flow *flow,
                     const struct flow *mask)
{
    struct ofp_oxm_header *oxm = (void *)buf;
    size_t oxm_field_sz = 0;
    uint32_t *nw_addr;
    uint8_t zero_mac_addr[] = { 0, 0, 0, 0, 0, 0};
    uint8_t oxm_src_port = 0, oxm_dst_port = 0;
    bool has_l4_ports = false;

    /* Add this point only ip addresses have hasmask if 
     * needed
     */

    if (mask->in_port) { /* Not partially maskable */
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC; 
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IN_PORT);
        oxm->length = OFPXMT_OFB_IN_PORT_SZ; 
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint32_t *)(oxm->data) = flow->in_port;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (memcmp(mask->dl_dst, zero_mac_addr, OFP_ETH_ALEN)) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_DST);
        oxm->length = OFPXMT_OFB_ETH_SZ; 
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        memcpy((uint8_t *)(oxm->data), flow->dl_dst, OFP_ETH_ALEN);
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (memcmp(mask->dl_src, zero_mac_addr, OFP_ETH_ALEN)) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_SRC);
        oxm->length = OFPXMT_OFB_ETH_SZ; 
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        memcpy((uint8_t *)(oxm->data), flow->dl_src, OFP_ETH_ALEN);
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (mask->dl_type) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_TYPE);
        oxm->length = OFPXMT_OFB_ETH_TYPE_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint16_t *)(oxm->data) = flow->dl_type;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (mask->dl_vlan) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_VLAN_VID); // FIXME : OFPVID_PRESENT ??
        oxm->length = OFPXMT_OFB_VLAN_VID_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint16_t *)(oxm->data) = flow->dl_vlan;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (mask->dl_vlan && mask->dl_vlan_pcp) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_VLAN_PCP);
        oxm->length = OFPXMT_OFB_VLAN_PCP_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint8_t *)(oxm->data) = flow->dl_vlan_pcp;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }

    if (mask->nw_src) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 1);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV4_SRC);
        oxm->length = 2*OFPXMT_OFB_IPV4_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        nw_addr = (void *)(oxm->data);
        *nw_addr++ = flow->nw_src;
        *nw_addr++ = mask->nw_src;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (mask->nw_dst) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 1);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV4_DST);
        oxm->length = 2*OFPXMT_OFB_IPV4_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        nw_addr = (void *)(oxm->data);
        *nw_addr++ = flow->nw_dst;
        *nw_addr++ = mask->nw_dst;
        oxm = INC_PTR8(buf, oxm_field_sz);
    }
    if (mask->dl_type && 
        htons(flow->dl_type) == ETH_TYPE_IP &&
        mask->nw_proto) {
        oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
        OFP_OXM_SHDR_HM(oxm, 0);
        OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IP_PROTO);
        oxm->length = OFPXMT_OFB_IP_PROTO_SZ;
        oxm_field_sz += sizeof(*oxm) + oxm->length;
        HTON_OXM_HDR(oxm);
        *(uint8_t *)(oxm->data) = flow->nw_proto;
        oxm = INC_PTR8(buf, oxm_field_sz);

        if (mask->nw_tos) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 0);
            OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IP_DSCP);
            oxm->length = OFPXMT_OFB_IP_DSCP_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            *(uint8_t *)(oxm->data) = flow->nw_tos;
            oxm = INC_PTR8(buf, oxm_field_sz);
        }

        if (flow->nw_proto == IP_TYPE_TCP) {
            oxm_src_port = OFPXMT_OFB_TCP_SRC;
            oxm_dst_port = OFPXMT_OFB_TCP_DST;
            has_l4_ports = true;
        } else if (flow->nw_proto == IP_TYPE_UDP) {
            oxm_src_port = OFPXMT_OFB_UDP_SRC;
            oxm_dst_port = OFPXMT_OFB_UDP_DST;
            has_l4_ports = true;
        }
    }
    
    if (has_l4_ports) {
        if (mask->tp_src) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 0);
            OFP_OXM_SHDR_FIELD(oxm, oxm_src_port);
            oxm->length = OFPXMT_OFB_L4_PORT_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            *(uint16_t *)(oxm->data) = flow->tp_src;
            oxm = INC_PTR8(buf, oxm_field_sz);
        }

        if (mask->tp_dst) {
            oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
            OFP_OXM_SHDR_HM(oxm, 0);
            OFP_OXM_SHDR_FIELD(oxm, oxm_dst_port);
            oxm->length = OFPXMT_OFB_L4_PORT_SZ;
            oxm_field_sz += sizeof(*oxm) + oxm->length;
            HTON_OXM_HDR(oxm);
            *(uint16_t *)(oxm->data) = flow->tp_dst;
            oxm = INC_PTR8(buf, oxm_field_sz);
        }
    }
    return oxm_field_sz;
}

/** 
 * of131_prep_ofpx_match - 
 *
 * Makes an ofpx_match given flow and mask
 * Return val is 8-byte aligned length of ofpx_match
 */
static size_t
of131_prep_ofpx_match(struct ofpx_match *match, size_t oxm_tlv_room,
                      const struct flow *flow, const struct flow *mask)
{
    size_t tlv_len, match_len;

    tlv_len = of131_add_oxm_fields((uint8_t *)(match->oxm_fields),
                                   oxm_tlv_room, flow, mask); 

    match_len = OFPX_MATCH_HDR_SZ + tlv_len;
    match->type = htons(OFPMT_OXM);
    match->length = htons(match_len);

    return C_ALIGN_8B_LEN(match_len);
}

static struct cbuf * __fastpath
of131_prep_flow_mod_match(uint8_t command, const struct flow *flow, 
                          const struct flow *mask, uint8_t *inst_list,
                          size_t inst_len)
{
    struct ofp131_flow_mod *ofm;
    size_t match_len = 0, frame_len = 0; 
    struct cbuf *b;

    b = zalloc_cbuf(OF_MAX_FLOW_MOD_BUF_SZ); /* It should suffice for now */
    ofm = CBUF_DATA(b);
    match_len = of131_prep_ofpx_match(&ofm->match, 
                                OF_MAX_FLOW_MOD_BUF_SZ - sizeof(*ofm),
                                flow, mask); 
    match_len -= sizeof(ofm->match); /* match_len includes match size */
    frame_len = sizeof(*ofm) + match_len + inst_len;
    cbuf_put(b, frame_len);
    ofm->header.version = OFP_VERSION_131;
    ofm->header.type = OFPT131_FLOW_MOD;
    ofm->header.length = htons(frame_len);
    ofm->command = command;

    if (inst_len) {
        memcpy(INC_PTR8(ofm, sizeof(*ofm) + match_len), 
                       inst_list, inst_len);
    }

    return b;
}

int 
of131_ofpx_match_to_flow(struct ofpx_match *ofx,
                         struct flow *flow, struct flow *mask)
{
    int len = ntohs(ofx->length);
    struct ofp_oxm_header *oxm_ptr = (void *)(ofx->oxm_fields);
    struct ofp_oxm_header *oxm, oxm_hdr;
    int n_tlvs = 0, min_tlv_len = 0;
    uint8_t hm = 0;

    memset(flow, 0, sizeof(*flow));
    memset(mask, 0, sizeof(*mask));

    if (ntohs(ofx->type) != OFPMT_OXM || 
        len < sizeof(*ofx)) {
        if (!c_rlim(&rl))
            c_log_err("%s: ofpx_match len err", FN);
        return -1;
    }

    oxm = &oxm_hdr;
    len -= sizeof(*ofx);

    while (len > (int)sizeof(*oxm)) {

        ASSIGN_OXM_HDR(oxm, oxm_ptr);
        NTOH_OXM_HDR(oxm);

        if (oxm->oxm_class != OFPXMC_OPENFLOW_BASIC ||
            n_tlvs++ >= OFP_MAX_OXM_TLVS ) {
            
            if (!c_rlim(&rl))
                c_log_err("%s: ERROR rem-len %d", FN, len);
            return -1;
        }

        switch (OFP_OXM_GHDR_FIELD(oxm)) {
        case OFPXMT_OFB_IN_PORT:
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_IN_PORT_SZ ||
                oxm->length != OFPXMT_OFB_IN_PORT_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: in-port err", FN);
                return -1;
            }
            
            flow->in_port = *(uint32_t *)(oxm_ptr->data);
            mask->in_port = 0xffffffff;
            break;
        case OFPXMT_OFB_ETH_DST:
            hm = OFP_OXM_GHDR_HM(oxm);
            min_tlv_len = hm ? 2 * OFPXMT_OFB_ETH_SZ: OFPXMT_OFB_ETH_SZ; 
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: eth-dst err", FN);
                return -1;
            }
            memcpy(flow->dl_dst, oxm_ptr->data, OFPXMT_OFB_ETH_SZ);
            if (hm) {
                memcpy(mask->dl_dst, oxm_ptr->data + OFPXMT_OFB_ETH_SZ, 
                       OFPXMT_OFB_ETH_SZ);
            } else {
                memset(mask->dl_dst, 0xff, OFPXMT_OFB_ETH_SZ);
            } 
            break;
        case OFPXMT_OFB_ETH_SRC:
            hm = OFP_OXM_GHDR_HM(oxm);
            min_tlv_len = hm ? 2 * OFPXMT_OFB_ETH_SZ: OFPXMT_OFB_ETH_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: eth-src err", FN);
                return -1;
            }
            memcpy(flow->dl_src, oxm_ptr->data, OFPXMT_OFB_ETH_SZ);
            if (hm) {
                memcpy(mask->dl_src, oxm_ptr->data + OFPXMT_OFB_ETH_SZ, 
                       OFPXMT_OFB_ETH_SZ);
            } else {
                memset(mask->dl_src, 0xff, OFPXMT_OFB_ETH_SZ);
            } 
            break;
        case OFPXMT_OFB_VLAN_VID:
            hm = OFP_OXM_GHDR_HM(oxm);
            min_tlv_len = hm ? 2*OFPXMT_OFB_VLAN_VID_SZ:OFPXMT_OFB_VLAN_VID_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: vlan-vid err", FN);
                return -1;
            }
            flow->dl_vlan = *(uint16_t *)(oxm_ptr->data);
            if (OFP_OXM_GHDR_HM(oxm)) {
                mask->dl_vlan = *(uint16_t *)(oxm_ptr->data +
                                              OFPXMT_OFB_VLAN_VID_SZ);
            } else {
                mask->dl_vlan = 0xffff;
            }
            break;
        case OFPXMT_OFB_VLAN_PCP:
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_VLAN_PCP_SZ  ||
                oxm->length != OFPXMT_OFB_VLAN_PCP_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: vlan-pcp err", FN);
                return -1;
            }
            flow->dl_vlan_pcp = *(uint8_t *)(oxm_ptr->data);
            mask->dl_vlan_pcp = 0xff;
            break;
        case OFPXMT_OFB_ETH_TYPE:
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_ETH_TYPE_SZ ||
                oxm->length != OFPXMT_OFB_ETH_TYPE_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: eth-type err", FN);
                return -1;
            }
            flow->dl_type = *(uint16_t *)(oxm_ptr->data);
            mask->dl_type = 0xffff;
            break;
        case OFPXMT_OFB_IPV4_SRC:
            hm = OFP_OXM_GHDR_HM(oxm);
            if (flow->dl_type != htons(ETH_TYPE_IP)) break;
            min_tlv_len = hm ? 2 * OFPXMT_OFB_IPV4_SZ: OFPXMT_OFB_IPV4_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ipv4-src err", FN);
                return -1;
            }
            flow->nw_src = *(uint32_t *)(oxm_ptr->data);
            if (hm) {
                mask->nw_src = *(uint32_t *)(oxm_ptr->data + OFPXMT_OFB_IPV4_SZ);
            } else {
                mask->nw_src = 0xffffffff;
            }
            break;
        case OFPXMT_OFB_IPV4_DST:
            hm = OFP_OXM_GHDR_HM(oxm);
            if (flow->dl_type != htons(ETH_TYPE_IP)) break;
            min_tlv_len = hm ? 2 * OFPXMT_OFB_IPV4_SZ: OFPXMT_OFB_IPV4_SZ;
            if (len < min_tlv_len || oxm->length != min_tlv_len) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ipv4-dst err", FN);
                return -1;
            }
            flow->nw_dst = *(uint32_t *)(oxm_ptr->data);
            if (hm) {
                mask->nw_dst = *(uint32_t *)(oxm_ptr->data + OFPXMT_OFB_IPV4_SZ);
            } else {
                mask->nw_dst = 0xffffffff;
            }
            break;
        case OFPXMT_OFB_IP_DSCP:
            if (flow->dl_type != htons(ETH_TYPE_IP)) break;
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_IP_DSCP_SZ ||
                oxm->length != OFPXMT_OFB_IP_DSCP_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ip-dscp err", FN);
                return -1;
            }
            flow->nw_tos = *(uint8_t *)(oxm_ptr->data);
            mask->nw_tos = 0xff;
            break;
        case OFPXMT_OFB_IP_PROTO:
            if (flow->dl_type != htons(ETH_TYPE_IP)) break;
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_IP_PROTO_SZ ||
                oxm->length != OFPXMT_OFB_IP_PROTO_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: ip-proto err", FN);
                return -1;
            }
            flow->nw_proto = *(uint8_t *)(oxm_ptr->data);
            mask->nw_proto = 0xff;
            break;
        case OFPXMT_OFB_TCP_SRC:
        case OFPXMT_OFB_UDP_SRC:
            if ((flow->dl_type != htons(ETH_TYPE_IP)) ||
                (flow->nw_proto != IP_TYPE_UDP && 
                flow->nw_proto != IP_TYPE_TCP)) {
                return -1;
            }
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_L4_PORT_SZ ||
                oxm->length != OFPXMT_OFB_L4_PORT_SZ) {
                if (!c_rlim(&rl))
                    c_log_err("%s: l4-src-port err", FN);
                break;;
            }
            flow->tp_src = *(uint16_t *)(oxm_ptr->data);
            mask->tp_src = 0xffff;
            break;
        case OFPXMT_OFB_TCP_DST:
        case OFPXMT_OFB_UDP_DST:
            if (flow->dl_type != htons(ETH_TYPE_IP) ||
                (flow->nw_proto != IP_TYPE_UDP  &&
                flow->nw_proto != IP_TYPE_TCP)) {
                break;
            }
            if (OFP_OXM_GHDR_HM(oxm) || len < OFPXMT_OFB_L4_PORT_SZ ||
                oxm->length != OFPXMT_OFB_L4_PORT_SZ) {
                return -1;
            }
            flow->tp_dst = *(uint16_t *)(oxm_ptr->data);
            mask->tp_dst = 0xffff;
            break;
        default:
            /*if (!c_rlim(&rl))
                c_log_err("%s: Unhandled OXM %u", FN, OFP_OXM_GHDR_FIELD(oxm));
            */
            break;
        } 

        len -= oxm->length + sizeof(*oxm);

        //c_log_err("%s: n_tlv(%d) type (%u) oxm-length %u rem %d",
        //           FN, n_tlvs, OFP_OXM_GHDR_FIELD(oxm), oxm->length, len);

        oxm_ptr = INC_PTR8(oxm_ptr, oxm->length + sizeof(*oxm));
    }

    return 0;
}

struct cbuf *
of131_prep_flow_add_msg(const struct flow *flow, const struct flow *mask,
                        uint32_t buffer_id, void *ins_list,
                        size_t ins_len, uint16_t i_timeo,
                        uint16_t h_timeo, uint16_t prio)
{
    struct cbuf *b = of131_prep_flow_mod_match(OFPFC_ADD, flow, mask,
                                               ins_list, ins_len);
    struct ofp131_flow_mod *ofm = CBUF_DATA(b);

#if 0
    struct  flow fl, msk;
    of131_ofpx_match_to_flow(&ofm->match, &fl, &msk);
    char *fl_str = of_dump_flow_generic(&fl, &msk);
    c_log_info("%s: %s", FN, fl_str);
    free(fl_str);
#endif

    ofm->idle_timeout = htons(i_timeo);
    ofm->hard_timeout = htons(h_timeo);
    ofm->priority = htons(prio);
    ofm->table_id = flow->table_id;
    ofm->buffer_id = htonl(buffer_id);
    /* FIXME - flags ?? */

#if 0
    c_log_err("%s: cookie %llx mask %llx tbl %d cmd %d itimeo %hu htimeo %hu"
               "prio %hu buf 0x%x oport %lu grp %lu flags %hu",
               FN, ntohll(ofm->cookie), ntohll(ofm->cookie_mask),
               ofm->table_id, ofm->command, ntohs(ofm->idle_timeout), 
               ntohs(ofm->hard_timeout), ntohs(ofm->priority),
               ntohl(ofm->buffer_id), ntohl(ofm->out_port), ntohl(ofm->out_group),  
               ntohs(ofm->flags));

    c_log_err("Action dump");
    c_hex_dump(ins_list, ins_len);
#endif

    return b;
}

struct cbuf *
of131_prep_flow_del_msg(const struct flow *flow,
                        const struct flow *mask,
                        uint32_t oport, bool strict,
                        uint16_t prio, uint32_t group)
{
    struct cbuf *b = of131_prep_flow_mod_match(strict?OFPFC_DELETE_STRICT:OFPFC_DELETE,
                                               flow, mask, NULL, 0);
    struct ofp131_flow_mod *ofm = (void *)(b->data);

    ofm->priority = htons(prio);
    ofm->table_id = flow->table_id;
    ofm->out_port = htonl(oport?:OFPP131_ANY);
    ofm->out_group = htonl(group);
    return b;
}

struct cbuf * 
of131_prep_flow_stat_msg(const struct flow *flow, 
                         const struct flow *mask,
                         uint32_t eoport,
                         uint32_t group)
{
    struct ofp131_flow_stats_request *ofsr;
    struct cbuf *b;
    struct ofp_multipart_request *ofp_mr;
    uint16_t oport = *(uint16_t *)(&eoport);
    void *ofpx_match_buf = NULL;
    size_t mlen;

    ofpx_match_buf = calloc(1, OF_MAX_FLOW_MOD_BUF_SZ); /* It should suffice for now */
    if (!ofpx_match_buf) return NULL;

    mlen = of131_prep_ofpx_match(ofpx_match_buf, 
                                OF_MAX_FLOW_MOD_BUF_SZ - sizeof(struct ofpx_match),
                                flow, mask);
    b = of131_prep_mpart_msg(OFPMP_FLOW, 0,
                             sizeof(*ofsr) + mlen - sizeof(ofsr->match));
    ofp_mr = CBUF_DATA(b);
    ofsr = ASSIGN_PTR(ofp_mr->body);
    ofsr->table_id = flow->table_id;
    ofsr->out_port = htonl(oport?:OFPP131_ANY);
    ofsr->out_group = htonl(group);
    memcpy(&ofsr->match, ofpx_match_buf, mlen);
    
    free(ofpx_match_buf);
    return b;
}

bool
of131_group_validate(bool add, uint32_t group, uint8_t type, 
                     struct of_act_vec_elem *act_vectors[] UNUSED,
                     size_t act_vec_len)
{

    if (group == OFPG_ANY || group > OFPG_MAX)
        return false;

    if (add) {
        if (group == OFPG_ALL)
            return false;
        if (type == OFPGT_INDIRECT && act_vec_len > 1) 
            return false;
    }

    return true;
}
 
struct cbuf * 
of131_prep_group_add_msg(uint32_t group, uint8_t type, 
                         struct of_act_vec_elem *act_vectors[],
                         size_t act_vec_len)
{
    size_t tot_len = 0;
    struct of_act_vec_elem *elem;
    struct ofp_group_mod *ofp_gm;
    struct ofp_bucket *ofp_b;
    size_t bkt_len = 0;
    struct cbuf *b;
    int act = 0;

    for (act = 0; act < act_vec_len; act++) {
        elem = act_vectors[act];
        if (elem) 
            tot_len += C_ALIGN_8B_LEN(sizeof(struct ofp_bucket) + 
                                  elem->action_len); 
    }
    
    tot_len += sizeof(struct ofp_group_mod);

    b = of131_prep_msg(tot_len, OFPT131_GROUP_MOD, 0);
    ofp_gm = CBUF_DATA(b);
    ofp_gm->command = htons(OFPGC_ADD);
    ofp_gm->type = type;
    ofp_gm->group_id = htonl(group);

    ofp_b = ASSIGN_PTR(ofp_gm->buckets);

    for (act = 0; act < act_vec_len; act++) {
        elem = act_vectors[act];
        if (elem) {
            ofp_b = INC_PTR8(ofp_b, bkt_len); 
            bkt_len = C_ALIGN_8B_LEN(sizeof(struct ofp_bucket) +
                                 elem->action_len);

            ofp_b->len = htons(bkt_len);
            ofp_b->weight = htons(elem->weight);
            memcpy(ofp_b->actions, elem->actions, elem->action_len);
        }
    }
            
    return b;
}

struct cbuf * 
of131_prep_group_del_msg(uint32_t group) 
{
    size_t tot_len = 0;
    struct ofp_group_mod *ofp_gm;
    struct cbuf *b;

    tot_len = sizeof(struct ofp_group_mod);
    b = of131_prep_msg(tot_len, OFPT131_GROUP_MOD, 0);
    ofp_gm = CBUF_DATA(b);
    ofp_gm->command = htons(OFPGC_DELETE);
    ofp_gm->group_id = htonl(group);

    return b;
}
 
size_t 
of131_make_inst_actions(mul_act_mdata_t *mdata, uint16_t type)
{
    struct ofp_instruction_actions *ofp_ia;

    if (mdata->act_inst_ptr || 
        mdata->only_acts) return 0;
    of_check_realloc_act(mdata, sizeof(*ofp_ia));

    ofp_ia = (void *)(mdata->act_wr_ptr);
    ofp_ia->type = htons(type);
    ofp_ia->len = htons(sizeof(*ofp_ia));

    mdata->act_inst_ptr = mdata->act_wr_ptr;
    mdata->act_wr_ptr += sizeof(*ofp_ia);

    return (sizeof(*ofp_ia)); 
}

void
of131_fini_inst_actions(mul_act_mdata_t *mdata)
{
    struct ofp_instruction_actions *ofp_ia;

    if (mdata->only_acts) return;
    assert(mdata->act_inst_ptr);

    ofp_ia = ASSIGN_PTR(mdata->act_inst_ptr);
    ofp_ia->len = htons(of_mact_inst_act_len(mdata));
    return;
}

size_t 
of131_make_inst_goto(mul_act_mdata_t *mdata, uint8_t table_id)
{
    struct ofp_instruction_goto_table *ofp_ig;

    of_check_realloc_act(mdata, sizeof(*ofp_ig));

    ofp_ig = (void *)(mdata->act_wr_ptr);
    ofp_ig->type = htons(OFPIT_GOTO_TABLE);
    ofp_ig->len = htons(sizeof(*ofp_ig));

    ofp_ig->table_id = table_id;

    mdata->act_wr_ptr += sizeof(*ofp_ig);
    return (sizeof(*ofp_ig)); 
}

size_t
of131_make_action_output(mul_act_mdata_t *mdata, uint32_t oport)
{
    struct ofp131_action_output *op_act;

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, sizeof(*op_act));
    oport = oport ? : OFPP131_CONTROLLER;

    op_act = (void *)(mdata->act_wr_ptr);
    op_act->type = htons(OFPAT131_OUTPUT);
    op_act->len  = htons(sizeof(*op_act));
    op_act->port = htonl(oport);

    op_act->max_len = (oport == OFPP131_CONTROLLER) ? 
                            htons(OFPCML_NO_BUFFER) : htons(OF_MAX_MISS_SEND_LEN);
    mdata->act_wr_ptr += sizeof(*op_act);
    of131_fini_inst_actions(mdata);
    return (sizeof(*op_act));
}

size_t
of131_make_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_VLAN_VID_SZ); 

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, len);
    
    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_VLAN_VID); //OFPVID_PRESENT ??
    oxm->length = OFPXMT_OFB_VLAN_VID_SZ;
    HTON_OXM_HDR(oxm);  
    *(uint16_t *)(oxm->data) = htons(vid & 0xfff);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_strip_vlan(mul_act_mdata_t *mdata)
{
    struct ofp_action_header *vid_strip_act;

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, sizeof(*vid_strip_act));

    vid_strip_act = (void *)(mdata->act_wr_ptr);
    vid_strip_act->type = htons(OFPAT131_POP_VLAN);
    vid_strip_act->len  = htons(sizeof(*vid_strip_act));

    mdata->act_wr_ptr += sizeof(*vid_strip_act);
    of131_fini_inst_actions(mdata);
    return (sizeof(*vid_strip_act));
}

size_t
of131_make_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_VLAN_PCP_SZ); 

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, len);
    
    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_VLAN_PCP); //OFPVID_PRESENT ??
    oxm->length = OFPXMT_OFB_VLAN_PCP_SZ;
    HTON_OXM_HDR(oxm);  
    *(uint8_t *)(oxm->data) = vlan_pcp;
    
    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_ETH_SZ); 

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, len);
    
    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_DST);
    oxm->length = OFPXMT_OFB_ETH_SZ;
    HTON_OXM_HDR(oxm);
    memcpy((uint8_t *)(oxm->data), dmac, OFP_ETH_ALEN);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_ETH_SZ);

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_ETH_SRC);
    oxm->length = OFPXMT_OFB_ETH_SZ;
    HTON_OXM_HDR(oxm);
    memcpy((uint8_t *)(oxm->data), smac, OFP_ETH_ALEN);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len; 
}

size_t
of131_make_action_set_ipv4_src(mul_act_mdata_t *mdata, uint32_t nw_saddr)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_IPV4_SZ);

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV4_SRC);
    oxm->length = OFPXMT_OFB_IPV4_SZ;
    HTON_OXM_HDR(oxm);
    *(uint32_t *)(oxm->data) = htonl(nw_saddr);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len; 
}

size_t
of131_make_action_set_ipv4_dst(mul_act_mdata_t *mdata, uint32_t nw_daddr)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_IPV4_SZ);

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IPV4_DST);
    oxm->length = OFPXMT_OFB_IPV4_SZ;
    HTON_OXM_HDR(oxm);
    *(uint32_t *)(oxm->data) = htonl(nw_daddr);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len; 
}

size_t
of131_make_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) + 
                                OFPXMT_OFB_IP_DSCP_SZ);

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, OFPXMT_OFB_IP_DSCP);
    oxm->length = OFPXMT_OFB_IP_DSCP_SZ;
    HTON_OXM_HDR(oxm);
    *(uint8_t *)(oxm->data) = tos & ((0x1<<7) - 1);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

static size_t
of131_make_action_set_tp_port(mul_act_mdata_t *mdata, uint8_t ip_proto, 
                              bool is_src, uint16_t port)
{
    struct ofp_action_set_field *ofp_sf;
    struct ofp_oxm_header *oxm;
    size_t len = C_ALIGN_8B_LEN(OFP_ACT_SETF_HDR_SZ + sizeof(*oxm) +
                                OFPXMT_OFB_L4_PORT_SZ);
    uint8_t port_type;

    switch (ip_proto) {
    case IP_TYPE_TCP:
        if (is_src) {
            port_type = OFPXMT_OFB_TCP_SRC;
        } else {
            port_type = OFPXMT_OFB_TCP_DST;
        } 
        break;
    case IP_TYPE_UDP:
        if (is_src) {
            port_type = OFPXMT_OFB_UDP_SRC;
        } else {
            port_type = OFPXMT_OFB_UDP_DST;
        }
        break;
    default:
        c_log_err("%s: Unsupported act tp-port", FN);
        return 0;
    }

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, len);

    ofp_sf = (void *)(mdata->act_wr_ptr);
    ofp_sf->type = htons(OFPAT131_SET_FIELD);
    ofp_sf->len = htons(len);

    oxm = (void *)(ofp_sf->field);
    oxm->oxm_class = OFPXMC_OPENFLOW_BASIC;
    OFP_OXM_SHDR_HM(oxm, 0);
    OFP_OXM_SHDR_FIELD(oxm, port_type);
    oxm->length = OFPXMT_OFB_L4_PORT_SZ;
    HTON_OXM_HDR(oxm);
    *(uint16_t *)(oxm->data) = htons(port);

    mdata->act_wr_ptr += len;
    of131_fini_inst_actions(mdata);
    return len;
}

size_t
of131_make_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of131_make_action_set_tp_port(mdata, IP_TYPE_UDP, true, port);
}

size_t
of131_make_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of131_make_action_set_tp_port(mdata, IP_TYPE_UDP, false, port);
}

size_t
of131_make_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of131_make_action_set_tp_port(mdata, IP_TYPE_TCP, true, port);
}

size_t
of131_make_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port)
{
    return of131_make_action_set_tp_port(mdata, IP_TYPE_TCP, false, port);
}

size_t
of131_make_action_group(mul_act_mdata_t *mdata, uint32_t group)
{
    struct ofp_action_group *grp_act;

    of131_make_inst_actions(mdata, OFPIT_WRITE_ACTIONS);
    of_check_realloc_act(mdata, sizeof(*grp_act));

    grp_act = (void *)(mdata->act_wr_ptr);
    grp_act->type = htons(OFPAT131_GROUP);
    grp_act->group_id = htonl(group);
    grp_act->len  = htons(sizeof(*grp_act));

    mdata->act_wr_ptr += sizeof(*grp_act);
    of131_fini_inst_actions(mdata);
    return (sizeof(*grp_act));
}

static int
of131_dump_act_output(struct ofp_action_header *action, void *arg)
{
    struct ofp131_action_output *of_ao = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-port(%u):max-len(0x%x),",
                        "act-out", ntohl(of_ao->port), 
                        ntohs(of_ao->max_len));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
of131_dump_push_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_push *ofp_ap = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    char *push_str;

    switch(ntohs(ofp_ap->type)) {
    case OFPAT131_PUSH_VLAN:
        push_str = "push-vlan";
        break;
    case OFPAT131_PUSH_MPLS:
        push_str = "push-mpls";
        break;
    case OFPAT131_PUSH_PBB:
        push_str = "push-pbb";
        break;
    default:
        return -1;
    }

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s:eth-type(0x%x),",
                        push_str, ntohs(ofp_ap->ethertype));
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
of131_dump_pop_vlan_action(struct ofp_action_header *action, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "pop-vlan,");
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return ntohs(action->len);
}

static int
of131_dump_set_field_dl_dst(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *mac = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-0x%02x:%02x:%02x:%02x:%02x:%02x,",
                        "set-dmac", mac[0], mac[1], mac[2], mac[3],
                        mac[4], mac[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_set_field_dl_src(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *mac = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-0x%02x:%02x:%02x:%02x:%02x:%02x,",
                        "set-smac", mac[0], mac[1], mac[2], mac[3],
                        mac[4], mac[5]);
    assert(dp->len < OF_DUMP_INST_SZ-1);
                        
    return oxm->length;
}

static int
of131_dump_set_field_dl_vlan(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint16_t *vid = (uint16_t *)(oxm->data);

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-0x%x,", "set-vlan", ntohs(*vid));
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
of131_dump_set_field_dl_vlan_pcp(struct ofp_oxm_header *oxm, void *arg)
{
    struct ofp_inst_parser_arg *dp = arg;
    uint8_t *vlan_pcp = oxm->data;

    if (OFP_OXM_GHDR_HM(oxm)) return -1;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-0x%x,", "set-vlan-pcp", *vlan_pcp);
    assert(dp->len < OF_DUMP_INST_SZ-1);
    return oxm->length;
}

static int
of131_dump_group_act(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_group *grp_act = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s:group-id(%lu),",
                        "act-group", U322UL(ntohl(grp_act->group_id))); 
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(action->len);
}

static int
of131_dump_act_set_field(struct ofp_action_header *action, void *arg)
{
    struct ofp_action_set_field *ofp_sf = (void *)(action);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "set-field: ");
    assert(dp->len < OF_DUMP_INST_SZ-1);

    of131_parse_act_set_field_tlv(ofp_sf, dp->act_parsers, arg);
    return ntohs(action->len);
}

static int
of131_dump_goto_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_goto_table *ofp_ig = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - dp->len - 1,
                        "%s-%d,", "goto", ofp_ig->table_id);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(inst->len); 
}

static int
of131_dump_wr_meta_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_write_metadata *ofp_iwm = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg;

    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1, 
                        "%s-0x%llx:0x%llx,", "write-meta",
                        U642ULL(ntohll(ofp_iwm->metadata)), 
                        U642ULL(ntohll(ofp_iwm->metadata_mask))); 
    assert(dp->len < OF_DUMP_INST_SZ-1);

    return ntohs(inst->len);
}

static int
of131_dump_act_inst(struct ofp_instruction *inst, void *arg)
{
    struct ofp_instruction_actions *ofp_ia = (void *)(inst);
    struct ofp_inst_parser_arg *dp = arg; 
    char *pinst = NULL;
    
    switch(ntohs(ofp_ia->type)) {
    case OFPIT_WRITE_ACTIONS:
        pinst = "write-act";
        break;
    case OFPIT_APPLY_ACTIONS:
        pinst = "apply-act";
        break;
    case OFPIT_CLEAR_ACTIONS:
        pinst = "clr-act";
        break;
    default:
        return -1;
    }
    
    dp->len += snprintf(dp->pbuf + dp->len, OF_DUMP_INST_SZ - (dp->len) - 1,
                        "%s: ", pinst);
    assert(dp->len < OF_DUMP_INST_SZ-1);

    if (ntohs(ofp_ia->len) > sizeof(*ofp_ia)) {
        of131_parse_actions((void *)(ofp_ia->actions), 
                        ntohs(ofp_ia->len) - sizeof(*ofp_ia), arg);
    }
    return ntohs(inst->len);
}

void
of131_parse_act_set_field_tlv(struct ofp_action_set_field *ofp_sf,
                              struct ofp_act_parsers *act_parsers, 
                              void *parse_ctx)
{
    struct ofp_oxm_header *oxm = (void *)(ofp_sf->field);

    NTOH_OXM_HDR(oxm);
    if (oxm->oxm_class != OFPXMC_OPENFLOW_BASIC) {
        HTON_OXM_HDR(oxm);
        return;
    }

    switch (OFP_OXM_GHDR_FIELD(oxm)) {
    case OFPXMT_OFB_IN_PORT:
        if (act_parsers->act_setf_in_port)
            act_parsers->act_setf_in_port(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_ETH_DST:
        if (act_parsers->act_setf_dl_dst)
            act_parsers->act_setf_dl_dst(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_ETH_SRC:
        if (act_parsers->act_setf_dl_dst)
            act_parsers->act_setf_dl_src(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_VLAN_VID:
        if (act_parsers->act_setf_dl_vlan)
            act_parsers->act_setf_dl_vlan(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_VLAN_PCP:
        if (act_parsers->act_setf_dl_vlan_pcp)
            act_parsers->act_setf_dl_vlan_pcp(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_ETH_TYPE:
        if (act_parsers->act_setf_dl_type)
            act_parsers->act_setf_dl_type(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_IPV4_SRC:
        if (act_parsers->act_setf_ipv4_src)
            act_parsers->act_setf_ipv4_src(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_IPV4_DST:
        if (act_parsers->act_setf_ipv4_dst)
            act_parsers->act_setf_ipv4_dst(oxm, parse_ctx);
    case OFPXMT_OFB_IP_DSCP:
        if (act_parsers->act_setf_ipv4_dscp)
            act_parsers->act_setf_ipv4_dscp(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_TCP_SRC:
        if (act_parsers->act_setf_tcp_src)
            act_parsers->act_setf_tcp_src(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_UDP_SRC:
        if (act_parsers->act_setf_udp_src)
            act_parsers->act_setf_udp_src(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_TCP_DST:
        if (act_parsers->act_setf_tcp_dst)
            act_parsers->act_setf_tcp_dst(oxm, parse_ctx);
        break;
    case OFPXMT_OFB_UDP_DST:
        if (act_parsers->act_setf_udp_dst)
            act_parsers->act_setf_udp_dst(oxm, parse_ctx);
        break;
    default:
        c_log_err("%s:Unhandled set-field", FN);
        break;
    }

    HTON_OXM_HDR(oxm);

    return;
}

void
of131_parse_actions(void *actions, size_t act_len,
                    void *parse_ctx)
{
    struct ofp_action_header *act = actions;
    struct ofp_act_parsers *act_parsers = 
                ((struct ofp_inst_parser_arg *)parse_ctx)->act_parsers;
    int n_act = 0;

    if (!actions || !act_len || !act_parsers) {
        c_log_err("%s: No Actions or Parsers", FN);
        return;
    }

    while (act_len) {
        if (n_act++ > OFP_MAX_ACTIONS) {
            c_log_err("%s: Too many actions", FN);
            goto done;
        } 
        switch(ntohs(act->type)) {
        case OFPAT_OUTPUT:
            if (act_parsers->act_output) 
                act_parsers->act_output(act, parse_ctx);
            break;
        case OFPAT131_PUSH_VLAN:
            if (act_parsers->act_push_vlan)
                act_parsers->act_push_vlan(act, parse_ctx);
            break;
        case OFPAT131_POP_VLAN:
             if (act_parsers->act_pop_vlan)
                act_parsers->act_pop_vlan(act, parse_ctx);
            break;
        case OFPAT131_PUSH_MPLS:
            if (act_parsers->act_push_mpls)
                act_parsers->act_push_mpls(act, parse_ctx);
            break;
        case OFPAT131_POP_MPLS:
            if (act_parsers->act_pop_mpls)
                act_parsers->act_pop_mpls(act, parse_ctx); 
            break;
        case OFPAT131_SET_FIELD:
            if (act_parsers->act_set_field)
                act_parsers->act_set_field(act, parse_ctx);
            break;
        case OFPAT131_GROUP:
            if (act_parsers->act_set_grp)
                act_parsers->act_set_grp(act, parse_ctx);
            break;
        case OFPAT131_SET_NW_TTL:
            if (act_parsers->act_set_nw_ttl)
                act_parsers->act_set_nw_ttl(act, parse_ctx);
            break;
        case OFPAT131_DEC_NW_TTL:
            if (act_parsers->act_dec_nw_ttl)
                act_parsers->act_dec_nw_ttl(act, parse_ctx);
            break;
        default:
            c_log_err("%s: Unhandled actions", FN);
            goto done;
        }

        act_len -= ntohs(act->len);
        act = INC_PTR8(act, ntohs(act->len));
    }

done:
    return;
}

struct ofp_act_parsers of131_dump_act_parsers = {
    .act_output = of131_dump_act_output,
    .act_push_vlan = of131_dump_push_action,
    .act_pop_vlan = of131_dump_pop_vlan_action,
    .act_push_mpls = of131_dump_push_action,
    .act_push_pbb = of131_dump_push_action,
    .act_set_field = of131_dump_act_set_field,
    .act_setf_dl_dst = of131_dump_set_field_dl_dst,
    .act_setf_dl_src = of131_dump_set_field_dl_src,
    .act_setf_dl_vlan = of131_dump_set_field_dl_vlan,
    .act_setf_dl_vlan_pcp = of131_dump_set_field_dl_vlan_pcp, 
    .act_set_grp = of131_dump_group_act
};

struct ofp_inst_parsers of131_dump_inst_parsers = {
    .prep_inst_parser = of_inst_parser_alloc,
    .pre_proc = of_inst_parser_pre_proc,
    .post_proc = of_inst_parser_post_proc,
    .goto_inst = of131_dump_goto_inst,
    .wr_meta_inst = of131_dump_wr_meta_inst,
    .wr_act_inst = of131_dump_act_inst,
    .apply_act_inst = of131_dump_act_inst,
    .clear_act_inst = of131_dump_act_inst,
    .fini_inst_parser = of_inst_parser_fini,
}; 

struct ofp_inst_parser_arg *
of131_parse_instructions(void *inst_list, size_t inst_len,
                         struct ofp_inst_parsers *inst_handlers,
                         struct ofp_act_parsers *act_handlers,
                         void *u_arg, bool acts_only)
{
    struct ofp_instruction *inst = inst_list;
    int n_inst = 0;
    void *parse_ctx;

    if (!inst_handlers  || !inst_handlers->prep_inst_parser) {
        c_log_err("%s: No parser specified for instructions", FN);
        return NULL;
    }

    parse_ctx = inst_handlers->prep_inst_parser(u_arg, inst_handlers,
                                                act_handlers);
    if (!inst_len) {
        if (inst_handlers->no_inst) {
            inst_handlers->no_inst(parse_ctx);
            goto done;
        }
    }

    if (acts_only) {
        of131_parse_actions(inst_list, inst_len, parse_ctx);
        goto done;
    }

    if (inst_handlers->pre_proc)
        inst_handlers->pre_proc(parse_ctx);


    while (inst_len) {
        if (n_inst++ > OFP_MAX_INSTRUCTIONS) {
            c_log_err("%s: Too many instructions", FN);
            goto done;
        } 
        switch(ntohs(inst->type)) {
        case OFPIT_GOTO_TABLE:
            if (inst_handlers->goto_inst) 
                inst_handlers->goto_inst(inst, parse_ctx);
            break;
        case OFPIT_WRITE_METADATA:
            if (inst_handlers->wr_meta_inst)
                inst_handlers->wr_meta_inst(inst, parse_ctx);
            break;
        case OFPIT_WRITE_ACTIONS:
            if (inst_handlers->wr_act_inst)
                inst_handlers->wr_act_inst(inst, parse_ctx);
            break;
        case OFPIT_APPLY_ACTIONS:
            if (inst_handlers->apply_act_inst)
                inst_handlers->apply_act_inst(inst, parse_ctx);
            break;
        case OFPIT_CLEAR_ACTIONS:
            if (inst_handlers->clear_act_inst)
                inst_handlers->clear_act_inst(inst, parse_ctx); 
            break;
        case OFPIT_METER:
            if (inst_handlers->meter_inst)
                inst_handlers->meter_inst(inst, parse_ctx);
            break;
        case OFPIT_EXPERIMENTER:
            if (inst_handlers->exp_inst)
                inst_handlers->exp_inst(inst, parse_ctx);
        default:
            c_log_err("%s: Unhandled instruction", FN);
            goto done;
        }

        inst_len -= ntohs(inst->len);
        inst = INC_PTR8(inst, ntohs(inst->len));
    }

done:
    if (inst_handlers->post_proc)
        inst_handlers->post_proc(parse_ctx);

    if (inst_handlers->fini_inst_parser)
        inst_handlers->fini_inst_parser(parse_ctx);

    return parse_ctx;
}

char *
of131_dump_actions(void *inst_list, size_t inst_len, bool acts_only)
{
    struct ofp_inst_parser_arg *dp;
    char *pbuf;

    dp = of131_parse_instructions(inst_list, inst_len,
                                  &of131_dump_inst_parsers,
                                  &of131_dump_act_parsers, NULL,
                                  acts_only);
    pbuf =  dp && dp->pbuf ? dp->pbuf : NULL;
    if (dp) free(dp);
    return pbuf;
}

bool
of131_supports_multi_tables(uint8_t n_tables UNUSED, uint8_t table_id UNUSED)
{
    return true;
}
