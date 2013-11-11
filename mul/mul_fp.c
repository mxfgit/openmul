/*
 *  mul_fp.c: MUL fastpath forwarding implementation for L2, L3 or 
 *            other known profiles.
 * 
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
#include "mul_fp.h"

struct flow l2_fl_mask;

void
c_l2fdb_show(c_switch_t *sw, void *arg,
             void (*show_fn)(void *arg, c_fl_entry_t *ent))
{
    unsigned int bkt_idx = 0, ent_idx = 0;
    c_l2fdb_ent_t  *ent = NULL;
    c_fl_entry_t fl_ent;
    uint8_t actions[C_INLINE_ACT_SZ];
    mul_act_mdata_t mdata;
     
    memset(&fl_ent, 0, sizeof(fl_ent));
    memcpy(&fl_ent.fl_mask, &l2_fl_mask, sizeof(struct flow));

    mdata.act_base = actions;
    of_mact_mdata_init(&mdata, C_INLINE_ACT_SZ);

    fl_ent.fl.table_id = C_TBL_HW_IDX_DFL;
    c_rd_lock(&sw->lock);
    if (sw->app_flow_tbl) {
        for (bkt_idx = 0; bkt_idx < C_L2FDB_SZ; bkt_idx++) {
            c_l2fdb_bkt_t  *bkt = sw->app_flow_tbl;

            bkt += bkt_idx;
            for (; bkt; bkt = bkt->next) {
                for (ent_idx = 0; 
                     ent_idx < C_FDB_ENT_PER_BKT;
                     ent_idx++) {

                    ent = &bkt->fdb_ent[ent_idx];
                    if (!ent->valid) continue; 
                    
                    c_rw_lock_init(&fl_ent.FL_LOCK);
                    fl_ent.sw = sw;
                    fl_ent.FL_ENT_TYPE = C_TBL_RULE;
                    fl_ent.FL_PRIO = C_FL_PRIO_DFL;
                    memcpy(&fl_ent.fl.dl_dst, ent->mac, OFP_ETH_ALEN);
                    sw->ofp_ctors->act_output(&mdata, ent->port);
                    fl_ent.actions = (void *)(mdata.act_base);
                    fl_ent.action_len = of_mact_len(&mdata);
                    show_fn(arg, &fl_ent);
                    of_mact_mdata_reset(&mdata);
                }
            }
        }
    }
    c_rd_unlock(&sw->lock);
}

static inline int
c_l2fdb_install(c_switch_t *sw, c_l2fdb_ent_t *ent)
{
    struct flow fl;
    uint8_t actions[C_INLINE_ACT_SZ];
    size_t act_len;
    mul_act_mdata_t mdata;

    mdata.act_base = actions;
    of_mact_mdata_init(&mdata, C_INLINE_ACT_SZ);

    memcpy(&fl.dl_dst, ent->mac, OFP_ETH_ALEN);
    act_len = sw->ofp_ctors->act_output(&mdata, ent->port);
    ent->installed = 1;
    of_send_flow_add_direct(sw, &fl, &l2_fl_mask, (uint32_t)(-1),
                            mdata.act_base, act_len, 60, 0,
                            C_FL_PRIO_DFL);
    return 0;
}

static int
c_l2fdb_uninstall(c_switch_t *sw, c_l2fdb_ent_t *ent)
{
    struct flow fl;

    memcpy(&fl.dl_dst, ent->mac, OFP_ETH_ALEN);
    ent->installed = 0;
    of_send_flow_del_direct(sw, &fl, &l2_fl_mask,
                            OFPP_NONE, false, C_FL_PRIO_DFL,
                            OFPG_ANY);
    return 0;
}

static void
c_l2fdb_evict(c_switch_t *sw, uint8_t *mac, uint16_t port,
              c_l2fdb_ent_t *ent)
{
    if (ent) {
        if (ent->installed) {
            c_l2fdb_uninstall(sw, ent);
        }
        c_l2fdb_ent_init(ent, mac, port);
    }
}

static int __fastpath
c_l2fdb_learn(c_switch_t *sw, uint8_t *mac, uint32_t port)
{
    c_l2fdb_bkt_t  *bkt = sw->app_flow_tbl;
    c_l2fdb_bkt_t  *last_bkt = NULL, *new_bkt = NULL;
    unsigned int   bkt_idx = c_l2fdb_key(mac);
    unsigned int   idx;
    c_l2fdb_ent_t  *ent, *emp_ent = NULL;
    c_l2fdb_ent_t  *evict_ent = NULL;
    
    bkt += bkt_idx;

    for (; bkt; bkt = bkt->next) {
        idx = 0;
        while(idx < C_FDB_ENT_PER_BKT) {
            ent = &bkt->fdb_ent[idx++];

            if (likely(!ent->valid)) {
                if (!emp_ent)
                    emp_ent = ent;
                continue;
            } 

            if (c_l2fdb_equal(mac, ent->mac)) {
                if (ent->port != port) {
                    ent->port = port;
                    c_l2fdb_install(sw, ent);
                }    
                return 0;
            }
            /* Minimal eviction alg. Need more work */
            if (!evict_ent) {
                time_t curr_time = time(NULL);
                if (curr_time > ent->timestamp + 25) 
                    evict_ent = ent; 
            }
        }
        last_bkt = bkt;
    }

add_entry:
    if (emp_ent)  {
        c_l2fdb_ent_init(emp_ent, mac, port);
        return 0;
    } 

    if (!evict_ent) {
        new_bkt = calloc(1, sizeof(*new_bkt));
        last_bkt->next = new_bkt;
        emp_ent = &new_bkt->fdb_ent[0];
        goto add_entry;
    } else {
        c_l2fdb_evict(sw, mac, port, evict_ent);
    }

    return 0;
}

static inline c_l2fdb_ent_t * 
c_l2fdb_lookup(c_switch_t *sw, uint8_t *mac)
{
    c_l2fdb_bkt_t  *bkt = sw->app_flow_tbl;
    unsigned int   bkt_idx = c_l2fdb_key(mac);
    unsigned int   idx = 0;
    c_l2fdb_ent_t  *ent;

    bkt += bkt_idx;

    for (; bkt; bkt = bkt->next) {
        idx = 0;
        while(idx < C_FDB_ENT_PER_BKT) {
            ent = &bkt->fdb_ent[idx++];
            if (ent->valid && c_l2fdb_equal(mac, ent->mac)) {
                return ent;
            } 
        }
    }

    return NULL;
}

int 
c_l2fdb_init(c_switch_t *sw)
{
    memset(&l2_fl_mask, 0, sizeof(l2_fl_mask));
    memset(l2_fl_mask.dl_dst, 0xff, 6);
    sw->app_flow_tbl = calloc(1, sizeof(struct c_l2fdb_bkt) * C_L2FDB_SZ);
    assert(sw->app_flow_tbl);

    return 0;
}

void
c_l2fdb_destroy(c_switch_t *sw)
{
    unsigned int   idx = 0;

    c_wr_lock(&sw->lock);

    if (sw->app_flow_tbl) {
        for (idx = 0; idx < C_L2FDB_SZ; idx++) {
            c_l2fdb_bkt_t  *bkt = sw->app_flow_tbl, *prev = NULL;

            bkt += idx;
            bkt = bkt->next;
            while (bkt) {
                prev = bkt;
                bkt = bkt->next;
                free(prev);
            }
        }
        free(sw->app_flow_tbl);
    }
    sw->app_flow_tbl = NULL;

    c_wr_unlock(&sw->lock);
}

/* 
 * c_l2_lrn_fwd - This is fast code which is supposed to know l2sw module's
 * learning and forwarding behaviour. Since it runs as a part of core controller                 
 * it can easily take advantage of controller's threaded features and run
 * in-thread-context. It offloads forwarding functions from the module itself.
 * (FIXME - This is not yet implemented fully. It will functionally work
 *  but there may be holes)
 */
int __fastpath
c_l2_lrn_fwd(c_switch_t *sw, struct cbuf *b UNUSED, void *data, size_t pkt_len, 
             struct c_pkt_in_mdata *pkt_mdata, uint32_t in_port)
{
    c_l2fdb_ent_t *ent;
    uint8_t actions[24];
    size_t act_len;
    struct of_pkt_out_params parms;
    struct flow *in_flow = pkt_mdata->fl;
    mul_act_mdata_t mdata;

    mdata.act_base = actions;
    of_mact_mdata_init(&mdata, sizeof(actions));

    /* We preinstall rules to drop these */
#ifdef L2_INVALID_ADDR_CHK 
    if (is_zero_ether_addr(in_flow->dl_src) ||
        is_zero_ether_addr(in_flow->dl_dst) ||
        is_multicast_ether_addr(in_flow->dl_src) ||
        is_broadcast_ether_addr(in_flow->dl_src)) {
        c_log_debug("%s: Invalid src/dst mac addr", FN);
        return -1;
    }
#endif

    c_wr_lock(&sw->lock);

    c_l2fdb_learn(sw, in_flow->dl_src, in_port);
    if ((ent = c_l2fdb_lookup(sw, in_flow->dl_dst))) {
        sw->ofp_ctors->act_output(&mdata, ent->port);
        ent->installed = 1;
        of_send_flow_add_direct(sw, in_flow, &l2_fl_mask,
                                pkt_mdata->buffer_id,
                                actions, of_mact_len(&mdata),
                                10, 20, 
                                C_FL_PRIO_DFL);
        if (pkt_mdata->buffer_id != (uint32_t)(-1)) {
            c_wr_unlock(&sw->lock);
            return 0;    
        }
    }
    c_wr_unlock(&sw->lock);

    of_mact_mdata_reset(&mdata);
    mdata.only_acts = true;
    act_len = sw->ofp_ctors->act_output(&mdata, OF_ALL_PORTS); 
    parms.buffer_id = pkt_mdata->buffer_id;
    parms.action_len = act_len;
    parms.action_list  = mdata.act_base;
    parms.in_port = in_port;
    parms.data = data;
    parms.data_len = (parms.buffer_id == (uint32_t)(-1))? pkt_len : 0;

    sw->ofp_ctors->pkt_out_fast(sw, &parms);

    return 0;
}

int 
c_l2_port_status(c_switch_t *sw UNUSED, uint32_t cfg UNUSED, uint32_t state UNUSED)
{
    /* Nothing to do for now */
    return 0;
}
