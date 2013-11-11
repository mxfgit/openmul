/*
 *  mul_cli.h: Mul cli application headers
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
#ifndef __MUL_CLI_H__
#define __MUL_CLI_H__

#include "config.h"
#include "mul_common.h"
#include "mul_vty.h"
#include "mul_fabric_servlet.h"
#include "mul_nbapi.h"

#define CLI_CONF_FILE "mulcli.conf"

#define CLI_TIMER_TS  (2)
#define CLI_TIMER_TUS (0)

#define CLI_TIMER_INIT_TS  (5)
#define CLI_TIMER_INIT_TUS (0)

#define CLI_UNK_BUFFER_ID (0xffffffff)

struct cli_common_args {
    bool flow_act;
};

struct cli_flow_action_parms {
    struct cli_common_args cmn;    
    uint64_t dpid;
    void *fl;
    void *mask;
    struct mul_act_mdata *mdata;
    bool drop_pkt;
};

struct cli_group_mod_parms
{
    struct cli_common_args cmn;
    uint64_t dpid;
    uint32_t group;
    uint8_t type;
    mul_act_mdata_t mdata[OF_MAX_ACT_VECTORS];
    bool drop_pkt[OF_MAX_ACT_VECTORS];
    size_t act_vec_len;
};

#define CLI_ARGS_TO_ACT_MDATA_SW(mdata, args) \
do { \
    struct cli_common_args *__cmn = (void *)(args); \
    if (__cmn->flow_act) { \
        struct cli_flow_action_parms *fl_parms = args; \
        (mdata) = fl_parms->mdata; \
    } else { \
        struct cli_group_mod_parms *g_parms = args; \
        (mdata) = &g_parms->mdata[g_parms->act_vec_len-1]; \
    } \
} while (0)

/* Main fabric context struct holding all info */
struct cli_struct {
    GSList        *cli_list;
    c_rw_lock_t   lock;
    void          *base;
    bool          init_events_triggered;
    struct event  *timer_event;
    mul_service_t *mul_service; /* Traffic-Routing Service Instance */
    mul_service_t *tr_service; /* Traffic-Routing Service Instance */
    mul_service_t *fab_service; /* Fabric Service Instance */

    uint32_t      sysid;
    uint32_t      state;
};
typedef struct cli_struct cli_struct_t;

struct cli_config_wr_arg {
    struct vty *vty;
    int write;        
};

void cli_module_init(void *ctx);
void cli_module_vty_init(void *arg);

#endif
