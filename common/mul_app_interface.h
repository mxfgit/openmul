/*
 *  mul_app_interface.h: MUL application interface public headers
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

#ifndef __MUL_APP_INTERFACE_H__
#define __MUL_APP_INTERFACE_H__

typedef void (*initcall_t)(void *);
extern initcall_t __start_modinit_sec, __stop_modinit_sec;
#define data_attr         __attribute__ ((section ("modinit_sec")))
#define module_init(x)   initcall_t _##x data_attr = x

#ifndef SWIG
extern initcall_t __start_modvtyinit_sec, __stop_modvtyinit_sec;
#define vty_attr         __attribute__ ((section ("modvtyinit_sec")))
#define module_vty_init(x)  initcall_t _##x vty_attr = x
#endif

/* Registered application names */
#define FAB_APP_NAME "mul-fabric"
#define CLI_APP_NAME "mul-cli"
#define L2SW_APP_NAME "mul-l2sw"
#define TR_APP_NAME "mul-tr"
#define MAKDI_APP_NAME "mul-makdi"
#define HELLO_APP_NAME "mul-hello"
#define MUL_MAX_SERVICE_NUM 6

/* Controller app event notifications */
typedef enum c_app_event {
    C_DP_REG,
    C_DP_UNREG,
    C_PACKET_IN,
    C_PORT_CHANGE,
    C_FLOW_REMOVED,
    C_FLOW_MOD_FAILED,
	C_HA_STATE,
    C_EVENT_MAX
} c_app_event_t;
#define C_APP_ALL_EVENTS  ((1 << C_EVENT_MAX) - 1) 

#define C_OFP_VERSION             (0xfe)
#define C_OFPT_BASE               (0xc0)
#define C_OFPT_SWITCH_ADD         (OFPT_FEATURES_REPLY)
#define C_OFPT_PACKET_IN          (OFPT_PACKET_IN)
#define C_OFPT_PACKET_OUT         (OFPT_PACKET_OUT)
#define C_OFPT_PORT_STATUS        (OFPT_PORT_STATUS)
#define C_OFPT_SWITCH_DELETE      (C_OFPT_BASE)
#define C_OFPT_FLOW_MOD           (OFPT_FLOW_MOD)
#define C_OFPT_PACKET_IN          (OFPT_PACKET_IN)
#define C_OFPT_FLOW_REMOVED       (OFPT_FLOW_REMOVED)
#define C_OFPT_ERR_MSG            (OFPT_ERROR)
#define C_OFPT_REG_APP            (C_OFPT_BASE + 1)
#define C_OFPT_UNREG_APP          (C_OFPT_BASE + 2)
#define C_OFPT_RECONN_APP         (C_OFPT_BASE + 3)
#define C_OFPT_NOCONN_APP         (C_OFPT_BASE + 4)
#define C_OFPT_SET_FPOPS          (C_OFPT_BASE + 5)
#define C_OFPT_GROUP_MOD          (C_OFPT_BASE + 6)
#define C_OFPT_AUX_CMD            (C_OFPT_BASE + 7)

struct c_ofp_switch_delete {
    struct ofp_header header;
    uint64_t          datapath_id;
    uint32_t          sw_alias;
    uint32_t          pad;
};
OFP_ASSERT(sizeof(struct c_ofp_switch_delete) == (24));

struct c_sw_port {
    uint32_t port_no;
    uint8_t hw_addr[OFP_ETH_ALEN];
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */

    uint8_t pad[6];

#define C_MLPC_DOWN 0x1
#define C_MLPC_NO_STP 0x2
    uint32_t config;

#define C_MLPS_DOWN 0x1
    uint32_t state;

    uint32_t of_config;     /* Openflow port config */
    uint32_t of_state;      /* Openflow port state */

    uint32_t curr;          /* Current features. */
    uint32_t advertised;    /* Features being advertised by the port. */
    uint32_t supported;     /* Features supported by the port. */
    uint32_t peer;          /* Features advertised by peer. */
};
OFP_ASSERT(sizeof(struct c_sw_port) == 64);

/* Switch Add message */
struct c_ofp_switch_add {
    struct ofp_header header;
    uint64_t datapath_id;   /* Datapath unique ID.  The lower 48-bits are for
                               a MAC address, while the upper 16-bits are
                               implementer-defined. */
    uint32_t sw_alias;
    uint32_t n_buffers;     /* Max packets buffered at once. */

    uint8_t n_tables;       /* Number of tables supported by datapath. */
    uint8_t ver;            /* Switch's negotiated version */
    uint8_t pad[6];         /* Align to 64-bits. */

    uint32_t capabilities;  /* Bitmap of support "ofp_capabilities". */
    uint32_t actions;       /* Deprecated */

    /* Port info.*/
    struct c_sw_port ports[0];  /* Port definitions.  The number of ports
                                   is inferred from the length field in
                                   the header. */
};
OFP_ASSERT(sizeof(struct c_ofp_switch_add) == 40);

struct c_ofp_port_status {
    struct ofp_header   header;
    uint64_t            datapath_id;
    uint32_t            sw_alias;
    uint32_t            config_mask;
    uint32_t            state_mask;
    uint8_t             reason;  /* One of common across OF versions */
    uint8_t             pad[7];  /* Align to 64-bits. */
    struct c_sw_port    desc;
};

struct flow {
    uint32_t            nw_src;            /* IP source address. */
    uint32_t            nw_dst;            /* IP destination address. */
    uint32_t            in_port;           /* Input switch port. */
    uint16_t            dl_vlan;           /* Input VLAN id. */
    uint16_t            dl_type;           /* Ethernet frame type. */
    uint16_t            tp_src;            /* TCP/UDP source port. */
    uint16_t            tp_dst;            /* TCP/UDP destination port. */
    uint8_t             dl_vlan_pcp;       /* Input VLAN priority. */
    uint8_t             nw_tos;            /* IPv4 DSCP. */
    uint8_t             nw_proto;          /* IP protocol. */
    uint8_t             pad0;
    uint8_t             dl_dst[6];         /* Ethernet destination address. */
    uint8_t             dl_src[6];         /* Ethernet source address. */
#define C_FL_TBL_ID_DFL 0
    uint8_t             table_id;          /* Table-Id in cases necessary */
#define FL_DFL_GW pad[0]
    uint8_t             pad[11];
};
OFP_ASSERT(sizeof(struct flow)==48);

struct c_ofp_packet_in {
    struct ofp_header header;
    uint64_t          datapath_id;   /* Switch id */  
    uint32_t          sw_alias;      /* Switch Alias id */
    uint32_t          buffer_id;     /* ID assigned by datapath. */
    struct flow       fl;
    uint32_t          in_port;       /* Port on which frame was received. */
    uint16_t          total_len;     /* Full length of frame. */
    uint8_t           reason;        /* Reason packet is being sent (one of OFPR_*) */
    uint8_t           pad;
    uint8_t           data[0];       /* Ethernet frame */
};
OFP_ASSERT(sizeof(struct c_ofp_packet_in) == (80));


struct c_ofp_flow_mod {
    struct ofp_header   header;
    uint64_t            datapath_id;

    struct flow         flow; 
    struct flow         mask; 
#define C_FL_ENT_STATIC     (0x1) 
#define C_FL_ENT_CLONE      (0x2)
#define C_FL_ENT_LOCAL      (0x4)
#define C_FL_ENT_NOCACHE    (0x8)
#define C_FL_ENT_NOSYNC     (0x10)
#define C_FL_ENT_GSTATS     (0x20)
#define C_FL_ENT_SWALIAS    (0x40)
#define C_FL_ENT_EXPIRED    (0x80)
    uint8_t             flags;
#define C_OFPC_ADD  0
#define C_OFPC_DEL  1
    uint8_t             command;
#define C_FL_PRIO_DFL 0
#define C_FL_PRIO_FWD 1
#define C_FL_PRIO_DRP 2
#define C_FL_PRIO_EXM 65535
    uint16_t            priority;
    uint32_t            sw_alias;
    uint32_t            wildcards;
    uint16_t            itimeo;
    uint16_t            htimeo;
    uint32_t            oport;
    uint32_t            buffer_id;
    uint32_t            ogroup;
    uint16_t            mod_flags;
	uint8_t		    	pad[2];
    struct ofp_action_header actions[0];
};
OFP_ASSERT(sizeof(struct c_ofp_flow_mod) == (144));

struct c_ofp_flow_info {
    struct ofp_header   header;
    uint64_t            datapath_id;
    uint32_t            sw_alias;
	uint32_t			pad;
    struct flow         flow; 
    struct flow         mask; 
    uint8_t             flags;
    uint8_t             command;
    uint16_t            priority;
    uint32_t            wildcards;
    uint16_t            itimeo;
    uint16_t            htimeo;
    uint16_t            mod_flags;
    uint16_t            oport;
    uint32_t            buffer_id;
	uint32_t			pad1;
    uint64_t            byte_count;
    uint64_t            packet_count;
#define C_FL_XPS_SZ 32
    uint8_t             bps[C_FL_XPS_SZ];
    uint8_t             pps[C_FL_XPS_SZ];
    struct ofp_action_header actions[0];
};
OFP_ASSERT(sizeof(struct c_ofp_flow_info) == (224));

/* Flow removed (datapath -> controller). */
struct c_ofp_flow_removed {
    struct ofp_header   header;
    uint64_t            datapath_id;
    struct flow         flow;
    struct flow         mask;
    uint64_t            cookie;         /* Opaque controller-issued identifier.*/
    uint32_t            duration_sec;   /* Time flow was alive in seconds. */
    uint32_t            duration_nsec;  /* Time flow was alive in nanosecs beyond
                                           duration_sec. */               
    uint16_t            idle_timeout;   /* Idle timeout from original flow mod.*/
    uint16_t            priority;       /* Priority level of flow entry. */
    uint8_t             reason;         /* One of OFPRR_*. */             
 
    uint8_t             pad[3];         /* Align to 64-bits. */           
    uint64_t            packet_count;                                      
    uint64_t            byte_count;                                        
};  
OFP_ASSERT(sizeof(struct c_ofp_flow_removed) == 152);

struct c_ofp_bkt {
    uint16_t weight;
    uint16_t act_len;
    uint8_t  pad[4];
    struct ofp_action_header actions[0];
};
OFP_ASSERT(sizeof(struct c_ofp_bkt) == 8);

struct c_ofp_group_mod {
    struct ofp_header   header;
    uint64_t            datapath_id;

#define C_OFPG_ADD  0
#define C_OFPG_DEL  1
    uint8_t             command;
    uint8_t             type;      /* One of OFPGT_*. */
    uint8_t             pad[2];
    uint32_t            group_id;
    struct c_ofp_bkt    buckets[0];
};
OFP_ASSERT(sizeof(struct c_ofp_group_mod) == 24);

struct c_ofp_packet_out {
    struct ofp_header   header;
    uint64_t            datapath_id;
    uint32_t            buffer_id;    
    uint32_t            in_port;
    uint16_t            actions_len; 
    uint8_t             pad[6];
    struct ofp_action_header actions[0]; 
    /* uint8_t data[0]; */        /* Packet data.  The length is inferred
                                     from the length field in the header.
                                     (Only meaningful if buffer_id == -1.) */
};
OFP_ASSERT(sizeof(struct c_ofp_packet_out) == 32);

struct c_ofp_register_app {
    struct ofp_header   header;
#define C_MAX_APP_STRLEN  64 
    char                app_name[C_MAX_APP_STRLEN];
#define C_APP_ALL_SW        0x01
#define C_APP_REMOTE        0x02
#define C_APP_AUX_REMOTE    0x04
    uint32_t            app_flags;
    uint32_t            ev_mask;
    uint32_t            dpid;
    uint32_t            pad;
    uint64_t            dpid_list[0];
};
OFP_ASSERT(sizeof(struct c_ofp_register_app) == 88);

struct c_ofp_unregister_app {
   struct ofp_header   header;
   char                app_name[C_MAX_APP_STRLEN];
  
};
OFP_ASSERT(sizeof(struct c_ofp_unregister_app) == 72);

struct c_ofp_set_fp_ops {
    struct ofp_header   header;
    uint64_t            datapath_id;
#define C_FP_TYPE_DFL 0
#define C_FP_TYPE_L2 1
    uint32_t            fp_type;
    uint32_t            pad;
}; 
OFP_ASSERT(sizeof(struct c_ofp_set_fp_ops) == 24);

struct c_ofp_auxapp_cmd {
    struct ofp_header   header;

#define C_AUX_CMD_SUCCESS (0) 
#define C_AUX_CMD_ECHO (C_AUX_CMD_SUCCESS) 
#define C_AUX_CMD_MUL_CORE_BASE (1) 
#define C_AUX_CMD_MUL_GET_SWITCHES (C_AUX_CMD_MUL_CORE_BASE + 1) 
#define C_AUX_CMD_MUL_GET_SWITCHES_REPLY (C_AUX_CMD_MUL_CORE_BASE + 2) 
#define C_AUX_CMD_MUL_GET_SWITCH_DETAIL (C_AUX_CMD_MUL_CORE_BASE + 3) 
#define C_AUX_CMD_MUL_GET_APP_FLOW (C_AUX_CMD_MUL_CORE_BASE + 4)
#define C_AUX_CMD_MUL_GET_ALL_FLOWS (C_AUX_CMD_MUL_CORE_BASE + 5)
#define C_AUX_CMD_TR_BASE (C_AUX_CMD_MUL_CORE_BASE + 1000) 
#define C_AUX_CMD_TR_GET_NEIGH (C_AUX_CMD_TR_BASE + 1)
#define C_AUX_CMD_TR_NEIGH_STATUS (C_AUX_CMD_TR_GET_NEIGH + 1)
#define C_AUX_CMD_FAB_BASE (C_AUX_CMD_MUL_CORE_BASE + 2000) 
#define C_AUX_CMD_FAB_HOST_ADD (C_AUX_CMD_FAB_BASE + 1) 
#define C_AUX_CMD_FAB_HOST_DEL (C_AUX_CMD_FAB_BASE + 2) 
#define C_AUX_CMD_FAB_SHOW_ACTIVE_HOSTS (C_AUX_CMD_FAB_BASE + 3)
#define C_AUX_CMD_FAB_SHOW_INACTIVE_HOSTS (C_AUX_CMD_FAB_BASE + 4)
#define C_AUX_CMD_FAB_SHOW_ROUTES (C_AUX_CMD_FAB_BASE + 5)
#define C_AUX_CMD_FAB_ROUTE (C_AUX_CMD_FAB_BASE + 6)
#define C_AUX_CMD_HA_BASE (C_AUX_CMD_MUL_CORE_BASE + 3000)
#define C_AUX_CMD_HA_STATE (C_AUX_CMD_HA_BASE + 1)
#define C_AUX_CMD_HA_REQ_STATE (C_AUX_CMD_HA_BASE + 2)
#define C_AUX_CMD_HA_STATE_RESP (C_AUX_CMD_HA_BASE + 3)
#define C_AUX_CMD_MAKDI_BASE (C_AUX_CMD_MUL_CORE_BASE + 4000) 
#define C_AUX_CMD_MAKDI_USER_ADD (C_AUX_CMD_MAKDI_BASE + 1) 
#define C_AUX_CMD_MAKDI_USER_DEL (C_AUX_CMD_MAKDI_BASE + 2) 
    uint32_t            cmd_code;
    uint32_t            pad;
    uint8_t             data[0];
};
OFP_ASSERT(sizeof(struct c_ofp_auxapp_cmd) == 16);

struct c_ofp_req_dpid_attr {
    uint64_t            datapath_id;
};
OFP_ASSERT(sizeof(struct c_ofp_req_dpid_attr) == 8);

struct c_ofp_port_neigh {
    uint16_t            port_no;
#define COFP_NEIGH_SWITCH 0x1
    uint16_t            neigh_present; 
    uint16_t            neigh_port;
    uint16_t            pad;
    uint64_t            neigh_dpid;
};
OFP_ASSERT(sizeof(struct c_ofp_port_neigh) == 16);

struct c_ofp_switch_neigh {
    struct c_ofp_req_dpid_attr switch_id;
    uint8_t                    data[0]; 
};
OFP_ASSERT(sizeof(struct c_ofp_switch_neigh) == 8);

#define SW_INIT             (0)
#define SW_OFP_NEGOTIATED   (0x1)
#define SW_REGISTERED       (0x2)
#define SW_DEAD             (0x4)
#define SW_REINIT           (0x8)
#define SW_REINIT_VIRT      (0x10)

struct c_ofp_switch_brief {
    struct c_ofp_req_dpid_attr switch_id;
    uint32_t                   n_ports;
    uint32_t                   state;
#define OFP_CONN_DESC_SZ (32)
    char                       conn_str[OFP_CONN_DESC_SZ];
};
OFP_ASSERT(sizeof(struct c_ofp_switch_brief) == 48);

struct c_ofp_host_mod {
    struct c_ofp_req_dpid_attr switch_id;
    struct flow                host_flow;
};
OFP_ASSERT(sizeof(struct c_ofp_host_mod) == 56);

struct c_ofp_route {
    struct c_ofp_host_mod      src_host;
    struct c_ofp_host_mod      dst_host;
    uint8_t                    route_links[0];
};
OFP_ASSERT(sizeof(struct c_ofp_route) == 112);

struct c_ofp_route_link {
    uint64_t                   datapath_id;
    uint16_t                   src_link;
    uint16_t                   dst_link; 
    uint32_t                   pad;
};
OFP_ASSERT(sizeof(struct c_ofp_route_link) == 16);

struct c_ofp_ha_state {
    uint32_t                   ha_sysid;
#define C_HA_STATE_NONE (0)
#define C_HA_STATE_CONNECTED (1)
#define C_HA_STATE_MASTER (2)
#define C_HA_STATE_SLAVE (3)
#define C_HA_STATE_CONFLICT (4)
#define C_HA_STATE_NOHA (5)
    uint32_t                   ha_state;
};
OFP_ASSERT(sizeof(struct c_ofp_ha_state) == 8);

struct c_ofp_s_chain_mod {
    struct c_ofp_host_mod      user_info;
    uint64_t                   num_nfvs;
#define MAX_NFV 10
#define MAX_NFV_NAME 64
    char                       nfv_list[MAX_NFV][MAX_NFV_NAME];    
};
OFP_ASSERT(sizeof(struct c_ofp_s_chain_mod) == 704);

#define C_OFP_ERR_CODE_BASE (100)

/* More bad request codes */
#define OFPBRC_BAD_DPID     (C_OFP_ERR_CODE_BASE)
#define OFPBRC_BAD_APP_REG  (C_OFP_ERR_CODE_BASE + 1)
#define OFPBRC_BAD_APP_UREG (C_OFP_ERR_CODE_BASE + 2)
#define OFPBRC_BAD_NO_INFO  (C_OFP_ERR_CODE_BASE + 3)
#define OFPBRC_BAD_GENERIC  (C_OFP_ERR_CODE_BASE + 4)

/* More bad action codes */
#define OFPBAC_BAD_GENERIC  (C_OFP_ERR_CODE_BASE)  

/* More flow mod failed codes */
#define OFPFMFC_BAD_FLAG    (C_OFP_ERR_CODE_BASE)   
#define OFPFMFC_GENERIC     (C_OFP_ERR_CODE_BASE + 1)   

#define C_OFP_MAX_ERR_LEN 128

#define C_ADD_ALIAS_IN_SWADD(sw_add, alias)         \
    do {                                            \
        *((uint16_t *)(sw_add->pad)) = htons((uint16_t)alias);     \
    } while (0)

#define C_GET_ALIAS_IN_SWADD(sw_add) (int)ntohs(*((uint16_t *)(sw_add->pad)))

typedef struct c_sw_port c_sw_port_t;
typedef struct c_ofp_switch_delete c_ofp_switch_delete_t;
typedef struct c_ofp_switch_add c_ofp_switch_add_t;
typedef struct c_ofp_packet_in c_ofp_packet_in_t;;
typedef struct c_ofp_port_status c_ofp_port_status_t;
typedef struct c_ofp_phy_port c_ofp_phy_port_t;
typedef struct c_ofp_flow_mod c_ofp_flow_mod_t;
typedef struct c_ofp_flow_info c_ofp_flow_info_t;
typedef struct c_ofp_packet_out c_ofp_packet_out_t; 
typedef struct c_ofp_register_app c_ofp_register_app_t;
typedef struct c_ofp_unregister_app c_ofp_unregister_app_t;
typedef struct c_ofp_set_fp_ops c_ofp_set_fp_ops_t;
typedef struct ofp_error_msg c_ofp_error_msg_t;
typedef struct c_ofp_auxapp_cmd c_ofp_auxapp_cmd_t; 
typedef struct c_ofp_req_dpid_attr c_ofp_req_dpid_attr_t;
typedef struct c_ofp_switch_neigh c_ofp_switch_neigh_t;
typedef struct c_ofp_port_neigh c_ofp_port_neigh_t;
typedef struct c_ofp_switch_brief c_ofp_switch_brief_t;
typedef struct c_ofp_host_mod c_ofp_host_mod_t; 
typedef struct c_ofp_route c_ofp_route_t;
typedef struct c_ofp_route_link c_ofp_route_link_t;
typedef struct c_ofp_ha_state c_ofp_ha_state_t;
typedef struct c_ofp_s_chain_mod c_ofp_s_chain_mod_t;

#endif
