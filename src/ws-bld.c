/**
 * Wireshark plugin for analysis of the SLAC BLD protocol
 * @author Jeremy Lorelli
 * @date July 25th, 2023
 */

#include <epan/packet.h>
#include <epan/epan_dissect.h>

#if WIRESHARK_VERSION_MAJOR < 2 || (WIRESHARK_VERSION_MAJOR == 2 && WIRESHARK_VERSION_MINOR < 5)
#define WS_OLD_API 1
#else
#define WS_OLD_API 0
#endif

#if WS_OLD_API
#include <epan/plugins.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#include "bld-proto.h"

#define EXPORT_SYM __attribute__((visibility("default")))

#define PLUGIN_VERSION "0.1.0"

EXPORT_SYM const gchar plugin_version[] = PLUGIN_VERSION;
EXPORT_SYM const gchar version[] = PLUGIN_VERSION; /* For old API */
EXPORT_SYM int plugin_want_major = 4;
EXPORT_SYM int plugin_want_minor = 0;

static uint32_t min(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

static int bld_proto = -1;

static int hf_bld_ts = -1;
static int hf_bld_pulseid = -1;
static int hf_bld_version = -1;
static int hf_bld_sevr = -1;
static int ett_bld = -1;
static int hf_bld_data[NUM_BLD_CHANNELS] = {-1};

static int hf_bld_comp_ts = -1;
static int hf_bld_comp_pulseid = -1;
static int hf_bld_comp_sevr = -1;

static int bld_dissect(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {
    int offset = 0;
    int length = tvb_reported_length(tvb);

    /* Add all header items */
    proto_tree_add_item(tree, hf_bld_ts, tvb, offset, sizeof(uint64_t), ENC_LITTLE_ENDIAN);
    offset += sizeof(uint64_t);
    proto_tree_add_item(tree, hf_bld_pulseid, tvb, offset, sizeof(uint64_t), ENC_LITTLE_ENDIAN);
    offset += sizeof(uint64_t);
    proto_tree_add_item(tree, hf_bld_version, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
    offset += sizeof(uint32_t);
    proto_tree_add_item(tree, hf_bld_sevr, tvb, offset, sizeof(uint64_t), ENC_LITTLE_ENDIAN);
    offset += sizeof(uint64_t);

    int numItems = length <= sizeof(bldMulticastPacket_t) ? (length - bldMulticastPacketHeaderSize) / sizeof(uint32_t) :
        NUM_BLD_CHANNELS;

    /* Add the channel's payload now */
    if (numItems > 0) {
        proto_tree* datasub = 
#if WS_OLD_API
            tree;
#else
            proto_tree_add_subtree(tree, tvb, offset, numItems, ett_bld, NULL, "Channel data");
#endif
    	for (int i = 0; i < numItems; ++i) {
            proto_tree_add_item(datasub, hf_bld_data[i], tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
       	    offset += sizeof(uint32_t);
    	}
	}

    /* Handle complementary packets coming in now */
    int compIdx = 1;
    while (offset < length) {
        char treeName[128];
        snprintf(treeName, sizeof(treeName), "Event %d", compIdx++);
        /* Mark this as a complementary chunk */
        proto_tree* ctree = 
        #if WS_OLD_API
            tree;
        #else
            proto_tree_add_subtree(tree, tvb, offset, sizeof(uint32_t), ett_bld, NULL, treeName);
        #endif
        proto_tree_add_item(ctree, hf_bld_comp_ts, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ctree, hf_bld_comp_pulseid, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); 
        offset += sizeof(uint32_t);
        proto_tree_add_item(ctree, hf_bld_comp_sevr, tvb, offset, sizeof(uint64_t), ENC_LITTLE_ENDIAN);
        offset += sizeof(uint64_t);
        
        /* Add items, again */
        numItems = min(length - offset / sizeof(uint32_t), NUM_BLD_CHANNELS);
        proto_tree* datasub =
        #if WS_OLD_API
            ctree;
        #else
            proto_tree_add_subtree(ctree, tvb, offset, numItems, ett_bld, NULL, "Channel Data");
        #endif
        for (int i = 0; i < numItems; ++i) {
            proto_tree_add_item(datasub, hf_bld_data[i], tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
            offset += sizeof(uint32_t);
        }
    }

    return tvb_captured_length(tvb);
}

static hf_register_info bld_fields[] = {
    {
        &hf_bld_ts,
        {
            "timestamp",
            "ts",
            FT_UINT64,
            BASE_HEX,
            NULL,
            0x0,
            "Data timestamp"
        }
    },
    {
        &hf_bld_pulseid,
        {
            "pulse_id",
            "pid",
            FT_UINT64,
            BASE_HEX,
            NULL,
            0x0,
            "Beam pulse ID"
        }
    },
    {
        &hf_bld_version,
        {
            "version",
            "ver",
            FT_UINT32,
            BASE_HEX,
            NULL,
            0x0,
            "Packet version, increments each time channel mask changes"
        }
    },
    {
        &hf_bld_sevr,
        {
            "severity_mask",
            "sevr",
            FT_UINT64,
            BASE_HEX,
            NULL,
            0x0,
            "Severity mask"
        }
    }
};

static hf_register_info bld_comp_fields[] = {
    {
        &hf_bld_comp_ts,
        {
            "timestamp delta",
            "ts_delta",
            FT_UINT32,
            BASE_HEX,
            NULL,
            0xFFFFF000,
            "Delta from timestamp in the header"
        }
    },
    {
        &hf_bld_comp_pulseid,
        {
            "pulse ID delta",
            "pid_delta",
            FT_UINT32,
            BASE_HEX,
            NULL,
            0x00000FFF,
            "Delta from pulse ID in the header"
        }
    },
    {
        &hf_bld_comp_sevr,
        {
            "severity mask",
            "sevr",
            FT_UINT64,
            BASE_HEX,
            NULL,
            0x0,
            "Severity mask for channels in this packet"
        }
    }
};

/* Exported for old versions of wireshark that directly call this for us */
EXPORT_SYM void plugin_reg_handoff() {
    dissector_handle_t handle = create_dissector_handle(bld_dissect, bld_proto);
    dissector_add_uint("udp.port", DEFAULT_BLD_PORT, handle);
}

void plugin_register_proto() {
    bld_proto = proto_register_protocol("SLAC BLD", "bld", "bld");

    static int* ett[] = {
        &ett_bld,
    };

    /* Generate list of data header fields */
    static hf_register_info bld_hf_data[NUM_BLD_CHANNELS];
    static char bld_field_names[32][NUM_BLD_CHANNELS];
    for (int i = 0; i < NUM_BLD_CHANNELS; ++i) {
        snprintf(bld_field_names[i], sizeof(bld_field_names[i]), "signal%d", i);

        hf_register_info m = {
            &hf_bld_data[i],
            {
                bld_field_names[i],
                bld_field_names[i],
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "Channel data"
            }
        };
        bld_hf_data[i] = m;
    }

    /* Register protocol fields */
    proto_register_field_array(bld_proto, bld_fields, array_length(bld_fields));
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(bld_proto, bld_hf_data, array_length(bld_hf_data));
    proto_register_field_array(bld_proto, bld_comp_fields, array_length(bld_comp_fields));
}

/* Entry point-- called by wireshark on load */
EXPORT_SYM void plugin_register() {
#if WS_OLD_API
    plugin_register_proto();
#else
    static proto_plugin plugin;

    plugin.register_protoinfo = plugin_register_proto;
    plugin.register_handoff = plugin_reg_handoff;
    proto_register_plugin(&plugin);
#endif
}
