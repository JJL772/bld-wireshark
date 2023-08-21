/**
 * Wireshark plugin for analysis of the SLAC BLD protocol
 * @author Jeremy Lorelli
 * @date July 25th, 2023
 */

#include <epan/packet.h>
#include <epan/epan_dissect.h>

/* Compat with <4.0 */
#ifndef WIRESHARK_VERSION_MAJOR
#   include <wireshark/config.h>
#   define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#   define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

#if WIRESHARK_VERSION_MAJOR < 2 || (WIRESHARK_VERSION_MAJOR == 2 && WIRESHARK_VERSION_MINOR < 1)
#   define WS_OLD_API 1
#else
#   define WS_OLD_API 0
#endif

#if !WS_OLD_API
#   include <epan/plugin_if.h>
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

typedef enum {
    BLD_UINT32 = 0,
    BLD_FLOAT32,

    BLD_FORMAT_COUNT,
} bld_format_t;

static int bld_proto = -1;

static int hf_bld_ts = -1;
static int hf_bld_pulseid = -1;
static int hf_bld_version = -1;
static int hf_bld_sevr = -1;
static int ett_bld = -1;
static int hf_bld_data[NUM_BLD_CHANNELS*BLD_FORMAT_COUNT] = {-1};

static int hf_bld_comp_ts = -1;
static int hf_bld_comp_pulseid = -1;
static int hf_bld_comp_sevr = -1;

static int bld_num_channels = -1;
static bld_format_t bld_channel_formats[NUM_BLD_CHANNELS];

#if WS_OLD_API
#   define create_dissector_handle new_create_dissector_handle
#endif

#if !WS_OLD_API /* Only needed for toolbar callbacks */
static int clamp(int val, int l, int h) {
    return val < l ? l : (val > h ? h : val);
}
#endif // !WS_OLD_API

static int get_bld_hf_data(int channel) {
    return bld_channel_formats[channel] == BLD_UINT32 ? hf_bld_data[channel * 2] : hf_bld_data[channel * 2 + 1];
}

static int bld_get_num_channels(size_t length) {
    if (bld_num_channels >= 0)
        return bld_num_channels;

    // We are being asked to infer channel count
    return length <= sizeof(bldMulticastPacket_t) ? (length - bldMulticastPacketHeaderSize) / sizeof(uint32_t) : NUM_BLD_CHANNELS;
}

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

    const int numItems = bld_get_num_channels(length);

    /* Add the channel's payload now */
    if (numItems > 0) {
        char label[128];
        snprintf(label, sizeof(label), "Channel data (%d channels)", numItems);
        proto_tree* datasub = 
#if WS_OLD_API
            tree;
#else
            proto_tree_add_subtree(tree, tvb, offset, numItems, ett_bld, NULL, label);
#endif
    	for (int i = 0; i < numItems; ++i) {
            proto_tree_add_item(datasub, get_bld_hf_data(i), tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
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

        char label[128];
        snprintf(label, sizeof(label), "Channel data (%d channels)", numItems);
        proto_tree* datasub =
        #if WS_OLD_API
            ctree;
        #else
            proto_tree_add_subtree(ctree, tvb, offset, numItems, ett_bld, NULL, label);
        #endif
        for (int i = 0; i < numItems; ++i) {
            proto_tree_add_item(datasub, get_bld_hf_data(i), tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
            offset += sizeof(uint32_t);
        }
    }

    return tvb_captured_length(tvb);
}

static hf_register_info bld_fields[] = {
    {
        &hf_bld_ts,
        {
            "Timestamp",
            "bld.timestamp",
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
            "Pulse ID",
            "bld.pulse_id",
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
            "Version",
            "bld.version",
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
            "Severity mask",
            "bld.severity_mask",
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
            "Timestamp delta",
            "bld.ev.timestamp_delta",
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
            "Pulse ID delta",
            "bld.ev.pulse_id_delta",
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
            "Severity mask",
            "bld.ev.severity_mask",
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
#if WS_OLD_API
    dissector_add_uint("udp.port", DEFAULT_BLD_PORT, handle);
#else
    dissector_add_uint_with_preference("udp.port", DEFAULT_BLD_PORT, handle);
#endif // WS_OLD_API
}

#if !WS_OLD_API
static void toolbar_channels_changed_callback(gpointer toolbar_item, gpointer item_data, gpointer user_data);
static void toolbar_channel_count_changed_callback(gpointer toolbar_item, gpointer item_data, gpointer user_data);
#endif // !WS_OLD_API

void plugin_register_proto() {
    bld_proto = proto_register_protocol("SLAC BLD", "BLD", "bld");

    static int* ett[] = {
        &ett_bld,
    };

    /* Generate list of data header fields */
    static hf_register_info bld_hf_data[NUM_BLD_CHANNELS*BLD_FORMAT_COUNT];
    static char bld_field_names[32][NUM_BLD_CHANNELS];
    static char bld_field_abbv[32][NUM_BLD_CHANNELS];
    
    for (int i = 0; i < NUM_BLD_CHANNELS * BLD_FORMAT_COUNT; i += BLD_FORMAT_COUNT) {
        int nameIndex = i / BLD_FORMAT_COUNT;
        snprintf(bld_field_names[nameIndex], sizeof(bld_field_names[nameIndex]), "signal%d", nameIndex);
        snprintf(bld_field_abbv[nameIndex], sizeof(bld_field_abbv[nameIndex]), "data.signal%d", nameIndex);

        /* int32 format */
        hf_register_info ui = {
            &hf_bld_data[i],
            {
                bld_field_names[nameIndex],
                bld_field_abbv[nameIndex],
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "Channel data"
            }
        };
        bld_hf_data[i] = ui;

        /* Floating point format */
        hf_register_info fl = {
            &hf_bld_data[i+1],
            {
                bld_field_names[nameIndex],
                bld_field_abbv[nameIndex],
                FT_FLOAT,
                BASE_DEC,
                NULL,
                0x0,
                "Channel data"
            }
        };
        bld_hf_data[i+1] = fl;
    }

    /* Register protocol fields */
    proto_register_field_array(bld_proto, bld_fields, array_length(bld_fields));
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(bld_proto, bld_hf_data, array_length(bld_hf_data));
    proto_register_field_array(bld_proto, bld_comp_fields, array_length(bld_comp_fields));

#if !WS_OLD_API
    /* Add BLD toolbar for changing channel formats, count, etc */
    ext_toolbar_t* toolbar = ext_toolbar_register_toolbar("BLD Protocol");
    ext_toolbar_add_entry(toolbar, EXT_TOOLBAR_STRING, "Channel Formats", "", "Comma separated list defining channel formats. e.g. f, u, f means channel 0 will be float, 1 will be int, and 2 will be float",
        FALSE, NULL, FALSE, "^(f|u)(,?\\s*(f|u))*$", toolbar_channels_changed_callback, NULL);

    /* Add first "autodetect" entry */
    GList* vals = NULL;
    vals = ext_toolbar_add_val(vals, "-1", "autodetect", TRUE);

    for (int i = 0; i <= NUM_BLD_CHANNELS; ++i) {
        char label[128];
        char value[128];
        snprintf(label, sizeof(label), "%d channels", i);
        snprintf(value, sizeof(value), "%d", i);
        vals = ext_toolbar_add_val(vals, value, label, FALSE);
    }
    
    ext_toolbar_add_entry(toolbar, EXT_TOOLBAR_SELECTOR, "Channel Count", "-1", "Number of channels in the packet", FALSE, vals, FALSE, NULL, toolbar_channel_count_changed_callback, NULL);
#endif // !WS_OLD_API
}

#if !WS_OLD_API
static void toolbar_channels_changed_callback(gpointer toolbar_item, gpointer item_data, gpointer user_data) {
    gchar* str = (gchar*)item_data;

    /* Fill formats with default */
    for (int i = 0; i < array_length(bld_channel_formats); ++i)
        bld_channel_formats[i] = BLD_UINT32;

    int i = 0;
    /* Given a string in the format "f, u, f, f, u" or "fuffu" or "f u f f u", determine channel formats */
    for (gchar* s = str; *s; s++) {
        if (*s == ' ' || *s == ',')
            continue;
        switch(*s) {
        case 'f':
            bld_channel_formats[i++] = BLD_FLOAT32;
            break;
        case 'u':
            bld_channel_formats[i++] = BLD_UINT32;
            break;
        default:
            break; /* Shouldn't ever get here unless the regexp is screwed up */
        }
    }
}

static void toolbar_channel_count_changed_callback(gpointer toolbar_item, gpointer item_data, gpointer user_data) {
    bld_num_channels = clamp(strtod((gchar*)item_data, NULL), -1, NUM_BLD_CHANNELS);
}
#endif // !WS_OLD_API

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
