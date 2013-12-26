#include "config.h"

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <epan/wmem/wmem.h>
#include <glib.h>
#include <glib/glist.h>

#define SANE_PORT 6566

#define SANE_INFO_INEXACT 0x01
#define SANE_INFO_RELOAD_OPTIONS 0x02
#define SANE_INFO_RELOAD_PARAMS 0x04

#define SANE_TYPE_BOOL 0
#define SANE_TYPE_INT 1
#define SANE_TYPE_FIXED 2
#define SANE_TYPE_STRING 3
#define SANE_TYPE_BUTTON 4
#define SANE_TYPE_GROUP 5

#define SANE_CAP_SOFT_SELECT 1
#define SANE_CAP_HARD_SELECT 2
#define SANE_CAP_SOFT_DETECT 4
#define SANE_CAP_EMULATED 8
#define SANE_CAP_AUTOMATIC 16
#define SANE_CAP_INACTIVE 32
#define SANE_CAP_ADVANCED 64

#define SANE_CONSTRAINT_NONE 0
#define SANE_CONSTRAINT_RANGE 1
#define SANE_CONSTRAINT_WORD_LIST 2
#define SANE_CONSTRAINT_STRING_LIST 3

static int proto_sane = -1;

static int hf_sane_option_capabilities = -1;
static int hf_sane_cap_soft_select = -1;
static int hf_sane_cap_hard_select = -1;
static int hf_sane_cap_soft_detect = -1;
static int hf_sane_cap_emulated = -1;
static int hf_sane_cap_automatic = -1;
static int hf_sane_cap_inactive = -1;
static int hf_sane_cap_advanced = -1;
static int hf_sane_option_constraint_type = -1;

static int hf_sane_constraint_min = -1;
static int hf_sane_constraint_max = -1;
static int hf_sane_constraint_quant = -1;
static int hf_sane_word_constraint = -1;
static int hf_sane_string_constraint = -1;

static int hf_sane_device = -1;
static int hf_sane_option_size = -1;
static int hf_sane_unit = -1;
static int hf_sane_status = -1;
static int hf_sane_opaque_response = -1;
static int hf_sane_pointer = -1;
static int hf_sane_pointer_value = -1;
static int hf_sane_option = -1;
static int hf_sane_option_value = -1;
static int hf_sane_option_name = -1;
static int hf_sane_option_title = -1;
static int hf_sane_value_length = -1;
static int hf_sane_value_type = -1;
static int hf_sane_action = -1;
static int hf_sane_option_index = -1;
static int hf_sane_set_option_info = -1;
static int hf_sane_resource = -1;
static int hf_sane_resource_handle = -1;
static int hf_sane_request = -1;
static int hf_sane_response = -1;
static int hf_sane_opcode = -1;
static int hf_sane_version = -1;
static int hf_sane_major_version = -1;
static int hf_sane_minor_version = -1;
static int hf_sane_build_number = -1;
static int hf_sane_username = -1;
static int hf_sane_option_count = -1;
static int hf_sane_option_description = -1;
static int hf_sane_device_name = -1;
static int hf_sane_device_vendor = -1;
static int hf_sane_device_model = -1;
static int hf_sane_device_type = -1;

static int hf_sane_set_option_info_inexact = -1;
static int hf_sane_set_option_info_reload_options = -1;
static int hf_sane_set_option_info_reload_params = -1;

static gint sane_tree_type = -1;
static gint sane_version_tree_type = -1;
static gint sane_message_tree_type = -1;
static gint sane_option_tree_type = -1;
static gint sane_string_tree_type = -1;
static gint sane_set_option_info_tree_type = -1;
static gint sane_option_capability_tree_type = -1;
static gint sane_device_tree_type = -1;

#define INT_TO_FIXED(x) (x / 65535.0f)

/* the names of the various SANE opcodes */
static const value_string opcode_names[] = {
    { 0, "SANE_NET_INIT" },
    { 1, "SANE_NET_GET_DEVICES" },
    { 2, "SANE_NET_OPEN" },
    { 3, "SANE_NET_CLOSE" },
    { 4, "SANE_NET_GET_OPTION_DESCRIPTORS" },
    { 5, "SANE_NET_CONTROL_OPTION" },
    { 6, "SANE_NET_GET_PARAMETERS" },
    { 7, "SANE_NET_START" },
    { 8, "SANE_NET_CANCEL" },
    { 9, "SANE_NET_AUTHORIZE" },
    { 10, "SANE_NET_EXIT" },
    { -1, NULL }
};

/* the actions that can be performed in SANE_NET_CONTROL_OPTION */
static const value_string action_names[] = {
    { 0, "SANE_ACTION_GET_VALUE" },
    { 1, "SANE_ACTION_SET_VALUE" },
    { 2, "SANE_ACTION_SET_AUTO" }
};

static const value_string constraint_type_names[] = {
    { 0, "SANE_CONSTRAINT_NONE" },
    { 1, "SANE_CONSTRAINT_RANGE" },
    { 2, "SANE_CONSTRAINT_WORD_LIST" },
    { 3, "SANE_CONSTRAINT_STRING_LIST" }
};

/* the names of value types passed to SANE_NET_CONTROL_OPTION */
static const value_string value_type_names[] = {
    { 0, "SANE_TYPE_BOOL" },
    { 1, "SANE_TYPE_INT" },
    { 2, "SANE_TYPE_FIXED" },
    { 3, "SANE_TYPE_STRING" },
    { 4, "SANE_TYPE_BUTTON" },
    { 5, "SANE_TYPE_GROUP" },
    { -1, NULL }
};

/* the SANE status enum names */
static const value_string sane_status_names[] = {
    { 0, "SANE_STATUS_GOOD" },
    { 1, "SANE_STATUS_UNSUPPORTED" },
    { 2, "SANE_STATUS_CANCELLED" },
    { 3, "SANE_STATUS_DEVICE_BUSY" },
    { 4, "SANE_STATUS_INVAL" },
    { 5, "SANE_STATUS_EOF" },
    { 6, "SANE_STATUS_JAMMED" },
    { 7, "SANE_STATUS_NO_DOCS" },
    { 8, "SANE_STATUS_COVER_OPEN" },
    { 9, "SANE_STATUS_IO_ERROR" },
    { 10, "SANE_STATUS_NO_MEM" },
    { 11, "SANE_STATUS_ACCESS_DENIED" }
};

/* SANE unit names */
static const value_string sane_unit_names[] = {
    { 0, "SANE_UNIT_NONE" },
    { 1, "SANE_UNIT_PIXELS" },
    { 2, "SANE_UNIT_BIT" },
    { 3, "SANE_UNIT_MM" },
    { 4, "SANE_UNIT_DPI" },
    { 5, "SANE_UNIT_PERCENT" },
    { 6, "SANE_UNIT_MICROSECONDS" }
};

typedef struct {
  /**
   * Contains a list of outstanding request opcodes. We use these to figure out
   * the response format.
   */
  GList *outstanding_request_opcodes;

  /**
   * Maps a position in the response stream to an opcode.
   */
  GHashTable *response_position_opcodes;
} sane_session_t;

void proto_register_sane(void) {
  static hf_register_info hf[] = {
      { &hf_sane_request, {
          "SANE Request", "sane.request", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      {&hf_sane_response, {
          "SANE Response", "sane.response", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_opcode, {
          "SANE RPC Opcode", "sane.opcode", FT_UINT32, BASE_DEC, VALS(opcode_names), 0x0, NULL, HFILL } },
      { &hf_sane_version, {
          "SANE version", "sane.version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_major_version, {
          "SANE major version", "sane.major_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_minor_version, {
          "SANE minor version", "sane.minor_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_build_number, {
          "SANE build number", "sane.build_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_username, {
          "Resource user name", "sane.username", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_resource, {
          "Resource name", "sane.resource", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_resource_handle, {
          "Resource handle", "sane.resource_handle", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_option_index, {
          "Option index", "sane.option_index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_action, {
          "Action", "sane.action", FT_UINT32, BASE_DEC, VALS(action_names), 0x0, NULL, HFILL } },
      { &hf_sane_value_type, {
          "Value type", "sane.value_type", FT_UINT32, BASE_DEC, VALS(value_type_names), 0x0, NULL, HFILL } },
      { &hf_sane_value_length, {
          "Value length (bytes)", "sane.value_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_option_value, {
          "Option value", "sane.option_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_pointer, {
          "Pointer", "sane.pointer", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_pointer_value, {
          "Pointer value", "sane.pointer_value", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
      /* a response not understood by the dissector because we couldn't find the corresponding request */
      { &hf_sane_opaque_response, {
          "Opaque response", "sane.response_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_status, {
          "Status", "sane.status", FT_UINT32, BASE_DEC, VALS(sane_status_names), 0x0, NULL, HFILL } },
      { &hf_sane_option_count, {
          "Option count", "sane.option_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_option_name, {
          "Option name", "sane.option_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_option_title, {
          "Option title", "sane.option_title", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_option, {
          "Option", "sane.option", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_option_description, {
          "Option description", "sane.option_description", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_set_option_info, {
          "Set option result flags", "sane.option.info", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_set_option_info_inexact, {
          "Option value does not exactly match requested value",
          "sane.option.inexact", FT_BOOLEAN, 8, NULL, SANE_INFO_INEXACT, NULL,
          HFILL } },
      { &hf_sane_set_option_info_reload_options, {
          "Setting this option may have affected the value of other options",
          "sane.option.reload_options", FT_BOOLEAN, 8, NULL,
          SANE_INFO_RELOAD_OPTIONS, NULL, HFILL } },
      { &hf_sane_set_option_info_reload_params, {
          "Setting this option may have affected scan parameters",
          "sane.option.reload_params", FT_BOOLEAN, 8, NULL,
          SANE_INFO_RELOAD_PARAMS, NULL, HFILL } },
      { &hf_sane_unit, {
          "Option value units", "sane.option.units", FT_UINT32, BASE_DEC, VALS(sane_unit_names), 0x0, NULL, HFILL } },
      { &hf_sane_option_size, {
          "Option size", "sane.option.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_option_capabilities, {
          "Option capabilities", "sane.option.capabilities", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_cap_soft_select, {
          "SOFT_SELECT capability, can be set by the user",
          "sane.option.capability.soft_select", FT_BOOLEAN, 8, NULL,
          SANE_CAP_SOFT_SELECT, NULL, HFILL } },
      { &hf_sane_cap_hard_select, {
          "HARD_SELECT capability, can be set by physical user intervention (e.g. flipping a switch)",
          "sane.option.capability.hard_select", FT_BOOLEAN, 8, NULL,
          SANE_CAP_HARD_SELECT, NULL, HFILL } },
      { &hf_sane_cap_soft_detect, {
          "SOFT_DETECT capability, can be detected by software",
          "sane.option.capability.soft_detect", FT_BOOLEAN, 8, NULL,
          SANE_CAP_SOFT_DETECT, NULL, HFILL } },
      { &hf_sane_cap_emulated, {
          "EMULATED, indicates functionality that may be emulated in "
          "software rather than supported natively by the device",
          "sane.option.capability.emulated", FT_BOOLEAN, 8, NULL,
          SANE_CAP_EMULATED, NULL, HFILL } },
      { &hf_sane_cap_automatic, {
          "AUTOMATIC, this device can pick a good value for this option",
          "sane.option.capability.automatic", FT_BOOLEAN, 8, NULL,
          SANE_CAP_AUTOMATIC, NULL, HFILL } },
      { &hf_sane_cap_inactive, {
          "INACTIVE, this option is not currently active",
          "sane.option.capability.inactive", FT_BOOLEAN, 8, NULL,
          SANE_CAP_INACTIVE, NULL, HFILL } },
      { &hf_sane_cap_advanced, {
          "ADVANCED, this option is intended for advanced users",
          "sane.option.capability.advanced", FT_BOOLEAN, 8, NULL,
          SANE_CAP_ADVANCED, NULL, HFILL } },
      { &hf_sane_option_constraint_type, {
          "Constraint type", "sane.option.constraint", FT_UINT32,
          BASE_DEC, VALS(constraint_type_names), 0x0, NULL, HFILL } },
      { &hf_sane_constraint_min, {
          "Minimum value", "sane.option.constraint.min", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_constraint_max, {
          "Maximum value", "sane.option.constraint.max", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_constraint_quant, {
          "Quantization value", "sane.option.constraint.quant", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_word_constraint, {
          "Valid value for this option", "sane.option.constraint.word", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_string_constraint, {
          "Valid value for this string option", "sane.option.constraint.string",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_device, {
          "Device entry", "sane.device",
          FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_device_name, {
          "Device name", "sane.device_name",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_device_vendor, {
          "Device vendor", "sane.device.vendor",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_device_model, {
          "Device model", "sane.device_model",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_sane_device_type, {
          "Device type", "sane.device_type",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } }

  };

  static gint *subtrees[] = {
      &sane_tree_type,
      &sane_version_tree_type,
      &sane_message_tree_type,
      &sane_option_tree_type,
      &sane_string_tree_type,
      &sane_set_option_info_tree_type,
      &sane_option_capability_tree_type,
      &sane_device_tree_type
  };

  proto_sane = proto_register_protocol("SANE Protocol", /* name       */
                                       "SANE", /* short name */
                                       "sane" /* abbrev     */
                                       );

  proto_register_field_array(proto_sane, hf, array_length(hf));
  proto_register_subtree_array(subtrees, array_length(subtrees));
}

static guint dissect_sane_word_and_return_item(tvbuff_t *tvb, proto_tree *tree,
                                               const int hfindex, guint offset,
                                               proto_item **item) {
  proto_item *new_item;
  new_item = proto_tree_add_item(tree, hfindex, tvb, offset, 4, ENC_BIG_ENDIAN);
  if (item) {
    *item = new_item;
  }

  return 4;
}

static guint dissect_sane_word(tvbuff_t *tvb, proto_tree *tree,
                               const int hfindex, guint offset) {
  return dissect_sane_word_and_return_item(tvb, tree, hfindex, offset, NULL);
}

/* returns whether the pointer is non-null */
static guint dissect_sane_pointer(tvbuff_t *tvb, proto_tree *tree, guint *offset) {
  guint pointer_value;
  proto_item *item;
  pointer_value = tvb_get_ntohl(tvb, *offset);
  *offset += dissect_sane_word_and_return_item(tvb, tree, hf_sane_pointer,
                                               *offset, &item);
  if (item) {
    if (!pointer_value) {
      proto_item_append_text(item, " (to null)");
    } else {
      proto_item_append_text(item, " to list of length %d", pointer_value);
    }
  }

  return pointer_value;
}

static guint dissect_sane_string(tvbuff_t *tvb, proto_tree *tree,
                                 const int hfindex, guint offset) {
  /* a string is a pointer to a null-terminated array of chars */
  guint pointer_start;
  guint pointer_value;
  guint string_start;
  proto_item *string_item;

  pointer_start = offset;

  /* parse out the pointer */
  pointer_value = dissect_sane_pointer(tvb, tree, &offset);

  /* now the string */
  string_start = offset;

  while (pointer_value && tvb_get_guint8(tvb, offset++));
  string_item = proto_tree_add_item(tree, hfindex, tvb, string_start,
                                    offset - string_start, ENC_ASCII);
  if (!pointer_value) {
    proto_item_append_string(string_item, "[empty string]");
  }

  return offset - pointer_start;
}

static guint dissect_sane_version(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  proto_item *ti;
  proto_tree *version_tree;

  ti = proto_tree_add_item(tree, hf_sane_version, tvb, offset, 4, ENC_BIG_ENDIAN);
  version_tree = proto_item_add_subtree(ti, 0);

  proto_tree_add_item(version_tree, hf_sane_major_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(version_tree, hf_sane_minor_version, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(version_tree, hf_sane_build_number, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

  return 4;
}

static guint dissect_sane_net_init(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  guint start;

  start = offset;
  offset += dissect_sane_version(tvb, tree, offset);
  offset += dissect_sane_string(tvb, tree, hf_sane_username, offset);
  return offset - start;
}

static guint dissect_sane_net_open(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  guint start;
  start = offset;
  offset += dissect_sane_string(tvb, tree, hf_sane_resource, offset);
  return offset - start;
}

static guint dissect_sane_net_open_response(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  guint start;
  start = offset;
  offset += dissect_sane_word(tvb, tree, hf_sane_status, offset);
  offset += dissect_sane_word(tvb, tree, hf_sane_resource_handle, offset);
  offset += dissect_sane_string(tvb, tree, hf_sane_username, offset);
  return offset - start;
}

static guint dissect_sane_net_close(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  proto_tree_add_item(tree, hf_sane_resource_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
  return 4;
}

static guint dissect_sane_net_get_option_descriptors(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  proto_tree_add_item(tree, hf_sane_resource_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
  return 4;
}

static guint dissect_sane_net_control_option(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  guint start;
  guint value_start;
  guint option_value_length;

  start = offset;
  proto_tree_add_item(tree, hf_sane_resource_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_sane_option_index, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_sane_action, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_sane_value_type, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  option_value_length = tvb_get_ntohl(tvb, offset);
  proto_tree_add_item(tree, hf_sane_value_length, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  dissect_sane_pointer(tvb, tree, &offset);
  value_start = offset;
  proto_tree_add_item(tree, hf_sane_option_value, tvb, value_start, option_value_length, ENC_BIG_ENDIAN);
  offset += option_value_length;

  return offset - start;
}

static guint dissect_sane_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset) {
  guint opcode;
  proto_item *message_item;
  proto_item *message_tree;
  guint message_length;
  conversation_t *conversation;
  sane_session_t *session;

  conversation = find_or_create_conversation(pinfo);
  session = (sane_session_t *) conversation_get_proto_data(conversation,
                                                           proto_sane);
  if (!session) {
    session = (sane_session_t *) wmem_alloc(wmem_file_scope(),
                                            sizeof(sane_session_t));
    session->outstanding_request_opcodes = NULL;

    // XXX - where should this be freed?
    session->response_position_opcodes = g_hash_table_new(NULL, NULL);
    conversation_add_proto_data(conversation, proto_sane, session);
  }

  message_length = 0;
  opcode = tvb_get_ntohl(tvb, offset);

  if (!pinfo->fd->flags.visited) {
    session->outstanding_request_opcodes = g_list_append(
        session->outstanding_request_opcodes, GINT_TO_POINTER(opcode));
  }

  message_length += 4;
  message_item = proto_tree_add_item(tree, hf_sane_request, tvb, offset, -1,
                                     ENC_NA);
  message_tree = proto_item_add_subtree(message_item, sane_message_tree_type);
  proto_tree_add_item(message_tree, hf_sane_opcode, tvb, offset, 4,
                      ENC_BIG_ENDIAN);
  offset += 4;

  if (opcode == 0 /* SANE_NET_INIT */) {
    message_length += dissect_sane_net_init(tvb, message_tree, offset);
  } else if (opcode == 2 /* SANE_NET_OPEN */) {
    message_length += dissect_sane_net_open(tvb, message_tree, offset);
  } else if (opcode == 3 /* SANE_NET_CLOSE */) {
    message_length += dissect_sane_net_close(tvb, message_tree, offset);
  } else if (opcode == 4 /* SANE_NET_GET_OPTION_DESCRIPTORS */) {
    message_length += dissect_sane_net_get_option_descriptors(tvb, message_tree,
                                                              offset);
  } else if (opcode == 5 /* SANE_NET_CONTROL_OPTION */) {
    message_length += dissect_sane_net_control_option(tvb, message_tree,
                                                      offset);
  }

  proto_item_set_len(message_item, message_length);
  proto_item_append_text(message_item, " [opcode=%s]",
                         val_to_str(opcode, opcode_names, "%d"));
  return message_length > 0 ? message_length : 1000;
}

static guint find_request_opcode(sane_session_t *session, packet_info *pinfo) {
  GList *first_outstanding_request;
  guint opcode;

  if (pinfo->fd->flags.visited) {
    /* XXX - this assumes that there is only one request/response per frame, fix that */
    opcode = GPOINTER_TO_INT(
        g_hash_table_lookup(session->response_position_opcodes,
                            GINT_TO_POINTER(pinfo->fd->num)));
  } else {
    /* need to look at the previous response */
    first_outstanding_request = g_list_nth(session->outstanding_request_opcodes, 0);
    if (first_outstanding_request) {
      opcode = GPOINTER_TO_INT(first_outstanding_request->data);
      session->outstanding_request_opcodes = g_list_remove_link(
          session->outstanding_request_opcodes,
          g_list_nth(session->outstanding_request_opcodes, 0));
    } else {
      opcode = -1;
    }

    /* now place the opcode in the table for later */
    /* XXX - this assumes that there is only one request/response per frame, fix that */
    g_hash_table_insert(session->response_position_opcodes,
                        GINT_TO_POINTER(pinfo->fd->num),
                        GINT_TO_POINTER(opcode));
  }

  return opcode;
}

static guint dissect_sane_status(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  proto_tree_add_item(tree, hf_sane_status, tvb, offset, 4, ENC_BIG_ENDIAN);
  return 4;
}

static guint dissect_sane_net_init_response(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  guint start;

  start = offset;
  offset += dissect_sane_status(tvb, tree, offset);
  offset += dissect_sane_version(tvb, tree, offset);

  return offset - start;
}

static guint dissect_range_constraint(tvbuff_t *tvb, proto_tree *tree,
                                      guint option_type, guint offset) {
  proto_item *min_item;
  proto_item *max_item;
  proto_item *quant_item;
  guint min;
  guint max;
  guint quant;
  guint start;

  start = offset;

  /* not sure why this is here, it doesn't appear to be called for in the spec */
  dissect_sane_pointer(tvb, tree, &offset);

  min = tvb_get_ntohl(tvb, offset);
  offset += dissect_sane_word_and_return_item(tvb, tree, hf_sane_constraint_min,
                                              offset, &min_item);

  max = tvb_get_ntohl(tvb, offset);
  offset += dissect_sane_word_and_return_item(tvb, tree, hf_sane_constraint_max,
                                              offset, &max_item);

  quant = tvb_get_ntohl(tvb, offset);
  offset += dissect_sane_word_and_return_item(tvb, tree,
                                              hf_sane_constraint_quant, offset,
                                              &quant_item);

  if (option_type == SANE_TYPE_FIXED) {
    proto_item_append_text(min_item, " (represented in fixed point: %f)", INT_TO_FIXED(min));
    proto_item_append_text(max_item, " (represented in fixed point: %f)", INT_TO_FIXED(max));
    if (quant != 0) {
      proto_item_append_text(quant_item, " (in steps of %f)", INT_TO_FIXED(quant));
    }
  }

  /* not sure why this is here, it doesn't appear to be called for in the spec */
  dissect_sane_pointer(tvb, tree, &offset);

  return offset - start;
}

static guint dissect_word_list_constraint(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  guint start;
  guint list_size;
  guint index;

  start = offset;
  list_size = dissect_sane_pointer(tvb, tree, &offset);

  /* the spec explicitly states that this value contains the length of the list */
  for (index = 0; index < list_size; index++) {
    offset += dissect_sane_word(tvb, tree, hf_sane_word_constraint, offset);
  }

  /* there is a null terminator */
  dissect_sane_pointer(tvb, tree, &offset);

  return offset - start;
}

static guint dissect_string_list_constraint(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  guint start;
  guint list_size;
  guint index;

  start = offset;

  /* the spec doesn't mention this, but there is a word
   * containing the number of strings in the list */
  list_size = dissect_sane_pointer(tvb, tree, &offset);

  for (index = 0; index < list_size; index++) {
    offset += dissect_sane_string(tvb, tree, hf_sane_string_constraint, offset);
  }

  /* there is a null terminator */
  dissect_sane_pointer(tvb, tree, &offset);

  return offset - start;
}

static guint dissect_sane_option_descriptor(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  guint start;
  proto_item *option_item;
  proto_tree *option_tree;
  proto_item *option_size_item;
  proto_item *option_capabilities_item;
  proto_tree *option_capabilities_tree;
  guint option_type;
  guint option_size;
  guint capabilities_start;
  guint constraint_type;

  start = offset;
  option_item = proto_tree_add_item(tree, hf_sane_option, tvb, offset, -1,
                                    ENC_NA);
  option_tree = proto_item_add_subtree(option_item, sane_option_tree_type);

  offset += dissect_sane_string(tvb, option_tree, hf_sane_option_name, offset);
  offset += dissect_sane_string(tvb, option_tree, hf_sane_option_title, offset);
  offset += dissect_sane_string(tvb, option_tree, hf_sane_option_description, offset);

  /* add the option's type */
  option_type = tvb_get_ntohl(tvb, offset);
  offset += dissect_sane_word(tvb, option_tree, hf_sane_value_type, offset);

  /* and its unit */
  offset += dissect_sane_word(tvb, option_tree, hf_sane_unit, offset);

  /* now the size field, whose meaning depends on the option's type */
  option_size = tvb_get_ntohl(tvb, offset);
  offset += dissect_sane_word_and_return_item(tvb, option_tree,
                                              hf_sane_option_size, offset,
                                              &option_size_item);
  switch (option_type) {
    case SANE_TYPE_STRING:
      proto_item_append_text(
          option_size_item, " (maximum length for this option including NULL)");
      break;
    case SANE_TYPE_INT:
    case SANE_TYPE_FIXED:
      proto_item_append_text(
          option_size_item,
          " (option is a vector of length %d / sizeof(SANE_WORD)) = %d",
          option_size, option_size / 4);
      break;
    case SANE_TYPE_BOOL:
      /* the spec says this must be set to sizeof(SANE_WORD) in this case */
      if (option_size != 4) {
        proto_item_append_text(
            option_size_item,
            " (invalid for boolean-type options, should be 4");
      }
      break;
    default:
      proto_item_append_text(option_size_item, " (ignored)");
  }

  /* option capabilities */
  capabilities_start = offset;
  offset += dissect_sane_word_and_return_item(tvb, option_tree,
                                              hf_sane_option_capabilities,
                                              offset,
                                              &option_capabilities_item);
  option_capabilities_tree = proto_item_add_subtree(
      option_capabilities_item, sane_option_capability_tree_type);
  proto_tree_add_item(option_capabilities_tree, hf_sane_cap_soft_select, tvb,
                      capabilities_start, 4,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(option_capabilities_tree, hf_sane_cap_hard_select, tvb,
                      capabilities_start, 4,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(option_capabilities_tree, hf_sane_cap_soft_detect, tvb,
                      capabilities_start, 4,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(option_capabilities_tree, hf_sane_cap_emulated, tvb,
                      capabilities_start, 4,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(option_capabilities_tree, hf_sane_cap_automatic, tvb,
                      capabilities_start, 4,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(option_capabilities_tree, hf_sane_cap_inactive, tvb,
                      capabilities_start, 4,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(option_capabilities_tree, hf_sane_cap_advanced, tvb,
                      capabilities_start, 4,
                      ENC_BIG_ENDIAN);

  constraint_type = tvb_get_ntohl(tvb, offset);
  offset += dissect_sane_word(tvb, option_tree, hf_sane_option_constraint_type,
                              offset);

  switch (constraint_type) {
    case SANE_CONSTRAINT_NONE:
      /* discard null pointer */
      dissect_sane_pointer(tvb, option_tree, &offset);
      break;
    case SANE_CONSTRAINT_RANGE:
      /* a range constraint follows */
      offset += dissect_range_constraint(tvb, option_tree, option_type, offset);
      break;
    case SANE_CONSTRAINT_WORD_LIST:
      /* a list of words follows */
      offset += dissect_word_list_constraint(tvb, option_tree, offset);
      break;
    case SANE_CONSTRAINT_STRING_LIST:
      /* a list of strings follows */
      offset += dissect_string_list_constraint(tvb, option_tree, offset);
      break;
  }

  proto_item_set_len(option_item, offset - start);
  return offset - start;
}

static guint dissect_sane_net_option_descriptors_response(tvbuff_t *tvb,
                                                          proto_tree *tree,
                                                          guint offset) {
  guint start;
  guint option_count;
  guint option_index;

  start = offset;
  option_count = tvb_get_ntohl(tvb, offset);
  proto_tree_add_item(tree, hf_sane_option_count, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* now a pointer to pointer to option descriptors.
   * For some reason the first level pointer is apparently null */
  dissect_sane_pointer(tvb, tree, &offset);

  for (option_index = 0; option_index < option_count; option_index++) {
    offset += dissect_sane_option_descriptor(tvb, tree, offset);
  }

  return offset - start;
}

static guint dissect_sane_net_control_option_response(tvbuff_t *tvb,
                                                      proto_tree *tree,
                                                      guint offset) {
  guint start;
  guint value_size;
  proto_item *set_option_info_item;
  proto_tree *set_option_info_tree;

  start = offset;
  offset += dissect_sane_status(tvb, tree, offset);

  set_option_info_item = proto_tree_add_item(tree, hf_sane_set_option_info, tvb,
                                             offset, 4, ENC_NA);
  set_option_info_tree = proto_item_add_subtree(set_option_info_item,
                                                sane_set_option_info_tree_type);

  proto_tree_add_item(set_option_info_tree, hf_sane_set_option_info_inexact,
                      tvb, offset, 1, ENC_NA);
  proto_tree_add_item(set_option_info_tree,
                      hf_sane_set_option_info_reload_options, tvb, offset, 1,
                      ENC_NA);
  proto_tree_add_item(set_option_info_tree,
                      hf_sane_set_option_info_reload_params, tvb, offset, 1,
                      ENC_NA);
  offset += 4;

  offset += dissect_sane_word(tvb, tree, hf_sane_value_type, offset);

  value_size = tvb_get_ntohl(tvb, offset);
  offset += dissect_sane_word(tvb, tree, hf_sane_value_length, offset);

  dissect_sane_pointer(tvb, tree, &offset);
  proto_tree_add_item(tree, hf_sane_option_value, tvb, offset, value_size,
                      ENC_NA);
  offset += value_size;
  offset += dissect_sane_string(tvb, tree, hf_sane_resource, offset);

  return offset - start;
}

static guint dissect_sane_net_get_devices_response(tvbuff_t *tvb, proto_tree *tree, guint offset) {
  guint device_count;
  guint device_start;
  guint index;
  guint start;
  proto_item *device_item;
  proto_tree *device_tree;

  start = offset;
  offset += dissect_sane_status(tvb, tree, offset);
  device_count = dissect_sane_pointer(tvb, tree, &offset);

  for (index = 0; index < device_count - 1; index++) {
    device_start = offset;
    device_item = proto_tree_add_item(tree, hf_sane_device, tvb, offset, -1, ENC_NA);
    device_tree = proto_item_add_subtree(device_item, sane_device_tree_type);

    dissect_sane_pointer(tvb, device_tree, &offset);
    offset += dissect_sane_string(tvb, device_tree, hf_sane_device_name, offset);
    offset += dissect_sane_string(tvb, device_tree, hf_sane_device_vendor, offset);
    offset += dissect_sane_string(tvb, device_tree, hf_sane_device_model, offset);
    offset += dissect_sane_string(tvb, device_tree, hf_sane_device_type, offset);
    proto_item_set_len(device_item, offset - device_start);
  }

  /* read off the null pointer that is present if the array is non-empty */
  /* remember, the device_count contains the null pointer in the count */
  if (device_count > 1) {
    dissect_sane_pointer(tvb, tree, &offset);
  }

  return offset - start;
}

static guint dissect_sane_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset) {
  conversation_t *conversation;
  sane_session_t *session;
  proto_item *item;
  guint opcode;
  guint start;

  start = offset;

  conversation = find_or_create_conversation(pinfo);
  session = (sane_session_t *) conversation_get_proto_data(conversation, proto_sane);

  if (!session || !session->outstanding_request_opcodes) {
    item = proto_tree_add_item(tree, hf_sane_opaque_response, tvb, offset,
                                     tvb_reported_length(tvb), ENC_NA);
    return tvb_reported_length(tvb);
  } else {
    opcode = find_request_opcode(session, pinfo);

    item = proto_tree_add_item(tree, hf_sane_response, tvb, offset,
                                     tvb_reported_length(tvb), ENC_NA);
    proto_item_append_text(item, " to opcode [%s (%d)]",
                           val_to_str(opcode, opcode_names, "UNKNOWN"), opcode);

    if (opcode == 0 /* SANE_NET_INIT */) {
      offset += dissect_sane_net_init_response(tvb, tree, offset);
    } else if (opcode == 1 /* SANE_NET_GET_DEVICES */) {
      offset += dissect_sane_net_get_devices_response(tvb, tree, offset);
    } else if (opcode == 2 /* SANE_NET_OPEN */) {
      offset += dissect_sane_net_open_response(tvb, tree, offset);
    } else if (opcode == 4 /* SANE_NET_GET_OPTION_DESCRIPTORS */) {
      offset += dissect_sane_net_option_descriptors_response(tvb, tree, offset);
    } else if (opcode == 5 /* SANE_NET_CONTROL_OPTION */) {
      offset += dissect_sane_net_control_option_response(tvb, tree, offset);
    } else {
      offset = tvb_reported_length(tvb);
    }

    proto_item_set_len(item, offset - start);
    return offset - start;
  }
}

static void dissect_sane(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gboolean is_request;
  guint offset;
  proto_item *sane_tree;
  guint pdu_length;

  sane_tree = NULL;

  is_request = (pinfo->match_uint == pinfo->destport);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SANE");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  if (tree) {
    proto_item *ti;

    ti = proto_tree_add_item(tree, proto_sane, tvb, 0, -1, ENC_NA);
    sane_tree = proto_item_add_subtree(ti, sane_tree_type);
  }

  while (offset < tvb_length(tvb)) {
    if (is_request) {
      pdu_length = dissect_sane_request(tvb, pinfo, sane_tree, offset);
    } else {
      pdu_length = dissect_sane_response(tvb, pinfo, sane_tree, offset);
    }

    offset += pdu_length;
  }
}

void proto_reg_handoff_sane(void) {
  static dissector_handle_t sane_handle;
  sane_handle = create_dissector_handle(dissect_sane, proto_sane);

  dissector_add_uint("tcp.port", SANE_PORT, sane_handle);
}
