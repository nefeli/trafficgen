/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: proto/status.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "status.pb-c.h"
void   status__init
                     (Status         *message)
{
  static Status init_value = STATUS__INIT;
  *message = init_value;
}
size_t status__get_packed_size
                     (const Status *message)
{
  assert(message->base.descriptor == &status__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t status__pack
                     (const Status *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &status__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t status__pack_to_buffer
                     (const Status *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &status__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Status *
       status__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Status *)
     protobuf_c_message_unpack (&status__descriptor,
                                allocator, len, data);
}
void   status__free_unpacked
                     (Status *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &status__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCEnumValue status__type__enum_values_by_number[2] =
{
  { "FAIL", "STATUS__TYPE__FAIL", 0 },
  { "SUCCESS", "STATUS__TYPE__SUCCESS", 1 },
};
static const ProtobufCIntRange status__type__value_ranges[] = {
{0, 0},{0, 2}
};
static const ProtobufCEnumValueIndex status__type__enum_values_by_name[2] =
{
  { "FAIL", 0 },
  { "SUCCESS", 1 },
};
const ProtobufCEnumDescriptor status__type__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "Status.Type",
  "Type",
  "Status__Type",
  "",
  2,
  status__type__enum_values_by_number,
  2,
  status__type__enum_values_by_name,
  1,
  status__type__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};
static const ProtobufCFieldDescriptor status__field_descriptors[1] =
{
  {
    "type",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_ENUM,
    offsetof(Status, has_type),
    offsetof(Status, type),
    &status__type__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned status__field_indices_by_name[] = {
  0,   /* field[0] = type */
};
static const ProtobufCIntRange status__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor status__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "Status",
  "Status",
  "Status",
  "",
  sizeof(Status),
  1,
  status__field_descriptors,
  status__field_indices_by_name,
  1,  status__number_ranges,
  (ProtobufCMessageInit) status__init,
  NULL,NULL,NULL    /* reserved[123] */
};
