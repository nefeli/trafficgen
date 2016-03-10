/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: proto/job.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "job.pb-c.h"
void   job__init
                     (Job         *message)
{
  static Job init_value = JOB__INIT;
  *message = init_value;
}
size_t job__get_packed_size
                     (const Job *message)
{
  assert(message->base.descriptor == &job__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t job__pack
                     (const Job *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &job__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t job__pack_to_buffer
                     (const Job *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &job__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Job *
       job__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Job *)
     protobuf_c_message_unpack (&job__descriptor,
                                allocator, len, data);
}
void   job__free_unpacked
                     (Job *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &job__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor job__field_descriptors[13] =
{
  {
    "tx_rate",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(Job, has_tx_rate),
    offsetof(Job, tx_rate),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "duration",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(Job, has_duration),
    offsetof(Job, duration),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "warmup",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(Job, has_warmup),
    offsetof(Job, warmup),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "num_flows",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(Job, has_num_flows),
    offsetof(Job, num_flows),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "size_min",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(Job, has_size_min),
    offsetof(Job, size_min),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "size_max",
    6,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(Job, has_size_max),
    offsetof(Job, size_max),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "life_min",
    7,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_FLOAT,
    offsetof(Job, has_life_min),
    offsetof(Job, life_min),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "life_max",
    8,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_FLOAT,
    offsetof(Job, has_life_max),
    offsetof(Job, life_max),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "randomize",
    9,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(Job, has_randomize),
    offsetof(Job, randomize),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "latency",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(Job, has_latency),
    offsetof(Job, latency),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "online",
    11,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(Job, has_online),
    offsetof(Job, online),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "stop",
    12,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(Job, has_stop),
    offsetof(Job, stop),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "print",
    13,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(Job, has_print),
    offsetof(Job, print),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned job__field_indices_by_name[] = {
  1,   /* field[1] = duration */
  9,   /* field[9] = latency */
  7,   /* field[7] = life_max */
  6,   /* field[6] = life_min */
  3,   /* field[3] = num_flows */
  10,   /* field[10] = online */
  12,   /* field[12] = print */
  8,   /* field[8] = randomize */
  5,   /* field[5] = size_max */
  4,   /* field[4] = size_min */
  11,   /* field[11] = stop */
  0,   /* field[0] = tx_rate */
  2,   /* field[2] = warmup */
};
static const ProtobufCIntRange job__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 13 }
};
const ProtobufCMessageDescriptor job__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "Job",
  "Job",
  "Job",
  "",
  sizeof(Job),
  13,
  job__field_descriptors,
  job__field_indices_by_name,
  1,  job__number_ranges,
  (ProtobufCMessageInit) job__init,
  NULL,NULL,NULL    /* reserved[123] */
};
