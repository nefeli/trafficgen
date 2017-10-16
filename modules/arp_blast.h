// Copyright (c) 2018, Nefeli Networks, Inc. All rights reserved.

#ifndef TRAFFICGEN_MODULES_ARP_BLAST_
#define TRAFFICGEN_MODULES_ARP_BLAST_

#include "pb/arp_blast_msg.pb.h"

#include <string>

#include <module.h>
#include <pb/module_msg.pb.h>
#include <utils/arp.h>
#include <utils/endian.h>
#include <utils/ether.h>
#include <utils/ip.h>

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Arp;
using bess::utils::Ethernet;

namespace trafficgen {

// LoadBalancer reads entries in the ASID field of NSH headers and sends packets
// to output gates equal to the values found.
class ArpBlast final : public Module {
 public:
  ArpBlast() : Module(), sha_() {
    max_allowed_workers_ = Worker::kMaxWorkers;
  }

  CommandResponse Init(const trafficgen::pb::ArpBlastArg &arg);

  std::string GetDesc() const override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  Ethernet::Address sha_;
};

}  // namespace trafficgen

#endif  // TRAFFICGEN_MODULES_ARP_BLAST_
