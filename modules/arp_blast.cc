#include "arp_blast.h"

#include <errno.h>

#include <packet.h>
#include <pktbatch.h>

namespace trafficgen {

CommandResponse ArpBlast::Init(const trafficgen::pb::ArpBlastArg &arg) {
  sha_ = Ethernet::Address(arg.sha());

  return CommandSuccess();
}

std::string ArpBlast::GetDesc() const {
  std::string mac_addr = sha_.ToString();
  return mac_addr;
}

void ArpBlast::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  size_t cnt = batch->cnt();
  for (size_t i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    Ethernet *ethh = pkt->head_data<Ethernet *>();
    if (ethh->ether_type != be16_t(Ethernet::Type::kArp)) {
      DropPacket(ctx, pkt);
      continue;
    }

    Arp *arph = reinterpret_cast<Arp *>(ethh + 1);
    if (arph->opcode != be16_t(Arp::Opcode::kRequest)) {
      DropPacket(ctx, pkt);
      continue;
    }

    arph->opcode = be16_t(Arp::Opcode::kReply);
    be32_t tmp_ip = arph->target_ip_addr;
    arph->target_hw_addr = arph->sender_hw_addr;
    arph->target_ip_addr = arph->sender_ip_addr;
    arph->sender_hw_addr = sha_;
    arph->sender_ip_addr = tmp_ip;

    ethh->dst_addr = ethh->src_addr;
    ethh->src_addr = sha_;

    EmitPacket(ctx, pkt, 0);
  }
}

ADD_MODULE(ArpBlast, "arp_blast", "Arp Blast")

}  // namespace trafficgen
