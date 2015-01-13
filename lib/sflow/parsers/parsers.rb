class SflowParser
  require 'ipaddr'
  def self.parse_datagram(data)
    header = Header.read(data)

    if header.version == 5
      agent_address = IPAddr.new(header.agent_address, Socket::AF_INET).to_s
      @sflow = {
          "agent_address" => agent_address,
          "sub_agent_id" => header.sub_agent_id.to_i,
          "samples" => [],
          "counters" => [],
          "flows" => []
      }

      header.flow_samples.each do |sample|
        if sample.sflow_sample_type ==  1
          @sflow["samples"] << self.parse_sample_data(sample.sample_data)
        elsif sample.sflow_sample_type == 2
          @sflow["counters"] << self.parse_counter_data(sample.sample_data)
        elsif sample.sflow_sample_type == 3
          @sflow["flows"] << self.parse_flow_data(sample.sample_data)
        end
      end
    end

    return @sflow
  end

  # Parse sample data
  def self.parse_sample_data(data)
    sample_data = Sflow5sampleheader1.read(data)

    sample = {
        "seq_number" => sample_data.seq_number,
        "source_id_type" => sample_data.source_id_type,
        "sampling_rate" => sample_data.sampling_rate.to_i,
        "sample_pool" => sample_data.sample_pool,
        "dropped_packets" => sample_data.dropped_packets,
        "i_iface_value" => sample_data.i_iface_value.to_i,
        "o_iface_value" => sample_data.o_iface_value.to_i,
        "eth_packets" => []
    }

    sample_data.records.each do |record|
      if record.format == 1 # flow_sample
        raw_packet = Sflow5rawpacket.read(record.record_data)

        sample["frame_length"] = raw_packet.frame_length.to_i

        if raw_packet.header_protocol == 1 # Ethernet
          sample["eth_packets"] << self.parse_sample_eth_packet(raw_packet.rawpacket_data.to_ary.join)
        end
      end
    end

    return sample
  end

  # Parse sample ethernet packet of sample data
  def self.parse_sample_eth_packet(data)
    eth_header = Sflow5rawpacketheaderEthernet.read(data)
    ip_packet = eth_header.ethernetdata.to_ary.join
    if eth_header.eth_type == 33024 #VLAN TAG
      vlan_header = Sflow5rawpacketdataVLAN.read(eth_header.ethernetdata.to_ary.join)
      ip_packet = vlan_header.vlandata.to_ary.join
    end

    ipv4 = IPv4Header.new(ip_packet)

    packet = {
        "version" => ipv4.version,
        "header_length" => ipv4.header_length,
        "packet_length" => ipv4.packet_length,
        "protocol" => ipv4.protocol,
        "src_addr" => ipv4.src_addr,
        "dst_addr" => ipv4.dst_addr
    }

    if ipv4.protocol == 6
      packet['tcp'] = TCPHeader.new(ipv4.data)
    elsif ipv4.protocol == 17
      packet['udp'] = UDPHeader.new(ipv4.data)
    end

    return packet
  end

  # Parse counter data
  def self.parse_counter_data(data)
    counter_data = Sflow5counterheader2.read(data)

    counter = {
        "seq_number" => counter_data.seq_number,
        "source_id_type" => counter_data.source_id_type,
        "if_counters" => [],
        "eth_counters" => []
    }

    counter_data.records.each do |record|
      if record.format == 1 # if_counter
        if_counter = Sflow5genericcounter.read(record.record_data)

        c = {}
        if_counter.each_pair { |key, val|
          c[key] = val.to_i
        }

        counter["if_counters"] << c
      elsif record.format == 2 # ethernet_counter
        eth_counter = Sflow5ethcounter.read(record.record_data)

        c = {}
        eth_counter.each_pair { |key, val|
          c[key] = val.to_i
        }

        counter["eth_counters"] << c
      end
    end

    return counter
  end

  # Parse flow data
  def self.parse_flow_data(data)
    flow_data = Sflow5sampleheader3.read(data)

    flow = {
        "seq_number" => flow_data.seq_number,
        "source_id_type" => flow_data.source_id_type,
        "source_id_index" => flow_data.source_id_index,
        "sampling_rate" => flow_data.sampling_rate,
        "sample_pool" => flow_data.sample_pool,
        "dropped_packets" => flow_data.dropped_packets,
        "i_iface_format" => flow_data.i_iface_format,
        "o_iface_format" => flow_data.o_iface_format,
        "ext_switches" => []
    }

    flow_data.records.each do |record|
      if record.format == 1001 # Extended switch
        flow["ext_switches"] << Sflow5extswitch.read(record.record_data)
      end
    end

    return flow
  end
end
