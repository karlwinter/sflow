class SflowStorage
  require 'json'

  def self.send_udpjson(sflow)

  #remap hash-keys with prefix "sflow_"
      mappings = {"agent_address" => "agent_address",
                  "sub_agent_id" => "sub_agent_id",
                  "sampling_rate" => "sample_ratio",
                  "i_iface_value" => "iif",
                  "o_iface_value" => "oif",
                  # "vlan_src" => "sflow_vlan_src",
                  # "vlan_dst" => "sflow_vlan_dst",
                  "ipv4_src" => "srcip",
                  "ipv4_dst" => "dstip",
                  "frame_length" => "packet_size",
                  "frame_length_multiplied" => "total_data",
                  "ip_type" => "ip_type",
                  "tcp_src_port" => "tcp_srcport",
                  "tcp_dst_port" => "tcp_dstport",
                  "tcp_urg" => "tcp_urg",
                  "tcp_ack" => "tcp_ack",
                  "tcp_psh" => "tcp_psh",
                  "tcp_rst" => "tcp_rst",
                  "tcp_syn" => "tcp_syn",
                  "tcp_fin" => "tcp_fin",
                  "udp_src_port" => "udp_srcport",
                  "udp_dst_port" => "udp_dstport",
                  #"i_octets" => "sflow_i_octets",
                  #"o_octets" => "sflow_o_octets",
                  #"interface" => "sflow_interface",
                  #"input_packets_error" => "sflow_input_packets_error",
                  #"output_packets_error" => "sflow_output_packets_error"

      }

      prefixed_sflow = Hash[sflow.map {|k, v| [mappings[k], v] }]

      # if sflow['i_iface_value'] and sflow['o_iface_value']
      #   i_iface_name = {"sflow_i_iface_name" => SNMPwalk.mapswitchportname(sflow['agent_address'],sflow['i_iface_value'])}
      #   o_iface_name = {"sflow_o_iface_name" => SNMPwalk.mapswitchportname(sflow['agent_address'],sflow['o_iface_value'])}
      #   prefixed_sflow.merge!(i_iface_name)
      #   prefixed_sflow.merge!(o_iface_name)
      # end

      $logstash.send(prefixed_sflow.to_json, 0)

  end

end
