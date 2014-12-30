class SflowStorage
  require 'json'

  def self.send_udpjson(sflow)

  #remap hash-keys with prefix "sflow_"
      # mappings = {
      #     "agent_address" => "agent_address",
      #     "sub_agent_id" => "sub_agent_id",
      #     "sampling_rate" => "sample_ratio",
      #     "frame_length" => "packet_size",
      # }

      # prefixed_sflow = Hash[sflow.map {|k, v| [mappings[k], v] }]

      # if sflow['i_iface_value'] and sflow['o_iface_value']
      #   i_iface_name = {"sflow_i_iface_name" => SNMPwalk.mapswitchportname(sflow['agent_address'],sflow['i_iface_value'])}
      #   o_iface_name = {"sflow_o_iface_name" => SNMPwalk.mapswitchportname(sflow['agent_address'],sflow['o_iface_value'])}
      #   prefixed_sflow.merge!(i_iface_name)
      #   prefixed_sflow.merge!(o_iface_name)
      # end

      $logstash.send(sflow.to_json, 0)

  end

end
