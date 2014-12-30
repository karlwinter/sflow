class SflowCollector
  module Collector
  Thread.abort_on_exception=true
  require 'socket'
    def post_init
      puts "Server listening."
    end

    def receive_data(data)
      operation = proc do
        begin
          if data != nil
            sflow = SflowParser.parse_datagram(data)
          end
        rescue Exception => e
          puts Time.now
          puts sflow.inspect
          puts e.message
          puts e.backtrace
        end
      end

      callback = proc do |sflow|
        begin
          if sflow != nil
            sflow["samples"].each do |sample|
              sample["eth_packets"].each do |packet|
                flow_data = {
                    "agent_address" => sflow["agent_address"],
                    "sub_agent_id" => sflow["sub_agent_id"],

                    "sampling_rate" => sample["sampling_rate"],
                    "frame_length" => sample["frame_length"],
                    "total_frame_length" => sample["sampling_rate"] * sample["frame_length"],
                    "i_iface_value" => sample["i_iface_value"],
                    "o_iface_value" => sample["o_iface_value"],

                    "sndr_addr" => packet["sndr_addr"],
                    "dest_addr" => packet["dest_addr"],
                    "protocol" => packet["protocol"]
                }

                if packet["protocol"] == 6 # tcp
                  flow_data.merge!({
                      "tcp_sndr_port" => packet["tcp"].sndr_port,
                      "tcp_dest_port" => packet["tcp"].dest_port,
                      "tcp_urg" => packet["tcp"].urg,
                      "tcp_ack" => packet["tcp"].ack,
                      "tcp_psh" => packet["tcp"].psh,
                      "tcp_rst" => packet["tcp"].rst,
                      "tcp_syn" => packet["tcp"].syn,
                      "tcp_fin" => packet["tcp"].fin
                  })
                elsif packet["protocol"] == 17 # udp
                  flow_data.merge!({
                      "udp_sndr_port" => packet["udp"].sndr_port,
                      "udp_dest_port" => packet["udp"].dest_port
                   })
                end

                SflowStorage.send_udpjson(flow_data)
              end
            end
          end
        rescue Exception => e
          puts Time.now
          puts sflow.inspect if sflow != nil
          puts e.message
          puts e.backtrace
        end
      end

      EM.defer(operation,callback)

    end
  end

  def self.start_collector(bind_ip = '0.0.0.0', bind_port = 6343)
    begin
      config = SflowConfig.new
      if config.logstash_host and config.logstash_port 
        puts "Connecting to Logstash: #{config.logstash_host}:#{config.logstash_port}"
        $logstash = UDPSocket.new
        $logstash.connect(config.logstash_host, config.logstash_port)
      else
        puts "no host:port given"
        exit 1
      end
      $switch_hash = config.switch_hash
      # if config.switch_hash != nil
      #   $switchportnames = SNMPwalk.new(config.switch_hash.each_key)
      # end
      EventMachine::run do
        EventMachine::open_datagram_socket(bind_ip, bind_port, Collector)
      end
    rescue Exception => e
      puts Time.now
      puts e.message
      puts e.backtrace
      raise "unable to start sflow collector"
    end
  end

end


