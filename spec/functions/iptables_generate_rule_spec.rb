require 'spec_helper'

describe 'iptables_generate_rule' do
  context "=> valid rules" do
    it {
      should run.with_params( 
                        { 'protocol' => 'tcp', 
                        'destination_port' => '22', 
                        'source' => '10.0.1.0/24', 
                        'destination' => '10.0.0.0/8',
                        'state' => 'NEW,REL,EST', 
                        'action' => 'ACCEPT', 
                        'incoming_interface' => 'eth1', 
                        'chain' => 'INPUT' } ) \
                .and_return(
                        [ "-A INPUT -i eth1 -s 10.0.1.0/24 -d 10.0.0.0/8" \
                            + " -p tcp --dport 22" \
                            + " -j ACCEPT" ] )
    }
    it {  should run.with_params( { 'protocol' => 'tcp', 
                        'destination_port' => '22', 
                        'source' => '10.0.1.0/24', 
                        'state' => 'NEW,REL,EST', 
                        'action' => 'ACCEPT', 
                        'incoming_interface' => 'eth1', 
                        'chain' => 'INPUT' } ) \
                .and_return(
                  [ "-A INPUT -i eth1 -s 10.0.1.0/24 -p tcp --dport 22" \
                      + " -j ACCEPT" ] )
    }
  end
end
