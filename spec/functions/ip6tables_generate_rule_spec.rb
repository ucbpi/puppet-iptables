require 'spec_helper'

describe 'ip6tables_generate_rule' do
  context "=> valid rules" do
    context "=> allow all traffic" do
      it {
        should run.with_params( { 'action' => 'ACCEPT' } ) \
                  .and_return(["-A INPUT -j ACCEPT"])
      }
    end

    context "=> allow ssh from specific subnet with int and src/dest set" do
      it {
        should run.with_params( { 'protocol' => 'tcp', 
                        'destination_port' => '22', 
                        'source' => '2600::0/48', 
                        'destination' => '2601::0/48',
                        'state' => 'NEW,REL,EST', 
                        'action' => 'ACCEPT', 
                        'incoming_interface' => 'eth1', 
                        'chain' => 'INPUT' } ) \
                .and_return(
                        [ "-A INPUT -i eth1 -s 2600::0/48 -d 2601::0/48" \
                            + " -p tcp --dport 22" \
                            + " -j ACCEPT" ] )
      }
    end
    
    context "=> allow ssh from specific source and interface" do
      it {  should run.with_params( { 'protocol' => 'tcp', 
                        'destination_port' => '22', 
                        'source' => '2600::0/48', 
                        'state' => 'NEW,REL,EST', 
                        'action' => 'ACCEPT', 
                        'incoming_interface' => 'eth1', 
                        'chain' => 'INPUT' } ) \
                .and_return(
                  [ "-A INPUT -i eth1 -s 2600::0/48 -p tcp --dport 22" \
                      + " -j ACCEPT" ] )
      }
    end

    context "=> allow all output" do
      it { should run.with_params( { 'chain' => 'OUTPUT' } ) \
                     .and_return( [ '-A OUTPUT -j ACCEPT' ] ) }
    end

    context "=> only allow sport 80 to connect to dport 80,443" do
      it { should run.with_params( { 'source_port' => '80',
                                  'destination_port' => [ '80','443' ] } ) \
                     .and_return( [ "-A INPUT -m multiport --sport 80" \
                                    + " --dports 80,443 -j ACCEPT" ] ) }
    end

    context "=> only FORWARD chain can have both in and out interfaces" do
      it { should run.with_params( { 'incoming_interface' => 'eth1',
                                     'outgoing_interface' => 'eth1' } ) \
                     .and_raise_error( Puppet::ParseError ) }
      it { should run.with_params( { 'incoming_interface' => 'eth1',
                                     'outgoing_interface' => 'eth1',
                                     'chain' => 'FORWARD' } ) \
                     .and_return( [ '-A FORWARD -i eth1 -o eth1 -j ACCEPT' ]) }
    end

    context "=> comment support" do
      it { should run.with_params( { 'comment' => [ 
                                  'multi', 
                                  'line',
                                  "comment that will exceed 80 chars so we " \
                                  + "can test wrapping.  this is a " \
                                  + "nice-to-have for documenting our " \
                                  + "iptables rules" ] } ) \
                     .and_return( [ '# multi', '# line',
                                    "# comment that will exceed 80 chars so " \
                                    + "we can test wrapping.  this is a " \
                                    + "nice-to-", "# have for documenting " \
                                    + "our iptables rules", \
                                    "-A INPUT -j ACCEPT" ] ) 
      }
    end
                                    
  end
end
