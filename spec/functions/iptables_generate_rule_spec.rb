require 'spec_helper'

describe 'iptables_generate_rule' do
  context "=> IPv4 => valid rules" do
    context "=> allow all traffic" do
      it {
        should run.with_params(nil,nil,'4').and_return(['-A INPUT -j ACCEPT']) 
      }
    end

    context "=> allow ssh from subnet with int and src/dest set" do
      it {
        input = { 
          'destination_port' => '22',
          'destination' => '10.0.0.0/8',
          'incoming_interface' => 'eth1',
          'protocol' => 'tcp',
          'source' => '10.0.1.0/24',
          'state' => 'NEW,REL,EST',
        }
        output = [
          "-A INPUT -i eth1 -s 10.0.1.0/24 -d 10.0.0.0/8 -p tcp --dport 22 " \
          + "-j ACCEPT" ]

        should run.with_params( input ) \
                .and_return( output )
      }
    end
    
    context "=> allow ssh from specific source and interface" do
      it {  
        input = {
          'destination_port' => '22',
          'protocol' => 'tcp',
          'source' => '10.0.1.0/24', 
          'incoming_interface' => 'eth1' }
        output = [ "-A INPUT -i eth1 -s 10.0.1.0/24 -p tcp --dport 22 " \
                  + "-j ACCEPT" ]
        should run.with_params( input ).and_return(output)
      }
    end

    context "=> allow all output" do
      it {
        input = { 'chain' => 'OUTPUT' }
        output = [ '-A OUTPUT -j ACCEPT' ]
        should run.with_params( input ).and_return( output )
      }
    end

    context "=> only allow sport 80 to connect to dport 80,443" do
      it {
        input = { 'destination_port' => '80,443', 'source_port' => '80' }
        output = [ "-A INPUT -m multiport --sport 80 --dports 80,443 " \
                 + "-j ACCEPT" ]
        should run.with_params(input).and_return(output)
      }
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

    context "=> test raw code insertion" do
      it {
        input = { 'protocol' => 'tcp',
                  'destination_port' => '32768:61000',
                  'raw' => '! --syn' }

        should run.with_params( input ) \
                  .and_return( [ "-A INPUT -p tcp --dport 32768:61000 ! " \
                                 + "--syn -j ACCEPT" ] )
      }
    end                                
  end

  # Test ip6tables rule generation below
  #
  context "=> IPv6 => valid rules" do
    context "=> allow all traffic" do
      it {
        output = [ '-A INPUT -j ACCEPT' ]
        should run.with_params( nil, nil, '6' ).and_return( output )
      }
    end

    context "=> allow ssh from specific subnet with int and src/dest set" do
      it {
        input = { 
          'protocol' => 'tcp',
          'destination_port' => '22',
          'source' => '2600::0/48',
          'destination' => '2601::0/48',
          'state' => 'NEW,REL,EST',
          'incoming_interface' => 'eth1' }
        output = [ "-A INPUT -i eth1 -s 2600::0/48 -d 2601::0/48 -p tcp " \
          + "--dport 22 -j ACCEPT" ]
        should run.with_params( input, nil, '6' )  \
                .and_return( output )
      }
    end
    
    context "=> allow ssh from specific source and interface" do
      it {
        options = {
          'protocol' => 'tcp',
          'source' => '2600::0/48',
          'state' => 'NEW,REL,EST',
          'incoming_interface' => 'eth1',
          'destination_port' => '22',
        }
        defaults = { }
        output = [ "-A INPUT -i eth1 -s 2600::0/48 -p tcp --dport 22 " \
          + "-j ACCEPT" ]
        should run.with_params( options, defaults, '6' ).and_return(output)
      }
    end

    context "=> allow all output" do
      it {
        options = { 'chain' => 'OUTPUT' }
        defaults = { }
        output = [ '-A OUTPUT -j ACCEPT' ]
        should run.with_params( options, defaults, '6' ) 
      }
    end

    context "=> only allow sport 80 to connect to dport 80,443" do
      it {
        options = {
        'source_port' => '80',
        'destination_port' => '80,443'
        }
        defaults = { }
        output = [ "-A INPUT -m multiport --sport 80 --dports 80,443 " \
                 + "-j ACCEPT" ]
        should run.with_params( options, defaults, '6' ).and_return( output )
      }
    end

    context "=> only FORWARD chain can have both in and out interfaces" do
      it {
        options = { 'incoming_interface' => 'eth1',
                    'outgoing_interface' => 'eth1' }
        defaults = { }
        should run.with_params( options, defaults, '6' ) \
          .and_raise_error(Puppet::ParseError)
      }
      it {
        options = { 'incoming_interface' => 'eth1',
                    'outgoing_interface' => 'eth1',
                    'chain' => 'FORWARD' }
        defaults = { }
        output = [ '-A FORWARD -i eth1 -o eth1 -j ACCEPT' ]
        should run.with_params(options,defaults,'6').and_return(output)
      }
    end

    context "=> comment support" do
      it {
        comment = [ 'multi', 'line',
          "a comment that will exceed 80 chars so we can test wrapping. this " \
          + "is a nice-to-have for documenting our iptables rules" ]
        output = [ '# multi', '# line',
          "# a comment that will exceed 80 chars so we can test wrapping. " \
          + "this is a nice-to",
          "# -have for documenting our iptables rules",
          '-A INPUT -j ACCEPT' ]
        input = { 'comment' => comment }
        should run.with_params( input, nil, '6' ) \
                     .and_return( output )
      }
    end

    context "=> test raw code insertion" do
      it {
        input = { 'protocol' => 'tcp',
                  'destination_port' => '32768:61000',
                  'raw' => '! --syn' }

        should run.with_params( input, '6' ) \
                  .and_return( [ "-A INPUT -p tcp --dport 32768:61000 ! " \
                                 + "--syn -j ACCEPT" ] )
      }
    end                                
  end
end
