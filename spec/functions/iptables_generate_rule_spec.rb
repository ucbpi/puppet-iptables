require 'spec_helper'

describe 'iptables_generate_rule' do
  context "=> IPv4 => valid rules" do
    context "=> allow all traffic" do
      it {
        input = { 'action' => 'ACCEPT', 'chain' => 'INPUT' }
        should run.with_params(input,'4').and_return(['-A INPUT -j ACCEPT'])
      }
    end

    context "=> allow ssh from subnet with int and src/dest set" do
      it {
        input = {
          'chain' => 'INPUT',
          'action' => 'ACCEPT',
          'destination_port' => '22',
          'destination' => '10.0.0.0/8',
          'incoming_interface' => 'eth1',
          'protocol' => 'tcp',
          'source' => '10.0.1.0/24',
          'state' => 'NEW,REL,EST',
        }
        output = [
          "-A INPUT -i eth1 -s 10.0.1.0/24 -d 10.0.0.0/8 -p tcp --dport 22 " \
          + "-m state --state NEW,REL,EST -j ACCEPT" ]

        should run.with_params( input ) \
                .and_return( output )
      }
    end

    context "=> allow ssh from specific source and interface" do
      it {
        input = {
          'chain' => 'INPUT',
          'action' => 'ACCEPT',
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
        input = { 'chain' => 'OUTPUT', 'action' => 'ACCEPT' }
        output = [ '-A OUTPUT -j ACCEPT' ]
        should run.with_params( input ).and_return( output )
      }
    end

    context "=> only allow sport 80 to connect to dport 80,443" do
      it {
        input = {
          'destination_port' => '80,443',
          'source_port' => '80',
          'action' => 'ACCEPT',
          'protocol' => 'tcp',
          'chain' => 'INPUT' }
        output = [ "-A INPUT -p tcp -m multiport --sport 80 --dports 80,443 " \
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
                                     'chain' => 'FORWARD',
                                     'action' => 'ACCEPT',
                                     'mod_flags' => { 'chn_FORWARD' => true } \
                                   } ) \
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
                  'raw' => '! --syn',
                  'action' => 'ACCEPT',
                  'chain' => 'INPUT' }

        should run.with_params( input ) \
                  .and_return( [ "-A INPUT -p tcp --dport 32768:61000 ! " \
                                 + "--syn -j ACCEPT" ] )
      }
    end

    context "=> test log prefix" do
      it do
        input = { 'protocol' => 'tcp',
                  'destination_port' => '32768:61000',
                  'action' => 'LOG',
                  'log_prefix' => 'LogPkt: ',
                  'mod_flags' => { 'act_LOG' => true } }
        output = [ "-A INPUT -p tcp --dport 32768:61000 -j LOG --log-prefix " \
          + "\"LogPkt: \"" ]
        should run.with_params(input, '4') \
          .and_return(output)
      end
    end

    context "=> test multiple source addresses" do
      it do
        input = { 'protocol' => 'tcp',
                  'destination_port' => '25',
                  'action' => 'REJECT',
                  'source' => [ '10.0.0.1', '10.0.0.2' ],
                  'chain' => 'OUTPUT' }
        output = [ "-A OUTPUT -s 10.0.0.1 -p tcp --dport 25 -j REJECT",
                   "-A OUTPUT -s 10.0.0.2 -p tcp --dport 25 -j REJECT" ]
        should run.with_params(input, '4') \
          .and_return(output)
      end
    end

    context "=> test multiple destination addresses" do
      it do
        input = { 'protocol' => 'tcp',
                  'destination_port' => '25',
                  'action' => 'REJECT',
                  'destination' => [ '10.0.0.1', '10.0.0.2' ],
                  'chain' => 'OUTPUT' }
        output = [ "-A OUTPUT -d 10.0.0.1 -p tcp --dport 25 -j REJECT",
                   "-A OUTPUT -d 10.0.0.2 -p tcp --dport 25 -j REJECT" ]
        should run.with_params(input, '4') \
          .and_return(output)
      end
    end

    context "=> error if destination_port specified, but not protocol" do
      it do 
        options = { 'destination_port' => '22' }
        defaults = { }
        expect {
          should run.with_params( options, defaults, '4' ).and_return([ ])
        }.to raise_error(Puppet::ParseError, /protocol required/)
      end
    end

    context "=> block protocol 88 traffic" do
      it {
        options = { 'protocol' => '88',
                    'action' => 'REJECT' }
        defaults = { }
        output = [ '-A INPUT -p 88 -j REJECT' ]
        expect {
          should run.with_params( options, defaults, '4' ).and_return(output)
        }
      }
    end
    context "=> disable strict protocol checking, and block eigrp traffic" do
      it {
        options = { 'strict_protocol_checking' => false,
                    'protocol' => 'eigrp',
                    'action' => 'REJECT' }
        defaults = { }
        output = [ '-A INPUT -p eigrp -j REJECT' ]
        expect {
          should run.with_params( options, defaults, '4' ).and_return(output)
        }
      }
    end

  end

  # Test ip6tables rule generation below
  #
  context "=> IPv6 => valid rules" do
    context "=> allow all traffic" do
      it {
        input = { 'action' => 'ACCEPT', 'chain' => 'INPUT' }
        output = [ '-A INPUT -j ACCEPT' ]
        should run.with_params( input, '6' ).and_return( output )
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
          'incoming_interface' => 'eth1',
          'action' => 'ACCEPT',
          'chain' => 'INPUT' }
        output = [ "-A INPUT -i eth1 -s 2600::0/48 -d 2601::0/48 -p tcp " \
          + "--dport 22 -m state --state NEW,REL,EST -j ACCEPT" ]
        should run.with_params( input, '6' ).and_return( output )
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
        output = [ "-A INPUT -i eth1 -s 2600::0/48 -p tcp --dport 22 " \
          + "-m state --state NEW,REL,EST -j ACCEPT" ]
        should run.with_params( options, '6' ).and_return(output)
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
        'destination_port' => '80,443',
        'protocol' => 'tcp',
        }
        defaults = { }
        output = [ "-A INPUT -p tcp -m multiport --sport 80 --dports 80,443 " \
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
                    'chain' => 'FORWARD',
                    'action' => 'ACCEPT',
                    'mod_flags' => { 'chn_FORWARD' => true } }
        output = [ '-A FORWARD -i eth1 -o eth1 -j ACCEPT' ]
        should run.with_params(options,'6').and_return(output)
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

    context "=> test log prefix" do
      it do
        input = { 'protocol' => 'tcp',
                  'destination_port' => '32768:61000',
                  'action' => 'LOG',
                  'log_prefix' => 'LogPkt: ',
                  'mod_flags' => { 'act_LOG' => true } }
        output = [ "-A INPUT -p tcp --dport 32768:61000 -j LOG --log-prefix " \
          + "\"LogPkt: \"" ]
        should run.with_params(input, '6') \
          .and_return(output)
      end
    end

    context "=> test multiple source addresses" do
      it do
        input = { 'protocol' => 'tcp',
                  'destination_port' => '25',
                  'action' => 'REJECT',
                  'source' => [ '2600::0/48', '2601::0/48' ],
                  'chain' => 'OUTPUT' }
        output = [ "-A OUTPUT -s 2600::0/48 -p tcp --dport 25 -j REJECT",
                   "-A OUTPUT -s 2601::0/48 -p tcp --dport 25 -j REJECT" ]
        should run.with_params(input, '6') \
          .and_return(output)
      end
    end

    context "=> test multiple destination addresses" do
      it do
        input = { 'protocol' => 'tcp',
                  'destination_port' => '25',
                  'action' => 'REJECT',
                  'destination' => [ '2600::0/48', '2601::0/48' ],
                  'chain' => 'OUTPUT' }
        output = [ "-A OUTPUT -d 2600::0/48 -p tcp --dport 25 -j REJECT",
                   "-A OUTPUT -d 2601::0/48 -p tcp --dport 25 -j REJECT" ]
        should run.with_params(input, '6') \
          .and_return(output)
      end
    end

    context "=> error if destination_port specified, but not protocol" do
      it do 
        options = { 'destination_port' => '22' }
        defaults = { }
        expect {
          should run.with_params( options, defaults, '6' ).and_return([ ])
        }.to raise_error(Puppet::ParseError, /protocol required/)
      end
    end

    context "=> block protocol 88 traffic" do
      it {
        options = { 'protocol' => '88',
                    'action' => 'REJECT' }
        defaults = { }
        output = [ '-A INPUT -p 88 -j REJECT' ]
        expect {
          should run.with_params( options, defaults, '6' ).and_return(output)
        }
      }
    end

    context "=> disable strict protocol checking, and block eigrp traffic" do
      it {
        options = { 'strict_protocol_checking' => false,
                    'protocol' => 'eigrp',
                    'action' => 'REJECT' }
        defaults = { }
        output = [ '-A INPUT -p eigrp -j REJECT' ]
        should run.with_params( options, defaults, '6' ).and_return(output)
      }
    end

    context '=> use REDIRECT action with a v4 rule' do
      it {
        options = {
        'chain' => 'PREROUTING',
        'action' => 'REDIRECT',
        'to_port' => '8080:8090',
        'protocol' => 'tcp',
        'destination_port' => '80:90',
        'table' => 'nat',
        'mod_flags' => { 'act_REDIRECT' => true },
        }
        defaults = { }
        output = [ '-A PREROUTING -p tcp --dport 80:90 -j REDIRECT --to-port 8080:8090' ]
        should run.with_params( options, defaults, '4' ).and_return(output)
      }
    end

    context '=> use REDIRECT action with a v6 rule' do
      it {
        options = {
        'action' => 'REDIRECT',
        'to_port' => '8080:8090',
        'protocol' => 'tcp',
        'destination_port' => '80:90',
        'mod_flags' => { 'act_REDIRECT' => true },
        }
        expect {
          should run.with_params( options, defaults, '6' ).and_raise_error(Puppet::ParseError)
        }
      }
    end

    context '=> use raw_after parameter' do
      it {
        options = {
          'protocol' => 'tcp',
          'raw_after' => '--to-port 80',
          'action' => 'REDIRECT',
          'chain' => 'PREROUTING',
          'table' => 'nat',
          'destination_port' => '22',
        }
        defaults = { }
        output = [ '-A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 80' ]
        should run.with_params( options, defaults, '4' ).and_return(output)
      }
    end
  end
end
