require 'spec_helper'

describe 'iptables::rule' do
  let(:facts) { { :concat_basedir => '/var/lib/puppet/concat' } }

  # Tests that assert specification of version set to 'ipv4' ensures only
  # IPv4 rules are generated.
  #
  # Related Issues:
  #   https://github.com/arusso/puppet-iptables/issues/9
  context 'ipv4 rules' do
    context 'allow ssh from ipv4 only' do
      let(:title) { 'allow-ssh-global' }

      let :params do
        {
          'protocol'         => 'tcp',
          'destination_port' => '22',
          'version'          => 'ipv4'
        }
      end

      it do
        options = {
          'protocol'         => 'tcp',
          'destination_port' => '22',
          'source'           => [],
          'destination'      => [],
        }

        should contain_iptables__ipv4
        should contain_iptables__ipv4__rule('allow-ssh-global').with( { 'options' => options }  )
        should_not contain_iptables__ipv6
        should_not contain_iptables_ipv6_rule('allow-ssh-global')
        should contain_concat__fragment("iptables-table-filter-chain-INPUT-rule-#{title}").with_order('1_filter_2_INPUT_500')
        should contain_concat__fragment("iptables-table-filter-chain-INPUT-rule-#{title}").with_content("-A INPUT -p tcp --dport 22 -j ACCEPT\n")
      end
    end

    context 'redirect ports' do
      let(:title) { 'redirect-to-http-alt' }

      let :params do
        {
          'protocol'         => 'tcp',
          'destination_port' => '80',
          'version'          => 'ipv4',
          'table'            => 'nat',
          'to_port'          => '8080',
          'action'           => 'REDIRECT',
          'chain'            => 'PREROUTING',
          'order'            => '100',
        }
      end

      it do
        should contain_iptables__ipv4
        should contain_iptables__ipv4__rule('redirect-to-http-alt')
        should_not contain_iptables__ipv6
        should_not contain_iptables__ipv6__rule('redirect-to-http-alt')
        should contain_concat__fragment("iptables-table-nat-chain-PREROUTING-rule-#{title}").with({
          'content' => "-A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080\n",
          'order'   => '2_nat_5_PREROUTING_100',
        })

        should contain_iptables__ipv4__chain('nat:PREROUTING')
        should contain_iptables__ipv4__table('nat')
      end
    end # redirect ports
  end # IPv4 Only

  # this test checks for:
  #   https://github.com/arusso/puppet-iptables/issues/9 (issue #9)
  context '=> allow ssh from ipv6 only' do
    let(:title) { 'allow-ssh-global' }

    let :params do
      {
        'version'          => 'ipv6',
        'destination_port' => '22',
        'protocol'         => 'tcp',
      }
    end

    it do
      options = {
        'protocol'         => 'tcp',
        'destination_port' => '22',
        'source'           => [],
        'destination'      => [],
      }
      should contain_iptables__ipv6
      should contain_iptables__ipv6__rule('allow-ssh-global').with( { 'options' => options }  )

      should_not contain_iptables_ipv4_rule('allow-ssh-global')
      should_not contain_iptables__ipv4

      should contain_concat__fragment("ip6tables-table-filter-chain-INPUT-rule-#{title}").with({
        'content' => "-A INPUT -p tcp --dport 22 -j ACCEPT\n",
        'order'   => '1_filter_2_INPUT_500',
      })
    end
  end

  context 'destination and destination port' do
    let(:title) { 'destination-and-dport' }
    let :params do
      {
        'destination'      => [ '4.2.2.1', '4.2.2.2', '::1' ],
        'destination_port' => [ '80', '443' ],
        'protocol'         => 'tcp',
      }
    end

    it do
      should contain_iptables__ipv4__rule('destination-and-dport')
      should contain_iptables__ipv6__rule('destination-and-dport')

      should contain_concat__fragment('iptables-table-filter-chain-INPUT-rule-destination-and-dport').with({
        'order'   => '1_filter_2_INPUT_500',
        'content' => "-A INPUT -d 4.2.2.1 -p tcp -m multiport --dports 80,443 -j ACCEPT\n-A INPUT -d 4.2.2.2 -p tcp -m multiport --dports 80,443 -j ACCEPT\n",
      })
      should contain_concat__fragment('ip6tables-table-filter-chain-INPUT-rule-destination-and-dport').with({
        'order'   => '1_filter_2_INPUT_500',
        'content' => "-A INPUT -d ::1 -p tcp -m multiport --dports 80,443 -j ACCEPT\n",
      })
    end
  end

  context 'invalid destination addresses' do
    let(:title) { 'invalid ips' }

    let :params do
      {
        'destination' => [ '10.0.0.256', '2001::1/129' ],
      }
    end

    it do
      expect {
        should_not contain_iptables__ipv4__rule('invalid ips')
        should_not contain_iptables__ipv6__rule('invalid ips')
      }.to raise_error(Puppet::Error, /invalid ip/)
    end
  end

  context 'match rule with limit set' do
    let(:title) { 'match-limit' }
    let :params do
      {
        'limit' => '10/sec',
        'limit_burst' => '5',
        'protocol' => 'tcp',
        'destination_port' => '22',
      }
    end

    it do
      should contain_iptables__ipv4__rule('match-limit').with_options({
        'limit' => '10/sec',
        'limit_burst' => '5',
        'protocol' => 'tcp',
        'destination_port' => '22',
        'source' => [],
        'destination' => [],
      })
      should contain_iptables__ipv6__rule('match-limit').with_options({
        'limit' => '10/sec',
        'limit_burst' => '5',
        'protocol' => 'tcp',
        'destination_port' => '22',
        'source' => [],
        'destination' => [],
      })
      should contain_concat__fragment('iptables-table-filter-chain-INPUT-rule-match-limit').with({
        'order' => '1_filter_2_INPUT_500',
        'content' => "-A INPUT -p tcp --dport 22 -m limit --limit 10/second --limit-burst 5 -j ACCEPT\n",
      })
      should contain_concat__fragment('ip6tables-table-filter-chain-INPUT-rule-match-limit').with({
        'order' => '1_filter_2_INPUT_500',
        'content' => "-A INPUT -p tcp --dport 22 -m limit --limit 10/second --limit-burst 5 -j ACCEPT\n",
      })
    end
  end
end
