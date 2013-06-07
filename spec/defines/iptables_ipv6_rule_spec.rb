require 'spec_helper'

describe 'iptables::ipv6::rule' do
  let(:facts) { { :concat_basedir => '/var/lib/puppet/concat' } }

  context "allow ssh from world" do
    let(:title) { 'allow ssh from world' }
    let(:params) { { 'options' => { 'destination_port' => '22',
                                    'protocol' => 'tcp' } } }

    it do
      should contain_iptables__ipv6__chain('INPUT')
      should contain_concat__fragment(
        'ip6tables-table-filter-chain-INPUT-rule-allow ssh from world' ) \
        .with( { 'order' => '1_filter_2_INPUT_500',
                  'target' => '/etc/sysconfig/ip6tables',
                  'content' => "-A INPUT -p tcp --dport 22 -j ACCEPT\n" } )
    end
  end

  context "allow ssh on ADMIN chain" do
    let(:title) { 'allow ssh on admin chain' }
    let(:params) { { 'options' => { 'destination_port' => '22',
                                    'protocol' => 'tcp',
                                    'chain' => 'ADMIN',
                                    'order' => '100' } } }
    it do
      should contain_iptables__ipv6__chain('ADMIN')
      should contain_concat__fragment(
        'ip6tables-table-filter-chain-ADMIN-rule-allow ssh on admin chain' ) \
        .with( { 'order' => '1_filter_9_ADMIN_100',
                'target' => '/etc/sysconfig/ip6tables',
                'content' => "-A ADMIN -p tcp --dport 22 -j ACCEPT\n" } )
    end
  end

  context "certain address jump to ADMIN chain" do
    let(:title) { 'admin-jump' }
    let(:params) { { 'options' => { 
      'source' => 'dead:beef::/120,dead:bead::/125',
      'action' => 'ADMIN',
      'order' => '25' } } }

    it do
      should contain_iptables__ipv6__chain('INPUT')
      should contain_concat__fragment(
        'ip6tables-table-filter-chain-INPUT-rule-admin-jump' ) \
        .with( { 'order' => '1_filter_2_INPUT_025',
                  'target' => '/etc/sysconfig/ip6tables',
                  'content' => "-A INPUT -s dead:beef::/120 -j ADMIN\n" + \
                               "-A INPUT -s dead:bead::/125 -j ADMIN\n" } )
    end
  end
end
