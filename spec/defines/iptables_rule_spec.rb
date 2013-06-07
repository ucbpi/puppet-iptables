require 'spec_helper'

describe 'iptables::rule' do
  let(:facts) { { :concat_basedir => '/var/lib/puppet/concat' } }

  # this test checks for:
  #   https://github.com/arusso/puppet-iptables/issues/9 (issue #9)
  context '=> allow ssh from ipv4 only' do
    let(:title) { 'allow ssh global' }
    let(:params) {
      { 'protocol' => 'tcp',
        'source_port' => '22',
        'version' => 'ipv4' } }

    it do
      options = {
        'action' => 'ACCEPT',
        'chain' => 'INPUT',
        'mod_flags' => { 'proto_tcp' => true,
                         'chn_INPUT' => true,
                         'act_ACCEPT' => true },
        'protocol' => 'tcp',
        'source_port' => '22',
        'source' => [],
      }
      should contain_iptables__ipv4
      # for now, we wont check the parameters being passed as hashes since there
      # is a bug in rspec-puppet that doesnt take into account hashes may have
      # inconsistent ordering. Further compounding the issue is the way Puppet
      # handles values inside of hashes, trying to convert integers to strings
      #
      # https://github.com/rodjek/rspec-puppet/issues/71
      # https://github.com/rodjek/rspec-puppet/issues/101
      #
      #should contain_iptables__ipv4__rule('allow ssh global') \
      #  .with( { 'options' => options }  )
      should contain_iptables__ipv4__rule('allow ssh global')
      should_not contain_iptables_ipv6_rule('allow ssh global')
      should_not contain_iptables__ipv6
    end
  end

  # this test checks for:
  #   https://github.com/arusso/puppet-iptables/issues/9 (issue #9)
  context '=> allow ssh from ipv6 only' do
    let(:title) { 'allow ssh global' }
    let(:params) {
      { 'version' => 'ipv6',
        'source_port' => '22',
        'protocol' => 'tcp' } }

    it {
      options = {
        'action' => 'ACCEPT',
        'chain' => 'INPUT',
        'mod_flags' => { 'proto_tcp' => true,
                         'chn_INPUT' => true,
                         'act_ACCEPT' => true },
        'protocol' => 'tcp',
        'source_port' => '22',
        'source' => [],
      }
      should contain_iptables__ipv6
      # for now, we wont check the parameters being passed as hashes since there
      # is a bug in rspec-puppet that doesnt take into account hashes may have
      # inconsistent ordering. Further compounding the issue is the way Puppet
      # handles values inside of hashes, trying to convert integers to strings
      #
      # https://github.com/rodjek/rspec-puppet/issues/71
      # https://github.com/rodjek/rspec-puppet/issues/101
      #
      #should contain_iptables__ipv6__rule('allow ssh global') \
      #  .with( { 'options' => options }  )
      should contain_iptables__ipv6__rule('allow ssh global')
      should_not contain_iptables_ipv4_rule('allow ssh global')
      should_not contain_iptables__ipv4
    }
  end
end
