require 'spec_helper'

describe 'iptables::ipv6' do
  let(:facts) { { :concat_basedir => '/var/lib/puppet/concat/' } }

  it do
    # we need some info from the top-level class
    should contain_iptables()

    # ensure we've got out iptables file, with mode 0440
    should contain_concat('/etc/sysconfig/ip6tables').with({
      'owner' => 'root',
      'group' => 'root',
      'mode' => '0440',
    })

    # ensure we've got our header comment fragment
    # and that it is ordered properly
    should contain_concat__fragment('ip6tables-header-comment').with({
      'ensure' => 'present',
      'target' => '/etc/sysconfig/ip6tables',
      'order' => '0',
      'content' => "# Firewall Managed by Puppet\n\n",
    })
  end
end
