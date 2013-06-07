require 'spec_helper'

describe 'iptables' do
  let(:facts) { { :concat_basedir => '/var/lib/puppet/concat/' } }

  context "=> invalid custom iptables_file" do
    let(:params) { {'iptables_file' => 'iptables.test' } }
    it { expect { raise_error(Puppet::Error) } }
  end

  context "=> invalid custom ip6tables_file" do
    let(:params) { { 'ip6tables_file' => 'ip6tables.test' } }
    it { expect { raise_error(Puppet::Error) } }
  end

  # if all goes well, we should have a concat::setup object
  context "=> custom iptables_file and ip6tables_file" do
    let(:params) {
      { 'iptables_file' => '/etc/sysconfig/iptables',
        'ip6tables_file' => '/etc/sysconfig/ip6tables' }
    }
    it { should contain_concat__setup() }
  end

  context "=> no parameters" do
    it { should contain_concat__setup() }
  end
end
