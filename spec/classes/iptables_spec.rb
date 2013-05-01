require 'spec_helper'

describe 'iptables' do
  let(:facts) { { :concat_basedir => '/var/lib/puppet/concat/' } }

  ################################
  # Unspecified filename
  #
  context 'with unspecified filepath' do
    it do
      should contain_concat('/etc/sysconfig/iptables')
    end
  end

  ################################
  # Valid filename provided
  #
  context 'with a valid filepath' do
    let(:params) { { :file => '/etc/sysconfig/iptables-test' } }

    it do
      should contain_concat('/etc/sysconfig/iptables-test')
    end
  end
end

