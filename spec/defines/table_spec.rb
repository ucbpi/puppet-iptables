require 'spec_helper'

describe 'iptables::table' do
  let(:facts) { { :concat_basedir => '/var/lib/puppet/concat' } }

  context 'with a valid table title' do
    let(:title) { 'filter' } 
    it do
      should contain_concat__fragment('iptables-table-filter')
    end
  end

  context 'with invalid table name' do
    let(:title) { 'forward' }
    
    it do
      expect {
        should contain_concat__fragment('iptables-table-forward')
      }.to raise_error(Puppet::Error, /invalid table title/)
    end
  end

  context 'with uppercase chars in name' do
    let(:title) { 'FILTER' }

    it do
      expect {
        should contain_concat__fragment('iptables-table-FILTER')
      }.to raise_error(Puppet::Error, /invalid table title/)
    end
  end
end
