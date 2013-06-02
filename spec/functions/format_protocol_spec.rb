require 'spec_helper'

describe 'format_protocol' do
  context "=> test illegal protocol type" do
    it { should run.with_params('tcp6').and_raise_error(Puppet::ParseError) }
  end
  context "=> test illegal protocol type - v4" do
    it {
      should run.with_params('tcp6','4').and_raise_error(Puppet::ParseError)
    }
  end
  context "=> test illegal protocol type - v6" do
    it { 
      should run.with_params('tcp6','6').and_raise_error(Puppet::ParseError)
    }
  end
  context "=> test legal protocol" do
    it { should run.with_params('tcp').and_return( '-p tcp' ) }
  end
  context "=> test legal protocol - v4" do
    it { should run.with_params('tcp','4').and_return( '-p tcp' ) }
  end
  context "=> test legal protocol - v6" do
    it { should run.with_params('tcp','6').and_return( '-p tcp' ) }
  end
  context "=> test icmp to icmpv6 assumption" do
    it { should run.with_params( 'icmp', '6' ).and_return( '-p icmpv6' ) }
  end
  context "=> test numeric protocol version passed" do
    it { should run.with_params('icmp',6).and_return( '-p icmpv6' ) }
  end
end
