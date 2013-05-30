require 'spec_helper'

describe 'format_protocol' do
  context "=> test illegal protocol type" do
    input = "tcp6"
    it { should run.with_params(input).and_raise_error(Puppet::ParseError) }
  end
  context "=> test illegal protocol type - v4" do
    input = "tcp6"
    it { should run.with_params(input,'4').and_raise_error(Puppet::ParseError) }
  end
  context "=> test illegal protocol type - v6" do
    input = "tcp6"
    it { should run.with_params(input,'6').and_raise_error(Puppet::ParseError) }
  end
  context "=> test legal protocol" do
    input = "tcp"
    output = { 'protocol' => '-p tcp', 'version' => '4', 'raw' => 'tcp' }
    it { should run.with_params(input).and_return(output) }
  end
  context "=> test legal protocol - v4" do
    input = "tcp"
    output = { 'protocol' => '-p tcp', 'version' => '4', 'raw' => 'tcp' }
    it { should run.with_params(input,'4').and_return(output) }
  end
  context "=> test legal protocol - v6" do
    input = "tcp"
    output = { 'protocol' => '-p tcp', 'version' => '6', 'raw' => 'tcp' }
    it { should run.with_params(input,'6').and_return(output) }
  end
  context "=> test icmp to icmpv6 assumption" do
    input = 'icmp'
    output = { 'protocol' => '-p icmpv6', 'version' => '6', 'raw' => 'icmp' }
    it { should run.with_params(input,'6').and_return(output) }
  end
end
