require 'spec_helper'

describe 'iptables_format_to_port' do
  context "=> tests with a single port" do
    it { should run.with_params('8080') \
      .and_return( '--to-port 8080' ) }
  end

  context "=> tests with a port range" do
    it { should run.with_params('8080:8089') \
      .and_return( '--to-port 8080:8089' ) }
  end

  context "=> test string ports" do
    it {
      should run.with_params('ssh:http').and_return('--to-port ssh:http')
    }
  end

  context "=> test an invalid port (too high)" do
    it {
      should run.with_params('80000').and_raise_error(Puppet::ParseError)
    }
  end

  context "=> send undef" do
    it { should run.with_params(:undef).and_return('') }
  end
  context "=> send nil" do
    it { should run.with_params(nil).and_return('') }
  end
end
