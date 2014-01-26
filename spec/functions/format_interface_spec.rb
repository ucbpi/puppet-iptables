require 'spec_helper'

describe 'format_interface' do
  context "=> valid interface name" do
    context "=> no direction" do
      it { should run.with_params('eth0').and_return("-i eth0") }
    end

    context "=> in direction" do
      it { should run.with_params('eth0','in').and_return("-i eth0") }
    end

    context "=> out direction" do
      it { should run.with_params('eth0','out').and_return("-o eth0") }
    end

    context "=> bad direction" do
      p = [ 'eth0', 'bad' ]
      it { should run.with_params(*p).and_raise_error(Puppet::ParseError) }
    end

    context "=> invalid interface name" do
      i = 'eth?'
      it { should run.with_params(i).and_raise_error(Puppet::ParseError) }
    end

    context "=> undef passed" do
      it { should run.with_params(:undef).and_return('') }
    end

    context "=> nil passed" do
      it { should run.with_params(nil).and_return('') }
    end

    context "=> array passed" do
      p=['eth0']
      it { should run.with_params(p).and_raise_error(Puppet::ParseError) }
    end
  end
end
