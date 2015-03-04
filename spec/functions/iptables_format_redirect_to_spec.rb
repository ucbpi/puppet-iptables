require 'spec_helper'

describe 'iptables_format_to_port' do
  %w{8080 8080:8089 ssh ssh:http}.each do |port|
    context "=> redirect to #{port}" do
      it do
        should run.with_params(port).and_return("--to-port #{port}")
      end
    end
  end

  %w{80000}.each do |port|
    context "=> invalid redirect to #{port}" do
      it do
        should run.with_params(port).and_raise_error(Puppet::ParseError)
      end
    end
  end

  [ :undef, nil ].each do |port|
    context "=> empty value #{port.to_s}" do
      it do
        should run.with_params(port).and_return('')
      end
    end
  end
end
