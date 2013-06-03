require 'spec_helper'

describe 'format_log' do
  context "=> no log options" do
    it {
      input = { }
      output = ''
      should run.with_params(input).and_return(output)
    }
  end

  context "=> log_level passed" do
    it {
      input = { 'log_level' => 'debug' }
      output = '--log-level 7'
      should run.with_params(input).and_return(output)
    }
    it {
      input = { 'log_level' => '3' }
      output = '--log-level 3'
      should run.with_params(input).and_return(output)
    }
  end

  context "=> log_prefix passed" do
    it {
      input = { 'log_prefix' => 'InPkt: ' }
      output = "--log-prefix 'InPkt: '"
      should run.with_params(input).and_return(output)
    }
    it {
      input = { 'log_prefix' => 'Drop Packet: ' }
      output = "--log-prefix 'Drop Packet: '"
      should run.with_params(input).and_return(output)
    }
    context "=> 29 chars cutoff" do
      it {
        input = { 'log_prefix' => 'Something Something Something Something' }
        output = "--log-prefix 'Something Something Something'"
        should run.with_params(input).and_return(output)
      }
    end
  end

  context "=> log_tcp_options = true" do
    it {
      input = { 'log_tcp_options' => true }
      output = '--log-tcp-options'
      should run.with_params(input).and_return(output)
    }
  end

  context "=> log_ip_options = true" do
    it {
      input = { 'log_ip_options' => true }
      output = '--log-ip-options'
      should run.with_params(input).and_return(output)
    }
  end

  context "=> log_tcp_sequence = true" do
    it {
      input = { 'log_tcp_sequence' => true }
      output = '--log-tcp-sequence'
      should run.with_params(input).and_return(output)
    }
  end

  context "=> log_uid = true and log_tcp_options = true" do
    it {
      input = { 'log_uid' => true, 'log_tcp_options' => true }
      output = '--log-tcp-options --log-uid'
      should run.with_params(input).and_return(output)
    }
  end
end
