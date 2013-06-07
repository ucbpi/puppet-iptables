require 'spec_helper'

describe 'iptables_parse_options' do
  context "=> nil passed" do
    it {
      input = [ ]
      flgs = { 'chn_INPUT' => true, 'act_ACCEPT' => true }
      output = { 'action' => 'ACCEPT', 'chain' => 'INPUT', 'mod_flags' => flgs }
      should run.with_params(input).and_return(output)
    }
  end

  context "=> with defaults" do
    defaults = {
      'action' => 'LOG',
      'source' => '192.168.23.0/24',
      'log_prefix' => 'BlkPkt: ',
      'log_level' => 'debug',
      'destination_port' => '22'
    }
    it {
      output = {
        'action' => 'LOG',
        'source' => '192.168.23.0/24',
        'chain' => 'INPUT',
        'log_prefix' => 'BlkPkt: ',
        'log_level' => 'debug',
        'destination_port' => '22',
        'mod_flags' => { 'act_LOG' => true, 'chn_INPUT' => true },
      }
      should run.with_params({ },defaults).and_return(output)
    }
    context "=> override defaults" do
      it {
        input = { 'source' => '192.168.26.0/24' }
        output = {
          'action' => 'LOG',
          'chain' => 'INPUT',
          'log_prefix' => 'BlkPkt: ',
          'log_level' => 'debug',
          'destination_port' => '22',
          'source' => '192.168.26.0/24',
          'mod_flags' => { 'act_LOG' => true, 'chn_INPUT' => true },
        }
        should run.with_params(input,defaults).and_return(output)
      }

      it {
        input = { 'chain' => 'OUTPUT', 'action' => 'REJECT' }
        output = {
          'action' => 'REJECT',
          'chain' => 'OUTPUT',
          'destination_port' => '22',
          'source' => '192.168.23.0/24',
          'mod_flags' => { 'act_REJECT' => true, 'chn_OUTPUT' => true },
          'log_prefix' => 'BlkPkt: ',
          'log_level' => 'debug',
        }
        should run.with_params(input,defaults).and_return(output)
      }
    end
  end
end
