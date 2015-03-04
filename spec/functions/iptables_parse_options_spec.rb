require 'spec_helper'

describe 'iptables_parse_options' do
  context "=> nil passed" do
    it {
      input = [ ]
      flgs = { 'chn_INPUT' => true, 'act_ACCEPT' => true, 'tbl_filter' => true }
      output = { 'action' => 'ACCEPT', 'chain' => 'INPUT', 'mod_flags' => flgs, 'table' => 'filter' }
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
        'table' => 'filter',
        'chain' => 'INPUT',
        'log_prefix' => 'BlkPkt: ',
        'log_level' => 'debug',
        'destination_port' => '22',
        'mod_flags' => { 'act_LOG' => true, 'chn_INPUT' => true, 'tbl_filter' => true },
      }
      should run.with_params({ },defaults).and_return(output)
    }
    context "=> override defaults" do
      it {
        input = { 'source' => '192.168.26.0/24' }
        output = {
          'action' => 'LOG',
          'chain' => 'INPUT',
          'table' => 'filter',
          'log_prefix' => 'BlkPkt: ',
          'log_level' => 'debug',
          'destination_port' => '22',
          'source' => '192.168.26.0/24',
          'mod_flags' => { 'act_LOG' => true, 'chn_INPUT' => true, 'tbl_filter' => true },
        }
        should run.with_params(input,defaults).and_return(output)
      }

      it {
        input = { 'chain' => 'OUTPUT', 'action' => 'REJECT' }
        output = {
          'action' => 'REJECT',
          'chain' => 'OUTPUT',
          'table' => 'filter',
          'destination_port' => '22',
          'source' => '192.168.23.0/24',
          'mod_flags' => { 'act_REJECT' => true, 'chn_OUTPUT' => true, 'tbl_filter' => true },
          'log_prefix' => 'BlkPkt: ',
          'log_level' => 'debug',
        }
        should run.with_params(input,defaults).and_return(output)
      }

      it {
        input = { 'chain' => 'PREROUTING', 'action' => 'REDIRECT', 'table' => 'nat', 'redirect_to' => '2222' }
        output = {
          'action' => 'REDIRECT',
          'chain' => 'PREROUTING',
          'table' => 'nat',
          'destination_port' => '22',
          'redirect_to' => '2222',
          'source' => '192.168.23.0/24',
          'log_prefix' => 'BlkPkt: ',
          'log_level' => 'debug',
          'mod_flags' => { 'act_REDIRECT' => true, 'chn_PREROUTING' => true, 'tbl_nat' => true },
        }
        should run.with_params(input,defaults).and_return(output)
      }
    end
  end
end
