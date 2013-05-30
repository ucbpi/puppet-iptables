require 'spec_helper'

describe 'iptables_prep_option' do

  vals = { 'option_one' => 'value_one', 'option_two' => 'value_two' }
  defs = {
    'option_two' => 'defs_value_two',
    'option_three' => 'defs_value_three'
  }

  # Test value hash precdence
  context '=> test value hash precedence' do
    context '=> no default, no hard-coded default' do
      out = 'value_one'
      it { should run.with_params('option_one',vals,defs).and_return( out ) }
    end

    context '=> no default, with hard-coded default' do
      out = 'value_one'
      it { should run.with_params('option_one',vals,defs,-1).and_return( out )}
    end

    context '=> with default, no hard-coded default' do
      out = 'value_two'
      it { should run.with_params('option_two',vals,defs).and_return( out ) }
    end

    context '=> with default, with hard-coded default' do
      out = 'value_two'
      it { should run.with_params('option_two',vals,defs,-1).and_return( out )}
    end
  end

  # Test defaults hash
  context '=> test defaults hash precedence' do
    out = 'defs_value_three'

    context '=> without hard-coded default' do
      it { should run.with_params('option_three',vals,defs).and_return( out ) }
    end

    context '=> with hard-coded default' do
      it { should run.with_params('option_three',vals,defs,-1).and_return( out )}
    end
  end

  # Test hard-coded defaults
  context '=> test hard-coded default' do
    context '=> none-specified' do
      out = ""
      it { should run.with_params('option_four',vals,defs).and_return( out ) }
    end

    context '=> -1 specified' do
      out = -1
      it { should run.with_params('option_four',vals,defs,-1).and_return( out ) }
    end
  end
end
