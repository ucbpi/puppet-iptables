require 'spec_helper'

describe 'iptables_prep_option' do

  vals = { 'opt1' => 'val1', 'opt2' => 'val2' }
  defs = { 'opt2' => 'dval2', 'opt3' => 'dval3'}

  # Test value hash precedence
  context '=> test value hash precedence' do
    context '=> no default, no hard-coded default' do
      it {
        out = 'val1'
        should run.with_params('opt1',vals,defs).and_return( out )
      }
    end

    context '=> no default, with hard-coded default' do
      it {
        out = 'val1'
        should run.with_params('opt1',vals,defs,-1).and_return( out )
      }
    end

    context '=> with default, no hard-coded default' do
      it {
        out = 'val2'
        should run.with_params('opt2',vals,defs).and_return( out )
      }
    end

    context '=> with default, with hard-coded default' do
      it {
        out = 'val2'
        should run.with_params('opt2',vals,defs,-1).and_return( out )
      }
    end
  end

  # Test defaults hash
  context '=> test defaults hash precedence' do

    context '=> without hard-coded default' do
      it {
        out = 'dval3'
        should run.with_params('opt3',vals,defs).and_return( out )
      }
    end

    context '=> with hard-coded default' do
      it {
        out = 'dval3'
        should run.with_params('opt3',vals,defs,-1).and_return( out )
      }
    end
  end

  # Test hard-coded defaults
  context '=> test hard-coded default' do
    context '=> none-specified' do
      it {
        out = ""
        should run.with_params('opt4',vals,defs).and_return( out )
      }
    end

    context '=> -1 specified' do
      it {
        out = -1
        should run.with_params('opt4',vals,defs,-1).and_return( out )
      }
    end
  end

  context "=> test with no defaults specified" do
    it { should run.with_params('opt4',vals,:undef,-1).and_return(-1) }
  end

  context "=> test with no defaults specified" do
    it { should run.with_params('opt4',vals,nil,-1).and_return(-1) }
  end
end
