require 'spec_helper'

describe 'format_state' do
  context '=> Pass legal states' do
    it { 
      should run.with_params('NEW,REL,EST,INV') \
        .and_return('-m state --state NEW,REL,EST,INV')
    }
  end

  context '=> Pass only illegal states' do
    it { should run.with_params('NOPE').and_raise_error(Puppet::ParseError) }
  end

  context '=> Pass undef (undef in puppet)' do
    it { should run.with_params(:undef).and_return('') }
  end

  context '=> Pass nil (undef in puppet)' do
    it { should run.with_params(nil).and_return('') }
  end

  context '=> Pass mix of legal and illegal states' do
    it {
      should run.with_params([ 'NET', 'NEW', 'OLD', 'REL', 'EST' ]) \
        .and_return('-m state --state NEW,REL,EST')
    }
  end
end
