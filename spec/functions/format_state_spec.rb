require 'spec_helper'

describe 'format_state' do
  context '=> Pass legal states' do
    input = 'NEW,REL,EST,INV'
    output = {
      'state' => '-m state --state NEW,REL,EST,INV',
      'raw' => input,
    }
    it { should run.with_params(input).and_return(output) }
  end

  context '=> Pass only illegal states' do
    input = 'NOPE'
    it { should run.with_params(input).and_raise_error(Puppet::ParseError) }
  end

  context '=> Pass nil (undef in puppet)' do
    input = nil 
    output = { 'state' => '', 'raw' => '' }
    it { should run.with_params(input).and_return(output) }
  end

  context '=> Pass mix of legal and illegal states' do
    input = [ 'NET', 'NEW', 'OLD', 'REL', 'EST' ]
    output = {
      'state' => '-m state --state NEW,REL,EST',
      'raw' => input,
    }
    it { should run.with_params(input).and_return(output) }
  end
end
