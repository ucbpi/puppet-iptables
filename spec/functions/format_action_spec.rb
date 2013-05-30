require 'spec_helper'

describe 'format_action' do
  context '=> Pass legal action' do
    returns = { 'action' => '-j ACCEPT',
                'raw' => 'ACCEPT' }
    it { should run.with_params('ACCEPT').and_return( returns ) }

  end

  context '=> Pass illegal status' do
    it { should run.with_params('SOME CHAIN').and_raise_error(Puppet::ParseError) }
  end
end
