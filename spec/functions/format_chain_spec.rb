require 'spec_helper'

describe 'format_chain' do
  context '=> Pass legal chain' do
    returns = { 'chain' => '-A INPUT',
                'raw' => 'INPUT' }
    it { should run.with_params('INPUT').and_return( returns ) }

  end

  context '=> Pass illegal status' do
    it { should run.with_params('SOME CHAIN').and_raise_error(Puppet::ParseError) }
  end
end
