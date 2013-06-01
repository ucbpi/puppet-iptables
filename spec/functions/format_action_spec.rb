require 'spec_helper'

describe 'format_action' do
  context '=> Pass legal action/chain' do
    it { should run.with_params('ACCEPT').and_return('-j ACCEPT') }
  end

  context '=> Pass illegal action/chain' do
    it {
      should run.with_params('SOME CHAIN').and_raise_error(Puppet::ParseError)
    }
  end
end
