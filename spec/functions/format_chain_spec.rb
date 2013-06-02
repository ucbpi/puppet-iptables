require 'spec_helper'

describe 'format_chain' do
  context '=> Pass legal chain' do
    it {
      should run.with_params('INPUT').and_return('-A INPUT')
      should run.with_params('OUTPUT').and_return('-A OUTPUT')
      should run.with_params('LOGNDROP').and_return('-A LOGNDROP')
    }
  end

  context '=> Pass illegal status' do
    it {
      should run.with_params('SOME CHAIN').and_raise_error(Puppet::ParseError)
    }
  end
end
