require 'spec_helper'

describe 'iptables_format_limit' do
  context 'limit only' do
    it do
      should run.with_params('10/s').and_return('-m limit --limit 10/second')
      should run.with_params('3/m').and_return('-m limit --limit 3/minute')
      should run.with_params('1').and_return('-m limit --limit 1/second')
      should run.with_params('1000/da').and_return('-m limit --limit 1000/day')
      should run.with_params('3600/h').and_return('-m limit --limit 3600/hour')
    end
  end

  context 'limit and burst' do
    it do
      should run.with_params('10/s','5').and_return('-m limit --limit 10/second --limit-burst 5')
      should run.with_params('3/m','2').and_return('-m limit --limit 3/minute --limit-burst 2')
      should run.with_params('1','9').and_return('-m limit --limit 1/second --limit-burst 9')
      should run.with_params('1000/da','3').and_return('-m limit --limit 1000/day --limit-burst 3')
      should run.with_params('3600/h','20').and_return('-m limit --limit 3600/hour --limit-burst 20')
    end
  end
end
