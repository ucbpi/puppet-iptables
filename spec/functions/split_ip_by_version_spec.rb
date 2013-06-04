require 'spec_helper'

describe 'split_ip_by_version' do
  context '=> 1 of each' do
    input = [ '2607:f8b0:4005:800::1005',
              '74.125.239.97',
              'alt2.aspmx.l.google.com.' ]
    output = { '6' => [ '2607:f8b0:4005:800::1005' ],
               '4' => [ '74.125.239.97' ],
               'other' => [ 'alt2.aspmx.l.google.com.' ] }

    it { should run.with_params(input).and_return( output ) }
  end

  context '=> v6 Only' do
    input = [ '::1' ]
    output = { '6' => [ '::1' ], '4' => [ ], 'other' => [ ] }
    it { should run.with_params(input).and_return( output ) }
  end

  context '=> v4 Only' do
    input = [ '127.0.0.1' ]
    output = { '4' => [ '127.0.0.1' ], '6' => [ ], 'other' => [ ] }
    it { should run.with_params(input).and_return( output ) }
  end

  context '=> other only' do
    input = [ 'localhost' ]
    output = { 'other' => [ 'localhost' ], '4' => [ ], '6' => [ ] }
    it { should run.with_params(input).and_return( output ) }
  end

  context '=> pass nothing' do
    it { should run.with_params(nil).and_return(
      { 'other' => [ ], '4' => [ ], '6' => [ ] } )
    }
  end
end
