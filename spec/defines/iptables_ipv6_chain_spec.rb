require 'spec_helper'

describe 'iptables::ipv6::chain' do
  let(:facts) { { :concat_basedir => '/var/lib/puppet/concat' } }

  context '=>  builtin chain' do
    let(:title) { 'filter:INPUT' }

    context '=> no options' do
      it do
        should contain_concat__fragment('ip6tables-table-filter-chain-INPUT') \
          .with( { 'order' => '1_filter_1_INPUT',
                   'target' => '/etc/sysconfig/ip6tables',
                   'content' => ":INPUT ACCEPT [0:0]\n" } )
      end
    end

    context '=> with comment' do
      let(:params) { { 'comment' => 'comment here' } }
      it do
        should contain_concat__fragment('ip6tables-table-filter-chain-INPUT') \
          .with( { 'order' => '1_filter_1_INPUT',
                   'target' => '/etc/sysconfig/ip6tables',
                   'content' => "# comment here\n:INPUT ACCEPT [0:0]\n" } )
      end
    end

    context '=> with valid policy' do
      let(:params) { { 'policy' => 'drop' } }
      it do
        should contain_concat__fragment('ip6tables-table-filter-chain-INPUT') \
          .with( { 'order' => '1_filter_1_INPUT',
                    'target' => '/etc/sysconfig/ip6tables',
                    'content' => ":INPUT DROP [0:0]\n" } )
      end
    end

    context '=> with invalid policy' do
      let(:params) { { 'policy' => 'reject' } }
      it do
        expect {
          should contain_concat__fragment('ip6tables-table-filter-chain-INPUT') \
             .with( { 'order' => '1_filter_1_INPUT',
                      'target' => '/etc/sysconfig/ip6tables',
                      'content' => ":INPUT DROP [0:0]\n" } )
        }.to raise_error(Puppet::Error, /invalid chain policy/)
      end
    end
  end

  context "=> non-builtin chain" do
    let(:title) { 'filter:JUNK' }

    context '=> no options' do
      it do
        should contain_concat__fragment('ip6tables-table-filter-chain-JUNK') \
          .with( { 'order' => '1_filter_1_JUNK',
                   'target' => '/etc/sysconfig/ip6tables',
                   'content' => ":JUNK - [0:0]\n" } )
      end
    end

    context '=> with comment' do
      let(:params) { { 'comment' => 'comment here' } }
      it do
        should contain_concat__fragment('ip6tables-table-filter-chain-JUNK') \
          .with( { 'order' => '1_filter_1_JUNK',
                   'target' => '/etc/sysconfig/ip6tables',
                   'content' => "# comment here\n:JUNK - [0:0]\n" } )
      end
    end

    context '=> with valid policy' do
      let(:params) { { 'policy' => 'drop' } }
      it do
        should contain_concat__fragment('ip6tables-table-filter-chain-JUNK') \
          .with( { 'order' => '1_filter_1_JUNK',
                    'target' => '/etc/sysconfig/ip6tables',
                    'content' => ":JUNK - [0:0]\n" } )
      end
    end

    context '=> with invalid policy' do
      let(:params) { { 'policy' => 'reject' } }
      it do
        should contain_concat__fragment('ip6tables-table-filter-chain-JUNK') \
           .with( { 'order' => '1_filter_1_JUNK',
                    'target' => '/etc/sysconfig/ip6tables',
                    'content' => ":JUNK - [0:0]\n" } )
      end
    end
  end

  context "=> invalid name" do
    let(:title) { 'filter:-INPUT' }

    it do
      expect {
        should contain_concat__fragment('ip6tables-table-filter-chain--INPUT') \
            .with( { 'order' => '1_filter_1_-INPUT',
                     'target' => '/etc/sysconfig/ip6tables',
                     'content' => ":-INPUT - [0:0]\n" } )
      }.to raise_error( Puppet::Error, /name cannot/ )
    end
  end
end
