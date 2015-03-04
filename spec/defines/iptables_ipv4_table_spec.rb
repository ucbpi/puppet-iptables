require 'spec_helper'

describe 'iptables::ipv4::table' do
  let(:facts) { { :concat_basedir => '/var/lib/puppet/concat' } }

  %w{nat raw filter mangle}.each do |table|
    context "table => #{table}" do
      let(:title) { "#{table}" }

      tbl_priority = {
        'filter' => '1',
        'nat'    => '2',
        'mangle' => '3',
        'raw'    => '4',
      }

      context 'table definition' do
        it do
          should contain_concat__fragment("iptables-table-#{table}").with({
            'target' => '/etc/sysconfig/iptables',
            'order' => "#{tbl_priority[table]}_#{table}_0",
            'content' => "*#{table}\n"
          })
        end
      end

      context "commit line" do
        it do
          should contain_concat__fragment("iptables-#{table}-commit-line").with({
            'ensure' => 'present',
            'target' => '/etc/sysconfig/iptables',
            'order' => "#{tbl_priority[table]}_#{table}_9",
            'content' => "COMMIT\n" } )
        end
      end
    end
  end

  %w{forward FILTER}.each do |bad_table|
    context "table => #{bad_table}" do
      let(:title) { bad_table }

      it do
        expect {
          should contain_concat__fragment("iptables-table-#{bad_table}")
        }.to raise_error(Puppet::Error, /invalid table title/)
      end
    end
  end
end
