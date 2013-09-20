require 'spec_helper'

describe 'format_protocol' do

  #
  ### Strict Protocol Checking Enabled
  context "=> strict protocol checking enabled" do

    context "=> test with no protocol passed" do
      it { should run.with_params( '' ).and_return( '' ) }
    end

    context "=> test with undef passed" do
      it { should run.with_params( :undef ).and_return('') }
    end

    context "=> test with nil passed" do
      it { should run.with_params( nil ).and_return('') }
    end

    #
    ## No Protocol Version Passed
    context "=> no proto version passed" do

      context "=> test illegal protocol type" do
        it { should run.with_params('tcp6').and_raise_error(Puppet::ParseError) }
      end

      context "=> test legal protocol" do
        it { should run.with_params('tcp').and_return( '-p tcp' ) }
      end

      context "=> test non-built-in protocol type" do
        it {
          should run.with_params('eigrp').and_raise_error(Puppet::ParseError)
        }
      end

      context "=> test numeric protocol" do
        it {
          should run.with_params('88').and_return('-p 88')
        }
      end
    end

    #
    ## Protocol Version 4
    context "=> proto version 4" do
      context "=> test illegal protocol type - v4" do
        it {
          should run.with_params('tcp6','4').and_raise_error(Puppet::ParseError)
        }
      end

      context "=> test legal protocol - v4" do
        it { should run.with_params('tcp','4').and_return( '-p tcp' ) }
      end

      context "=> test non-built-in protocol type" do
        it {
          should run.with_params('eigrp','4').and_raise_error(Puppet::ParseError)
        }
      end

      context "=> test numeric protocol" do
        it {
          should run.with_params('88','4').and_return('-p 88')
        }
      end
    end

    #
    ## Protocol Version 6
    context "=> proto version 6" do
      
      context "=> test illegal protocol type - v6" do
        it { 
          should run.with_params('tcp6','6').and_raise_error(Puppet::ParseError)
        }
      end

      context "=> test legal protocol - v6" do
        it { should run.with_params('tcp','6').and_return( '-p tcp' ) }
      end
      
      context "=> test icmp to icmpv6 assumption" do
        it { should run.with_params( 'icmp', '6' ).and_return( '-p icmpv6' ) }
      end
      
      context "=> test numeric protocol version passed" do
        it { should run.with_params('icmp',6).and_return( '-p icmpv6' ) }
      end

      context "=> test non-built-in protocol type" do
        it {
          should run.with_params('eigrp','6').and_raise_error(Puppet::ParseError)
        }
      end

      context "=> test numeric protocol" do
        it {
          should run.with_params('88','6').and_return('-p 88')
        }
      end
    end
  end

  #
  ### Strict Protocol Checking Disabled
  context "=> strict protocol checking disabled" do
    #
    ## No Protocol Version
    context "=> no version specified" do
      context "=> test built-in protocol" do
        it { should run.with_params('tcp',nil,false).and_return('-p tcp') }
      end

      context "=> test non built-in protocol" do
        it { should run.with_params('igmp',nil,false).and_return('-p igmp') }
      end
    end

    #
    ## Protocol Version 4
    context "=> proto version 4" do
      context "=> built-in protocol" do
        it { should run.with_params('tcp', '4', false ).and_return('-p tcp') }
      end

      context "=> non-built-in protocol" do
        it { should run.with_params('eigrp','4',false).and_return('-p eigrp') }
      end

      context "=> numeric protocol" do
        it { should run.with_params('88','4',false).and_return('-p 88') }
      end
    end

    #
    ## Protocol Version 6
    context "=> proto version 6" do
      context "=> built-in protocol" do
        it { should run.with_params('tcp','6',false).and_return('-p tcp') }
      end

      context "=> non-built-in protocol" do
        it { should run.with_params('eigrp','6',false).and_return('-p eigrp') }
      end

      context "=> numeric protocol" do
        it { should run.with_params('88','6',false).and_return('-p 88') }
      end
    end
  end
end
