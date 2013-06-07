require 'spec_helper'

describe 'format_port' do
  context "=> test defaults to dport" do
    it { should run.with_params('22') \
      .and_return( { 'port' => '--dport 22', 'multiport' => false } ) }
  end

  context "=> test array of legal dports" do
    it { should run.with_params([ '22', '80' ],'dport') \
      .and_return( { 'port' => '--dports 22,80', 'multiport' => true } ) }
  end

  context "=> test array of mixed legality dports" do
    input = [ "ftp", "ssh", "80", "443" ]
    output = {
      'port' => "--dports 80,443",
      'multiport' => true,
    }
    it { should run.with_params(input,'dport').and_return( output ) }
  end

  context "=> test array of all illegal sports" do
    input = [ "ftp", "ssh", "ssh" ]
    it { 
      should run.with_params(input,"sport").and_raise_error(Puppet::ParseError)
    }
  end

  context "=> test array of all the same sport" do
    input = [ "22", "22", "22" ]
    output = { 
      'port' => '--sport 22',
      'multiport' => false,
    }
    it { should run.with_params(input,'sport').and_return(output) }
  end

  context "=> test array of multiple duplicate sports" do
    input = [ "22", "22", "22", "80", "80" ]
    output = { 
      'port' => '--sports 22,80',
      'multiport' => true,
    }
    it { should run.with_params(input,'sport').and_return(output) }
  end
  context "=> test array of all the same sport" do
    input = [ "22", "22", "22" ]
    output = { 
      'port' => '--sport 22',
      'multiport' => false,
    }
    it { should run.with_params(input,'sport').and_return(output) }
  end

  context "=> send undef" do
    it {
      input = :undef
      output = {
        'port' => '',
        'multiport' => false,
      }
      should run.with_params(input,'sport').and_return(output)
    }
  end
  context "=> send nil" do
    it {
      input = nil
      output = {
        'port' => '',
        'multiport' => false,
      }
      should run.with_params(input,'sport').and_return(output)
    }
  end

  context "=> port range notation" do
    it {
      # This should work
      input = "32768:61000"
      output = { 'port' => "--dport 32768:61000", 'multiport' => false }
      should run.with_params(input).and_return(output)

      # This should fail
      input = "32768:"
      should run.with_params(input).and_raise_error(Puppet::ParseError)
    }
  end
end
