module Puppet::Parser::Functions
  newfunction(:format_chain, :type => :rvalue,:doc => <<-EOS
given a chain name, returns a hash with the chain formatted for insertion into
an iptables rule along with the raw chain name.
  EOS
) do |args|
    chain = args[0]

    # Do some validation here
    if chain =~ /\s/
      raise Puppet::ParseError, \
        "chain name cannot contain whitespace - \"#{chain}\""
    end

    r_h = { 
      'chain' => "-A #{chain}",
      'raw' => chain,
    }

    return r_h
  end
end
