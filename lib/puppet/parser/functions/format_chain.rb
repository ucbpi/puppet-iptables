module Puppet::Parser::Functions
  newfunction(:format_chain, :type => :rvalue,:doc => <<-EOS
format_chain( name )

Given an chain name, generates the partial iptables rule to faciliate appending
a rule to given chain.

Examples:

  # returns '-A INPUT'
  format_chain('INPUT')

  # returns '-A LOGNDUMP'
  format_chain('LOGNDUMP')

  # throws ParseError
  format_chain('SOME CHAIN')
  EOS
) do |args|
    raise Puppet::ParseError, "no chain specified" if args == nil

    chain = 'INPUT'
    chain = args[0] unless args[0] == nil

    # Do some validation here
    if chain =~ /\s/
      raise Puppet::ParseError, \
        "chain name cannot contain whitespace - \"#{chain}\""
    end

    return "-A #{chain}"
  end
end
