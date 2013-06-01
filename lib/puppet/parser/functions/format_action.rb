module Puppet::Parser::Functions
  newfunction(:format_action, :type => :rvalue,:doc => <<-EOS
Given an action, ie. ACCEPT/REJECT or a chain name, returns the partial iptables
rule to facilitate taking the appropriate action.

Examples:

  # returns "-j ACCEPT'
  format_action('ACCEPT')

  # returns '-j LOG'
  format_action('LOG')

  # Parse Error
  format_action(nil)
  format_action('')
  format_action('SOME CHAIN')
  EOS
) do |args|
    action = args[0]

    # do some basic validation of the action
    if action =~ /\s/
      raise Puppet::ParseError, \
        "action cannot contain whitepace - \"#{action}\""
    end

    return "-j #{action}"
  end
end
