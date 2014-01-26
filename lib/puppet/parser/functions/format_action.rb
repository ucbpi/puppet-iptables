module Puppet::Parser::Functions
  newfunction(:format_action, :type => :rvalue,:doc => <<-EOS
Given an action, ie. ACCEPT/REJECT or a chain name, returns the partial iptables
rule to facilitate taking the appropriate action.

Examples:

  # returns "-j ACCEPT'
  format_action('ACCEPT')
  format_action(nil)

  # returns '-j LOG'
  format_action('LOG')

  # Parse Error
  format_action('')
  format_action('SOME CHAIN')
  EOS
) do |args|
    action = 'ACCEPT'
    action = args[0] unless args[0] == nil

    if action == :undef or action == ''
      raise Puppet::ParseError, \
        "action not specified"
    end

    # do some basic validation of the action
    if action =~ /\s/
      raise Puppet::ParseError, \
        "action cannot contain whitespace - \"#{action}\""
    end

    return "-j #{action}"
  end
end
