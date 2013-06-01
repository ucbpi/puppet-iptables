module Puppet::Parser::Functions
  newfunction(:format_action, :type => :rvalue,:doc => <<-EOS
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
