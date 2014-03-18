module Puppet::Parser::Functions
  newfunction(:format_interface, :type => :rvalue,:doc => <<-EOS
  EOS
) do |args|

    # setup some objects to hold our regexes
    out_rx = /^out(going)?$/i
    in_rx = /^in(coming)?$/i
    int_rx = /^[a-z0-9\.\-_]+\+?$/i

    return '' if args == nil or args[0] == :undef
    return '' if args[0] == nil

    # make sure we were at least passed a string or nil
    raise Puppet::ParseError, "non-string interface passed - #{args[0]}" \
      unless args[0].kind_of?(String)

    interface = ''
    interface = String(args[0]).dup


    # handle cases where we weren't passed an interface
    return interface if interface == ''

    direction = 'in'
    direction = args[1] unless args[1] == nil

    raise Puppet::ParseError, "invalid direction specified - #{direction}" \
      unless direction =~ /(#{out_rx}|#{in_rx})/i

    # lets assume all interfaces will only have alphanumerics, plus
    # '.' and '_'
    raise Puppet::ParseError, "bad interface name passed - #{interface}" \
      unless interface =~ int_rx

    return "-o #{interface}" if direction =~ out_rx
    return "-i #{interface}"
  end
end
