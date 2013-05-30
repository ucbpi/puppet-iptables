module Puppet::Parser::Functions
  newfunction(:format_protocol, :type => :rvalue,:doc => <<-EOS
  EOS
) do |args|
    protocols = {
      '4' => [ 'tcp', 'udp', 'udplite', 'icmp', 'esp', 'ah', 'sctp', 'all' ],
      '6' => [ 'tcp', 'udp', 'icmpv6', 'esp', 'all' ]
    }

    protocol = args[0].dup
    version = '4'
    version = '6' if args[1] =~ /(ip(v)?)?6/i

    # we'll be nice and translate icmp to icmpv6 when passed icmp for formatting
    # a ipv6 protocol
    protocol = 'icmpv6' if version == '6' and protocol == 'icmp'

    # do some basic validation of the protocol
    raise Puppet::ParseError, "invalid protocol - #{protocol}" \
      unless protocols[version].include?(protocol)  

    r_h = {
     'protocol' => "-p #{protocol}",
     'version' => version,
     'raw' => args[0],
    }

    return r_h
  end
end
