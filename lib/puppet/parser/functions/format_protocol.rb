module Puppet::Parser::Functions
  newfunction(:format_protocol, :type => :rvalue,:doc => <<-EOS
format_protocol( protocol [, version ])

Given a protocol name and ip protocol version (4 or 6), returns the partial
iptables rule to faciliate the matching on this protocol

If not specified, ip protocol version defaults to 4.

Valid protocols for each ip version:
  4: 'tcp', 'udp', 'udplite', 'icmp', 'esp', 'ah', 'sctp', 'all'
  6: 'tcp', 'udp', 'icmpv6', 'esp', 'all'

Examples:

  # returns '-p tcp'
  format_protocol('tcp',4)
  format_protocol('tcp',6)

  # returns '-p icmp'
  format_protocol('icmp',4)

  # returns '-p icmpv6'
  format_protocol('icmp',6)
  format_protocol('icmpv6',6)

  # parse error
  format_protocol('proto')
  format_protocol('proto',6)
  EOS
) do |args|
    protocols = {
      '4' => [ 'tcp', 'udp', 'udplite', 'icmp', 'esp', 'ah', 'sctp', 'all' ],
      '6' => [ 'tcp', 'udp', 'icmpv6', 'esp', 'all' ]
    }

    protocol = args[0].dup
    version = '4'
    version = '6' if String(args[1]) =~ /(ip(v)?)?6/i

    # we'll be nice and translate icmp to icmpv6 when passed icmp for formatting
    # a ipv6 protocol
    protocol = 'icmpv6' if version == '6' and protocol == 'icmp'

    # do some basic validation of the protocol
    raise Puppet::ParseError, "invalid protocol - #{protocol}" \
      unless protocols[version].include?(protocol)  

    return "-p #{protocol}"
  end
end
