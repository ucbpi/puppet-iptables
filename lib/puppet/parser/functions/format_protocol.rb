module Puppet::Parser::Functions
  newfunction(:format_protocol, :type => :rvalue,:doc => <<-EOS
format_protocol( protocol [, version ])
Formats the protocol portion of an iptable rule.

Takes 3 optional arguments as input:
  String:  protocol name, defaults to 'all'
  String:  protocol version, default to '4'
  Boolean: strict protocol checking, defaults to 'true'

Beyond formatting the protocol component, this function also does some sanity
checking to make it difficult to pass a bad protocol value.  If strict is left
set to 'true', this function will verify the protocol is one of the protocols
baked into iptables/ip6tables.

Valid protocols for each ip version:
  4: 'tcp', 'udp', 'udplite', 'icmp', 'esp', 'ah', 'sctp', 'all'
  6: 'tcp', 'udp', 'icmpv6', 'esp', 'all'

Alternatively, you can pass an integer value representing the protocol type.

Passing 'false' as argument 3, will allow you to specify any string/integer
combination.

Examples:

  # returns '-p tcp'
  format_protocol('tcp',4)
  format_protocol('tcp',6)

  # returns '-p icmp'
  format_protocol('icmp',4)

  # returns '-p icmpv6'
  format_protocol('icmp',6)
  format_protocol('icmpv6',6)

  # returns ''
  format_protocol(undef)
  format_protocol('')

  # returns '-p eigrp'
  format_protocol('eigrp',4,false)
  format_protocol('eigrp',6,false)

  # returns '-p 88'
  format_protocol('88',4)
  format_protocol('88',6)

  # parse error
  format_protocol('proto')
  format_protocol('proto',6)
  EOS
) do |args|
    protocols = {
      '4' => [ 'tcp', 'udp', 'udplite', 'icmp', 'esp', 'ah', 'sctp', 'all' ],
      '6' => [ 'tcp', 'udp', 'icmpv6', 'esp', 'all' ]
    }

    return '' if args == nil or args[0] == :undef

    protocol = ''
    protocol = args[0].dup unless args[0] == nil
    version = '4'
    version = '6' if String(args[1]) =~ /(ip(v)?)?6/i
    strict = true
    strict = false if args[2] == false

    return protocol if protocol == ''

    # we'll be nice and translate icmp to icmpv6 when passed icmp for formatting
    # a ipv6 protocol
    protocol = 'icmpv6' if version == '6' and protocol == 'icmp'

    # if we disabled strict_protocol_checking, or if we set our protocol to an
    # integer, don't worry about verifying the protocol exists in our lists
    if strict and not protocol =~ /^[0-9]+$/
      # do some basic validation of the protocol
       raise Puppet::ParseError, "invalid protocol - #{protocol}" \
         unless protocols[version].include?(protocol)  
    end

    return "-p #{protocol}"
  end
end
