module Puppet::Parser::Functions
  newfunction(:format_port, :type => :rvalue,:doc => <<-EOS
format_port( port, type ):

Provided port(s), as either an array or comma separated list of port numbers,
and the type of port, either sport (source port) or dport (dest.  port),
generates a partial iptables rule handling the appropriate ports.

Result is returned in a hash, with the flag multiport set to true if more than
one valid port was passed.  False otherwise.

If multiple ports are specified, but some are not legal, they will be skipped
and a warning will be logged.

If all ports specified are invalid, a ParseError will be thrown.

If no ports are specified, an empty string will be returned.

If not specified, the type defaults to 'dport'

Examples:

  # returns { 'port' => '--dport 22', 'multiport' => false }
  format_port('22')

  # returns { 'port' => '--dports 22,80', 'multiport' => true }
  format_port('22,80')
  format_port([ '22', '80' ])
  format_port([ '22', '80', 'ftp' ]) # a warning is also logged for 'ftp'

  # returns { 'port' => '', 'multiport' => false }
  format_port('')
  format_port(nil)

  # throws ParseError
  format_port('ftp')
  EOS
) do |args|
    Puppet::Parser::Functions.function('warning')
    
    ports = []
    ports = args[0] unless args[0] == nil or args[0] == :undef
    type = "dport"
    type = "sport" if args[1] == "sport"


    ports = ports.split(',') if ports.kind_of?(String)
    ports.uniq!

    # special case -- we weren't given an empty array or string
    if ports.size == 0
      return { 
        'port' => '',
        'multiport' => false
      }
    end

    # go through our ports, removing any non numeric ones
    # if we've got at least one good one, we'll just skip the bad ones and warn
    # the user.  otherwise, we'll throw a parse error
    to_delete = Array.new 
    ports.each { |p| to_delete.push(p) unless p =~ /^[0-9]+(:[0-9]+)?$/ }

    # delete ports if they aren't numeric, maybe we'll support well-known ports
    # in the future...
    ports.delete_if { |port| to_delete.include?(port) }
    if ports.size > 0 and to_delete.size > 0
      function_warning(["non-numeric ports \"#{to_delete.join(',')}\" skipped"])
    elsif ports.size == 0
      raise Puppet::ParseError, "no valid ports specified"
    end

    # give some indication if they'll want to add the multiport module
    multiport = false
    multiport = true if ports.size > 1

    if multiport then port = "--#{type}s"
    else port = "--#{type}" end
    port = "#{port} #{ports.join(',')}"

    r_h = {
      'multiport' => multiport,
      'port' => port,
    }

    return r_h
  end
end
