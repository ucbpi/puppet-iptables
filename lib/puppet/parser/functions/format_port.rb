module Puppet::Parser::Functions
  newfunction(:format_port, :type => :rvalue,:doc => <<-EOS
  EOS
) do |args|
    Puppet::Parser::Functions.function('warning')
    
    ports = args[0].dup
    type = "dport"
    type = "sport" if args[1] == "sport"

    # special case -- we weren't given any ports to format
    if ports.size == 0
      return { 
        'port' => '',
        'ports' => '',
        'raw' => args[0],
        multiport => false
      }
    end

    ports = ports.split(',') unless ports.kind_of?(Array)
    ports.uniq!

    # go through our ports, removing any non numeric ones
    # if we've got at least one good one, we'll just skip the bad ones and warn
    # the user.  otherwise, we'll throw a parse error
    to_delete = Array.new 
    ports.each { |port| to_delete.push(port) if port =~ /[^0-9]/ }

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
      'ports' => port,
      'raw' => args[0],
    }

    return r_h
  end
end
