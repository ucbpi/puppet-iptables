module Puppet::Parser::Functions
  newfunction(:iptables_format_limit, :type => :rvalue,:doc => <<-EOS
  EOS
) do |args|
    limit = burst = ''

    limit = args[0].dup if args[0].is_a?(String)
    burst = args[1].dup if args[1].is_a?(String)

    return '' if limit == ''

    info = limit.split('/')
    value = info[0]

    valid_units = [ 'second', 'minute', 'hour', 'day' ]

    unit = info[1]
    unit = valid_units.select { |v| v =~ /^#{unit}/ }[0] unless unit.nil?
    unit ||= 'second'

    burst = "--limit-burst #{burst}" unless burst == ''

    return "-m limit --limit #{value}/#{unit} #{burst}".strip
  end
end
