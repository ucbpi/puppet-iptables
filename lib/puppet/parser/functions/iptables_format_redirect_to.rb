module Puppet::Parser::Functions
  newfunction(:iptables_format_redirect_to, :type => :rvalue,:doc => <<-EOS
  EOS
) do |args|
    red = ''
    red = args[0] if args[0].is_a?(String)

    return red if red == ''

    nums = red.split(':')

    nums.each do |n|
      # if we were given integer ports, do some minor logic on them
      if n.is_a? String and n.to_i.to_s == n and n.to_i > 65535
        raise Puppet::ParseError, "invalid port number (max is 65535)"
      end

      # if we ever figure out a way to look into the /etc/services file, we can
      # try and verify that the ports are valid
    end

    if nums.size == 1
      return "--redirect-to #{nums[0]}"
    elsif nums.size == 2
      return "--redirect-to #{nums[0]}:#{nums[1]}"
    else
      raise Puppet::ParseError, "invalid range definition '#{red}'"
    end
  end
end
