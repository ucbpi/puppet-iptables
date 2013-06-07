module Puppet::Parser::Functions
  newfunction(:format_log, :type => :rvalue,:doc => <<-EOS
format_log( options ):

  EOS
) do |args|
    syslog_priorities = {
      'emerg'   => '0',
      'panic'   => '0',
      'alert'   => '1',
      'crit'    => '2',
      'err'     => '3',
      'error'   => '3',
      'warn'    => '4',
      'warning' => '4',
      'notice'  => '5',
      'info'    => '6',
      'debug'   => '7',
    }

    raise Puppet::ParseError, "input must be an anonymous array" \
      unless args.is_a?(Array)

    return '' unless args[0] != nil

    raise Puppet::ParseError, "input must be hash table" \
      unless args[0].is_a?(Hash)

    opts = args[0] unless args[0] == nil

    log_opts = Array.new

    #
    ## log_level option
    #
    loglevel = []
    loglevel = opts['log_level'].split('.') unless opts['log_level'] == nil

    if loglevel.size == 1
      # we were just passed the log level, if it's a text version, convert it to
      # numeric
      loglevel[0] = syslog_priorities[loglevel[0]] \
        if syslog_priorities.has_key?(loglevel[0])

      # make sure it's a valid syslog priority
      raise Puppet::ParseError, "invalid log level passed - #{loglevel[0]}" \
        unless syslog_priorities.has_value?(String(loglevel[0]))

      log_opts.push("--log-level #{loglevel[0]}")
    elsif loglevel.size == 0
      # no log_level info was passed, we can move on
    else
      raise Puppet::ParseError, \
        "invalid log level passed - #{opts['log_level']}"
    end

    #
    ## log_prefix options
    #
    logprefix = ''
    logprefix = opts['log_prefix'] unless opts['log_prefix'] == nil

    if logprefix.size == 0
      # do nothing
    elsif logprefix.size > 0
      # push the first 29 characters, giving a warning if we trimmed some
      log_opts.push("--log-prefix '" + logprefix.scan(/^.{1,29}/)[0] + "'")
      function_warning(["log prefix \"#{logprefix}\" exceeds 29 characters." \
                      + " Truncating chars beyond 29"]) if logprefix.size > 29
    end

    #
    ## log_tcp_options option
    #
    log_opts.push('--log-tcp-options') if opts['log_tcp_options']

    #
    ## log_ip_options option
    #
    log_opts.push('--log-ip-options') if opts['log_ip_options']

    #
    ## log_uid option
    #
    log_opts.push('--log-uid') if opts['log_uid']

    #
    ## log_tcp_sequence
    #
    log_opts.push('--log-tcp-sequence') if opts['log_tcp_sequence']

    return log_opts.join(' ')
  end
end
