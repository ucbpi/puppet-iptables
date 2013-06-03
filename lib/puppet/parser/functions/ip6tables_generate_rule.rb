module Puppet::Parser::Functions
  newfunction(:ip6tables_generate_rule, :type => :rvalue, :doc => <<-EOS
Provided an array of options, generates iptables rule(s) 
EOS
) do |args|
    Puppet::Parser::Functions.function('iptables_prep_option')
    Puppet::Parser::Functions.function('format_action')
    Puppet::Parser::Functions.function('split_ip_by_version')
    Puppet::Parser::Functions.function('format_chain')
    Puppet::Parser::Functions.function('format_interface')
    Puppet::Parser::Functions.function('format_port')
    Puppet::Parser::Functions.function('format_protocol')
    Puppet::Parser::Functions.function('format_state')

    options = args[0]
    defaults = args[1]

    flags = {}
    flags.default = false

    #
    ## action option (act)
    #
    act_input = function_iptables_prep_option( [ 'action', options, defaults,
                                                  'ACCEPT' ] )
    act = function_format_action( [ act_input ] )
    flags["act_#{act_input}"] = true  # flags['act_LOG'], flags['act_REJECT']

    #
    ## chain option (chn)
    #
    chn_input = function_iptables_prep_option( [ 'chain', options, defaults,
                                               'INPUT' ] )
    chn = function_format_chain( [ chn_input ] )
    flags["chn_#{chn_input}"] = true

    #
    ## destination option (dst_ip)
    #
    dst = function_iptables_prep_option( [ 'destination', options, defaults ] )
    dst = function_split_ip_by_version( [ dst ] )['ipv6']
    dst.push('') if dst.size == 0

    #
    ## destination_port option (dport)
    
    dport = function_iptables_prep_option( [ 'destination_port', options,
                                              defaults ] )
    r_h = function_format_port( [ dport, 'dport' ] )
    dport = r_h['port']
    flags['multiport'] = true if r_h['multiport']

    #
    ## source option (src_ip)
    #
    src = function_iptables_prep_option( [ 'source', options, defaults ] )
    src = function_split_ip_by_version( [ src ] )['ipv6']
    src.push('') if src.size == 0 

    #
    ## source_port option (sport)
    #
    sport = function_iptables_prep_option( [ 'source_port', options,
                                              defaults ] )
    r_h = function_format_port( [ sport, 'sport' ] )
    sport = r_h['port']
    flags['multiport'] = true if r_h['multiport']

    #
    ## incoming_interface option (in_int)
    #
    in_int = function_iptables_prep_option( [ 'incoming_interface', options,
                                                defaults ] )
    in_int = function_format_interface( [ in_int, 'in' ] )

    #
    ## outgoing_interface option (out_int)
    #
    out_int = function_iptables_prep_option( [ 'outgoing_interface', options,
                                                defaults ] )
    out_int = function_format_interface( [ out_int,'out' ] )

    raise Puppet::ParseError,
      "only the FORWARD chain may specify both an in and out interface" \
      if out_int != '' and in_int != '' and ! flags['chn_FORWARD']

    #
    ## protocol option (proto)
    #
    proto = function_iptables_prep_option( [ 'protocol', options, defaults ] )
    proto = function_format_protocol( [ proto, '6' ] )
    flags["proto_#{proto}"] = true

    #
    ## state option (ste)
    #
    ste = function_iptables_prep_option( [ 'state', options, defaults ] )
    r_h = function_format_state( [ ste ] )
    ste = r_h['state']

    #
    ## begin processing
    #
    rules = [ ]


    # lets handle the comments first
    comment_line_width = 80
    comment = options['comment']
    if comment != nil 
      prepend = "# "
      comment_width = comment_line_width - prepend.length
      comments = []
      if comment.kind_of?(Array)
        comment.each do |c|
          comments += c.scan(/.{1,#{comment_width}}/) if c.kind_of?(String)
        end
      else
        comments = comment.scan(/.{1,#{comment_width}}/)
      end
      comments.map! { |c| c = prepend + c }
      rules += comments
    end

    # allow users to pass rule rule code through, without being
    # tampered with
    raw = options['raw']

    src.each do |s|
      # we'll store our pieces here, and join() them later
      rule = []

      @src = "-s #{s}" if s != ''
      @src = nil if s == nil or s == ''
      dst.each do |d|
        @dst = "-d #{d}" if d != ''
        @dst = nil if d == nil or d == ''
        rule.push(chn)
        rule.push(in_int)
        rule.push(out_int)
        rule.push(@src)
        rule.push(@dst)
        rule.push(proto)
        rule.push('-m multiport') if flags['multiport']
        rule.push(sport)
        rule.push(dport)
        rule.push(raw)
        rule.push(act)
        rule.compact!
        rule.delete('')
      end

      rules.push(rule.join(' '))
    end
    return rules
  end
end
