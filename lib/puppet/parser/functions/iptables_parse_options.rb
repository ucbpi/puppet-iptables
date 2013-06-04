module Puppet::Parser::Functions
  newfunction(:iptables_parse_options, :type => :rvalue, :doc => <<-EOS
EOS
) do |args|
    options = { }
    options = args[0] if args[1].is_a?(Hash)

    defaults = { }
    defaults = args[1] if args[1].is_a?(Hash)

    version = '4'
    version = args[2][-1].chr if args[2].is_a?(String) \
      and args[2] =~ /(?i-mx:ip(v)?(4|6))/

    # these are the only static defaults for our module
    mod_default = {
      'action' => 'ACCEPT',
      'chain' => 'INPUT',
    }

    # store any flags we want to pass back out to the calling function.  this
    # will end up being part of the options hash we return, with key 'mod_flags'
    mod_flags = { }

    #
    ## 'action' option - act_ flags
    #
    action_input = [ 'action', options, defaults, mod_default['action'] ]
    options['action'] = function_iptables_prep_option( action_input )
    mod_flags["act_#{options['action']}"] = true

    #
    ## 'chain' option - chn_ flags
    #
    chain_input = [ 'chain', options, defaults, mod_default['chain'] ]
    options['chain'] = function_iptables_prep_option( chain_input )
    mod_flags["chn_#{options['chain']}"] = true

    #
    ## 'destination' option
    #
    dest_input = [ 'destination', options, defaults,
                   mod_default['destination'] ]
    options['destination'] = function_iptables_prep_option( dest_input )

    #
    ## 'destination_port' option
    #
    dpt_input = [ 'destination_port', options, defaults,
                    mod_default['destination_port'] ]
    options['destination_port'] = function_iptables_prep_option( dpt_input )

    #
    ## 'incoming_interface' option
    #
    in_input = [ 'incoming_interface', options, defaults,
                 mod_default['incoming_interface'] ]
    options['incoming_interface'] = function_iptables_prep_option( in_input )

    #
    ## 'log_ip_options' option
    #
    lio_input = [ 'log_ip_options', options, defaults,
                  mod_default['log_ip_options'] ]
    options['log_ip_options']= function_iptables_prep_option( lio_input )

    #
    ## 'log_level' option
    #
    ll_input = [ 'log_level', options, defaults, mod_default['log_level'] ]
    options['log_level'] = function_iptables_prep_option( ll_input )

    #
    ## 'log_prefix' option
    #
    lp_input = [ 'log_prefix', options, defaults, mod_default['log_prefix'] ]
    options['log_prefix'] = function_iptables_prep_option( lp_input )

    #
    ## 'log_tcp_options' option
    #
    lto_input = [ 'log_tcp_options', options, defaults,
                  mod_default['log_tcp_options'] ]
    options['log_tcp_options'] = function_iptables_prep_option( lto_input )

    #
    ## 'log_tcp_sequence' option
    #
    lts_input = [ 'log_tcp_sequence', options, defaults,
                  mod_default['log_tcp_sequence'] ]
    options['log_tcp_sequence'] = function_iptables_prep_option( lts_input )

    #
    ## 'outgoing_interface' option
    #
    out_input = [ 'outgoing_interface', options, defaults,
                  mod_default['outgoing_interface'] ]
    if options['outgoing_interface'] != ''
      options['outgoing_interface'] = function_iptables_prep_option( out_input)
    end

    #
    ## 'protocol' option
    #
    proto_input = [ 'protocol', options, defaults, mod_default['protocol'] ]
    options['protocol'] = function_iptables_prep_option( proto_input )
    mod_flags["proto_#{options['protocol']}"] = true \
      unless options['protocol'] == '' 
    #
    ## 'source' option
    #
    src_input = [ 'source', options, defaults, mod_default['source'] ]
    options['source'] = function_iptables_prep_option( src_input )

    #
    ## 'source_port' option
    #
    spt_input = [ 'source_port', options, defaults, mod_default['source_port'] ]
    options['source_port'] = function_iptables_prep_option( spt_input )

    #
    ## 'state' option
    #
    ste_input = [ 'state', options, defaults, mod_default['state'] ]
    options['state'] = function_iptables_prep_option( ste_input )

    # finally, we return our options after pruning empty ones
    options.delete_if { |opt,val| val=='' }
    options['mod_flags'] = mod_flags
    return options
  end
end
