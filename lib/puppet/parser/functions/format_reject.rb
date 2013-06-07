module Puppet::Parser::Functions
  newfunction(:format_reject, :type => :rvalue,:doc => <<-EOS
  EOS
) do |args|
    rej = ''
    rej = args[0] if args[0].is_a?(String)

    ver = '4'
    ver = args[1][-1].chr if args[1][-1].chr == '6'

    return rej if rej == ''

    # create a translation table so reject types from iptables
    # and ip6tables can be used as interchangeably as possible,
    # though its not perfect.
    translations = {
      # v4 to v6 translations
      'icmp-net-unreachable' => 'icmp6-no-route',
      'icmp-host-unreachable' => 'icmp6-addr-unreachable',
      'icmp-port-unreachable' => 'icmp6-port-unreachable',
      'icmp-proto-unreachable' => 'icmp6-port-unreachable',
      'icmp-net-prohibited' => 'icmp6-adm-prohibited',
      'icmp-host-prohibited' => 'icmp6-adm-prohibited',
      'icmp-admin-prohibited' => 'icmp6-adm-prohibited',
      # v6 to v4 translations
      'icmp6-no-route' => 'icmp-net-unreachable',
      'no-route' => 'icmp-net-unreachable',
      'icmp6-adm-prohibited' => 'icmp-admin-prohibited',
      'adm-prohibited' => 'icmp-admin-prohibitied',
      'icmp6-addr-unreachable' => 'icmp-host-unreachable',
      'addr-unreach' => 'icmp-addr-unreachable',
      'icmp6-port-unreachable' => 'icmp-port-unreachable',
      'port-unreach' => 'icmp-port-unreachable'
    }

    valid_rejects = {
      '4' => [ 'icmp-net-unreachable', 'icmp-host-unreachable',
               'icmp-port-unreachable', 'icmp-proto-unreachable',
               'icmp-net-prohibited', 'icmp-host-prohibited',
               'icmp-admin-prohibited' ],
      '6' => [ 'icmp6-no-route', 'no-route', 'icmp6-adm-prohibited',
               'adm-prohibited', 'icmp6-addr-unreachable', 'addr-unreach',
               'icmp6-port-unreachable', 'port-unreach' ]
    }

    if ( ver == '4' and valid_rejects['6'].include?(rej) ) or
       ( ver == '6' and valid_rejects['4'].include?(rej) ) then
       rej = translations[rej]
    end
    return "--reject-with #{rej}"
  end
end
