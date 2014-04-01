# == Define: iptables::rule
#
# Defines a iptables/ip6tables rule to be applied to the system
#
# === Parameters
#
# [*action*]
#
# Determines what action should occur on match.  Default is to ACCEPT.
# Valid values are:
#   ACCEPT, REJECT, LOG and any other valid CHAIN name.
#
# [*chain*]
#
# Chain to create this rule on. Defaults to 'INPUT'
#
# [*comment*]
#
# Optional value to be placed in the rule file as a comment, so reading
# the rule file is a bit easier
#
# [*destination*]
#
# IP Address, Subnet or Range.
#
# [*filter*]
#
# Determines which direction of traffic we are filtering on.  If not set,
# default is to filter on ingress traffic.
#
# [*interface*]
#
# Applies this rule only to the specified interface
#
# [*order*]
#
# Rules are processed in ascending order.
#
# [*protocol*]
#
# Applies this rule only to the specified protocol
#
# [*source*]
#
# Source address, subnet or ip range.
#
# [*state*]
#
# Match rule on particular states. Valid states are:
#   RELATED, ESTABLISHED, NEW
#
# [*strict_protocol_checking*]
#
# When set to true, protocols other than those baked into iptables/ip6tables
# must be specified by their IP Protocol number.
#
# When set to false any protocol name can be specified that exists in
# /etc/protocols on the node the rule is applied on. Puppet does not check to
# ensure the existance of protocols in /etc/protocols.
#
# Default is true
#
define iptables::rule (
  $action = 'UNSET', # accept, reject, etc
  $chain = 'UNSET', # input, output, forward, etc
  $comment = 'UNSET', # optional - puts a note in the firewall rule file
  $destination = [], # destination ip
  $destination_port = [], # destination port
  $incoming_interface = 'UNSET', # incoming interface
  $log_level = 'UNSET', # log level
  $log_prefix = 'UNSET', #
  $limit = 'UNSET',
  $limit_burst = 'UNSET',
  $outgoing_interface = 'UNSET',
  $order = 'UNSET',
  $priority = 'UNSET',
  $protocol = 'UNSET',
  $raw = 'UNSET',
  $reject_with = 'UNSET',
  $source = [],
  $source_port =  [],
  $state = 'UNSET',
  $strict_protocol_checking = 'UNSET',
  $table = 'UNSET',
  $version = 'UNSET',
) {
  include iptables

  # we renamed priority to order, but lets allow priority to be used unless
  # order is specified
  if $order == undef and $priority != undef {
    notice ('DEPRECATED: "priority" parameter is now "order"')
    $order_r = $priority
  } else {
    $order_r = $order
  }

  $ips = split_ip_by_version($source)
  $ipd = split_ip_by_version($destination)

  $options = {
    'action'                   => default2undef( $action ),
    'chain'                    => default2undef( $chain ),
    'comment'                  => default2undef( $comment ),
    'destination'              => $ipd['4'],
    'destination_port'         => $destination_port,
    'incoming_interface'       => default2undef( $incoming_interface ),
    'log_level'                => default2undef( $log_level ),
    'log_prefix'               => default2undef( $log_prefix ),
    'limit'                    => default2undef( $limit ),
    'limit_burst'              => default2undef( $limit_burst ),
    'order'                    => default2undef( $order_r ),
    'outgoing_interface'       => default2undef( $outgoing_interface ),
    'protocol'                 => default2undef( $protocol ),
    'raw'                      => default2undef( $raw ),
    'reject_with'              => default2undef( $reject_with ),
    'source'                   => $ips['4'],
    'source_port'              => $source_port,
    'strict_protocol_checking' => default2undef( $strict_protocol_checking ),
    'state'                    => default2undef( $state ),
    'table'                    => default2undef( $table ),
  }

  $options6 = {
    'action'                   => default2undef( $action ),
    'chain'                    => default2undef( $chain ),
    'comment'                  => default2undef( $comment ),
    'destination'              => $ipd['6'],
    'destination_port'         => $destination_port,
    'incoming_interface'       => default2undef( $incoming_interface ),
    'log_level'                => default2undef( $log_level ),
    'log_prefix'               => default2undef( $log_prefix ),
    'limit'                    => default2undef( $limit ),
    'limit_burst'              => default2undef( $limit_burst ),
    'order'                    => default2undef( $order_r ),
    'outgoing_interface'       => default2undef( $outgoing_interface ),
    'protocol'                 => default2undef( $protocol ),
    'raw'                      => default2undef( $raw ),
    'reject_with'              => default2undef( $reject_with ),
    'source'                   => $ips['6'],
    'source_port'              => $source_port,
    'strict_protocol_checking' => default2undef( $strict_protocol_checking ),
    'state'                    => default2undef( $state ),
    'table'                    => default2undef( $table ),
  }

  # only generate rules for a particular protocol if either:
  # 1. both protocols have 0 addresses specified
  # 2. the protocol in question has more than 0 addresses specified
  $v4_count = size($ips['4']) + size($ipd['4'])
  $v6_count = size($ips['6']) + size($ipd['6'])
  $other_count = size($ips['other']) + size($ipd['other'])
  if $v4_count > 0 and $v6_count == 0 {
    # we only apply iptables rules
    $gen4 = true
    $gen6 = false
  } elsif $v6_count > 0 and $v4_count == 0 {
    # we only apply ip6tables rules
    $gen4 = false
    $gen6 = true
  } elsif $other_count > 0 and $v4_count ==0 and $v6_count == 0 {
    fail("${title} - only invalid ip addresses specified.")
  } else {
    # we apply both
    $gen4 = true
    $gen6 = true
    if $other_count > 0 {
      warning { "${title} - invalid IPs detected and will be skipped": }
    }
  }

  case $version {
    /(?i-mx:ip(v)?)?4/: {
      # ensure we're managing at least the ipv4 file
      include iptables::ipv4
      if $gen4 { iptables::ipv4::rule { $title: options => $options } }
    }

    /(?i-mx:ip(v)?)?6/: {
      include iptables::ipv6
      if $gen6 { iptables::ipv6::rule { $title: options => $options6 } }
    }

    default: {
      # ensure we're managing the proper files
      include iptables::ipv4
      include iptables::ipv6

      if $gen4 { iptables::ipv4::rule { $title: options => $options } }
      if $gen6 { iptables::ipv6::rule { $title: options => $options6 } }
    }
  }
}
