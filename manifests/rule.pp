# == Define: iptables::rule
#
# Defines a iptables/ip6tables rule to be applied to the system
#
# === Parameters
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
# [*action*]
#
# Determines what action should occur on match.  Default is to ACCEPT.
# Valid values are:
#   ACCEPT, REJECT, LOG and any other valid CHAIN name.
#
define iptables::rule (
  $action = undef, # accept, reject, etc
  $chain = undef, # input, output, forward, etc
  $comment = undef, # optional - puts a note in the firewall rule file
  $destination = undef, # destination ip
  $destination_port = undef, # destination port
  $incoming_interface = undef, # incoming interface
  $log_level = undef, # log level
  $log_prefix = undef, #
  $limit = undef,
  $limit_burst = undef,
  $outgoing_interface = undef,
  $order = undef,
  $priority = undef,
  $protocol = undef,
  $raw = undef,
  $reject_with = undef,
  $source = undef,
  $source_port = undef,
  $state = undef,
  $table = undef,
  $version = undef
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

  $options = {
    'action'             => $action,
    'chain'              => $chain,
    'comment'            => $comment,
    'destination'        => $destination,
    'destination_port'   => $destination_port,
    'incoming_interface' => $incoming_interface,
    'log_level'          => $log_level,
    'log_prefix'         => $log_prefix,
    'limit'              => $limit,
    'limit_burst'        => $limit_burst,
    'order'              => $order_r,
    'outgoing_interface' => $outgoing_interface,
    'protocol'           => $protocol,
    'raw'                => $raw,
    'reject_with'        => $reject_with,
    'source'             => $ips['4'],
    'source_port'        => $source_port,
    'state'              => $state,
    'table'              => $table,
  }

  $options6 = {
    'action'             => $action,
    'chain'              => $chain,
    'destination'        => $destination,
    'destination_port'   => $destination_port,
    'incoming_interface' => $incoming_interface,
    'log_level'          => $log_level,
    'log_prefix'         => $log_prefix,
    'limit'              => $limit,
    'limit_burst'        => $limit_burst,
    'order'              => $order_r,
    'outgoing_interface' => $outgoing_interface,
    'protocol'           => $protocol,
    'raw'                => $raw,
    'reject_with'        => $reject_with,
    'source'             => $ips['6'],
    'source_port'        => $source_port,
    'state'              => $state,
    'table'              => $table,
  }

  # only generate rules for a particular protocol if either:
  # 1. both protocols have 0 addresses specified
  # 2. the protocol in question has more than 0 addresses specified
  $diff = size($ips['4']) - size($ips['6'])
  if $diff >= 0 { $gen4 = true }
  else { $gen4 = false }

  if $diff <= 0 { $gen6 = true }
  else { $gen6 = false }

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
