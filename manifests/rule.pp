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

  $options = {
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
    'source'             => $source,
    'source_port'        => $source_port,
    'state'              => $state,
    'table'              => $table,
  }

  case $version {
    /(?i-mx:ip(v)?)?4/: { iptables::ipv4::rule { $title: options => $options } }
    /(?i-mx:ip(v)?)?6/: { iptables::ipv6::rule { $title: options => $options } }
    default: {
      iptables::ipv4::rule { $title: options => $options }
      iptables::ipv6::rule { $title: options => $options }
    }
  }
}
