# == Define: iptables::rule
#
# Defines a iptables rule to be applied to the system
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
# IP Address, Subnet or Range.  IPv4 only for now
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
# [*protocol*]
#
# Applies this rule only to the specified protocol
#
# [*priority*]
#
# Rule priority, rules are processed in ascending order.
#
# [*source*]
#
# Source address, subnet or ip range.  IPv4 only for now.
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
  $protocol = undef,
  $priority = undef,
  $raw = undef,
  $reject_with = undef,
  $source = undef,
  $source_port = undef,
  $state = undef,
  $table = undef
) {
  include iptables

  # set a default priority
  if $priority {
    $priority_r = lead( $priority, $iptables::rule_priority_width )
  } else {
    $priority_r = $iptables::priority[rule]['default']
  }

  # used for strict checking of log levels in rules
  $log_priorities = {
    'emerg'   => 0,
    'panic'   => 0,
    'alert'   => 1,
    'crit'    => 2,
    'err'     => 3,
    'error'   => 3,
    'warn'    => 4,
    'warning' => 4,
    'notice'  => 5,
    'info'    => 6,
    'debug'   => 7,
  }

  # used so we can do strict checking of log levels
  $log_facilities = {
    kern      => 0,
    user      => 1,
    mail      => 2,
    daemon    => 3,
    auth      => 4,
    syslog    => 5,
    lpr       => 6,
    news      => 7,
    uucp      => 8,
    clock     => 9, # not technically reserved
    authpriv  => 10,
    ftp       => 11,
    ntp       => 12, # not technically reserved
    log_audit => 13, # not technically reserved
    log_alert => 14, # not technically reserved
    cron      => 15,
    local0    => 16,
    local1    => 17,
    local2    => 18,
    local3    => 19,
    local4    => 20,
    local5    => 21,
    local6    => 22,
    local7    => 23,
  }


  # Clean up user input
  #

  # action
  if $action {
    $action_r = upcase( $action )
    # TODO: Better validation
    validate_re( $action_r, '^[A-Z][0-9A-Za-z_]*$' )
  }
  else { $action_r = 'ACCEPT' }

  # Chain
  if $chain { $chain_r = upcase( $chain ) }
  else { $chain_r = 'INPUT' }

  # User comment
  if $comment { $comment_r = regsubst( $comment, '\n', '' ) }
  else { $comment_r = undef }


  # Destination address
  if $destination {
    $destination_r = $destination
  } else {
    $destination_r = undef
  }

  # Destination port
  if $destination_port {
    $destination_port_r = $destination_port
    if is_array( $destination_port_r ) {
      # we were given an array of ports. we need to find a way to check these
    } else {
      validate_re( $destination_port_r, '^[0-9]{1,5}$' )
    }
  } else { $destination_port_r = undef }

  # outgoing interface
  if $outgoing_interface {
    # We were passed an interface
    $interfaces = split( $::interfaces, ',' )
    if ! ( $outgoing_interface in $interfaces ) {
      warning("interface '${outgoing_interface}' does not appear to be present")
    }
    $outgoing_interface_r = $outgoing_interface
    validate_re( $outgoing_interface, '^[a-z._]+[0-9]*$' )
  }

  # incoming interface
  if $incoming_interface {
    # We were passed an interface
    $interfaces = split( $::interfaces, ',' )
    if ! ( $incoming_interface in $interfaces ) {
      warning("interface '${incoming_interface}' does not appear to be present")
    }
    $incoming_interface_r = $incoming_interface
    validate_re( $incoming_interface, '^[a-z._]+[0-9]*$' )
  }

  # protocol
  if $protocol {
    $protocol_r = downcase( $protocol )
    validate_re( $protocol_r, '^(tcp|udp|udplite|icmp|esp|ah|sctp|all)$' )
  } else {
    $protocol_r = 'all'
  }

  # Source address
  if $source {
    $source_r = $source
  } else {
    $source_r = undef
  }

  # Source port
  if $source_port {
    if is_array( $source_port ) {
      # TODO better validation for arrays
    } else {
      # TODO: better port validation
      validate_re( $source_port_r, '^[0-9]{1,5}$' )
    }
    $source_port_r = $source_port
  } else {  $source_port_r = undef }

  if $reject_with {
    $reject_with_r = downcase( $reject_with )
    if ! member( $iptables::icmp_reject_types, $reject_with ) {
      fail( "invalid reject-with type -- ${reject_with_r}" )
    }
  }
  else { $reject_with_r = undef }

  if $table {
    $table_r = downcase( $table )
    if ! has_key ( $iptables::builtin_chains, $table_r ) {
      fail ( "invalid table name -- ${table_r}" )
    }
  } else {
    $table_r = 'filter'
  }

  if $state { $state_r = $state }
  else { $state_r = undef }

  # Define our chain if it isn't already
  if ! defined( Iptables::Chain[$chain_r] ) {
    iptables::chain { $chain_r:
      table => $table_r,
    }
  }

  $table_priority_r = $iptables::priority[table][$table_r]
  $chain_priority_r = $chain_r
  $priorities = [ $table_priority_r, $table_r, $priority_r, $chain_r ]
  $rule_priority_r = join( $priorities, $iptables::join_separator )

  concat::fragment { "rule-${name}":
    target  => $iptables::file_r,
    order   => $rule_priority_r,
    content => template('iptables/rule_line.erb'),
  }
}
