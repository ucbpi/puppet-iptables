# == Define: iptables::ipv6::rule
#
# Defines a iptables rule to be applied to the system
#
# === Parameters
#
# [*options*]
#
# A hash table of all the options available to the rule
#
define iptables::ipv6::rule ( $options = 'UNSET', $defaults = 'UNSET' ) {
  include iptables::ipv6

  $order = $iptables::order
  $separator = $iptables::join_separator
  $rule_width = $iptables::rule_order_width

  $opt = iptables_parse_options( $options, $defaults, '6' )

  $table = $opt['table']
  if member(keys($iptables::ipv6::builtin_chains),$table) == false {
    fail("invalid table name: ${table} for ip6tables")
  }

  if $opt['chain'] != 'UNSET' and $opt['chain'] =~ /^[^-].*$/ {
    $chain = $opt['chain']
  } else {
    $chain = 'INPUT'
  }

  # ensure our table/chain combo is already setup
  $chain_res = Iptables::Ipv6::Chain["${table}:${chain}"]
  if ! defined ( $chain_res ) {
    iptables::ipv6::chain{ "${table}:${chain}": }
  }

  $builtin = $iptables::ipv6::builtin_chains[$table]
  $rule = join( iptables_generate_rule( $opt, '6' ), "\n" )

  $table_order_arr = [ $order['table'][$table], $table ]
  $table_order = join( $table_order_arr, $separator )

  # TODO: pretty sure the following line is a bug preventing IPv6 chains other
  #       than the ADMIN and INPUT chain. Nobody has complained though, so
  #       maybe I'm forgetting while we need this?
  if $chain !~  /^(ADMIN|INPUT)$/ { fail( "chain - ${chain}") }
  $chain_order_arr = member( $builtin, $chain ) ? {
    true    => [ $order['chain'][$chain], $chain ],
    default => [ $order['chain']['other'], $chain ],
  }
  $chain_order = join( $chain_order_arr, $separator )

  $rule_order = $opt['order'] ? {
    /^[0-9]+$/ => lead( $opt['order'], $rule_width ),
    default    => lead( $order['rule']['default'], $rule_width ),
  }

  $frag_order_arr = [ $table_order, $chain_order, $rule_order ]
  $frag_order = join( $frag_order_arr, $separator )

  concat::fragment { "ip6tables-table-${table}-chain-${chain}-rule-${name}":
    target  => $iptables::ipv6::config,
    order   => $frag_order,
    content => "${rule}\n",
  }
}
