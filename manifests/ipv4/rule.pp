# == Define: iptables::ipv4::rule
#
# Defines a iptables rule to be applied to the system
#
# === Parameters
#
# [*options*]
#
# A hash table of all the options available to the rule
#
define iptables::ipv4::rule ( $options = 'UNSET', $defaults = 'UNSET' ) {
  include iptables::ipv4

  $order = $iptables::order
  $separator = $iptables::join_separator
  $rule_width = $iptables::rule_order_width

  $opt = iptables_parse_options( $options, $defaults , '4' )

  $table = $opt['table']
  if member(keys($iptables::ipv4::builtin_chains),$table) == false {
    fail("invalid table name: ${table} for iptables")
  }

  if $opt['chain'] != 'UNDEF' and $opt['chain'] =~ /^[^- ].+$/ {
    $chain = $opt['chain']
  } else {
    $chain = 'INPUT'
  }

  # ensure our table/chain combo is already setup
  $chain_res = Iptables::Ipv4::Chain["${table}:${chain}"]
  if ! defined ( $chain_res ) {
    iptables::ipv4::chain{ "${table}:${chain}": }
  }

  $builtin = $iptables::ipv4::builtin_chains[$table]
  $rule = join( iptables_generate_rule( $opt, '4' ), "\n" )

  $table_order_arr = [ $order['table'][$table], $table ]
  $table_order = join( $table_order_arr, $separator )

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

  concat::fragment { "iptables-table-${table}-chain-${chain}-rule-${name}":
    target  => $iptables::ipv4::config,
    order   => $frag_order,
    content => "${rule}\n",
  }
}
