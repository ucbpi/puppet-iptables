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
define iptables::ipv6::rule ( $options = undef, $defaults = undef ) {
  include iptables::ipv6

  $order = $iptables::order
  $separator = $iptables::join_separator
  $rule_width = $iptables::rule_order_width

  $opt = iptables_parse_options( $options, $defaults, '6' )

  if $opt['table'] =~ /^[a-z]$/ {
    $table = $opt['table']
  } else {
    $table = 'filter'
  }

  if $opt['chain'] =~ /^[^-].*$/ {
    $chain = $opt['chain']
  } else {
    $chain = 'INPUT'
  }

  # setup our chain if not done already.  let it handle
  # setting up our table
  $chain_res = Iptables::Ipv6::Chain[$chain]
  if ! defined ( $chain_res ) {
    iptables::ipv6::chain{ $chain: }
  }

  $builtin = $iptables::ipv6::builtin_chains[$table]
  $rule = join( iptables_generate_rule( $opt, '6' ), "\n" )

  $table_order_arr = [ $order['table'][$table], $table ]
  $table_order = join( $table_order_arr, $separator )

  if ! $chain =~  /^(ADMIN|INPUT)$/ { fail( "chain - ${chain}") }
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
