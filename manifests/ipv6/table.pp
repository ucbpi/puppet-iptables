# == Define: iptables::table
# Setup an iptable, table.  Must be one of:
#
# - filter
# - nat
# - mangle
# - raw
#
define iptables::ipv6::table {
  include iptables::ipv6

  $order = $iptables::order
  $table_width = $iptables::table_order_width
  $chain_width = $iptables::chain_order_width
  $separator = $iptables::join_separator
  $config = $iptables::ipv6::config

  if $name !~ /^(filter|mangle|raw)$/ {
    fail ( "Ip6tables::Table[${name}] : invalid table title - ${name}" )
  }

  $table_order = lead( $order['table'][$name], $table_width )
  $chain_order = lead( $order['chain']['table'], $chain_width )

  $table_order_arr = [ $table_order, $name, $chain_order ]
  $table_order_r = join( $table_order_arr, $separator )

  concat::fragment { "ip6tables-table-${name}":
    target  => $config,
    order   => $table_order_r,
    content => "*${name}\n",
  }
}
