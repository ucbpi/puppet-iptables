# == Define: iptables::chain
#
# Setup an iptables chain
#
# === Parameters:
#
# [*comment*]
#
# Setup any comments you want to appear near this chain in the target config.
# Default is none
#
# [*policy*]
#
# Set our default policy if this is a built-in chain. If this is not a built-in
# chain, this parameter is ignored.  Default is 'ACCEPT'
#
define iptables::ipv6::chain (
  $comment = undef,
  $policy = 'ACCEPT',
) {
  include iptables::ipv6

  $tc = split($title,':')
  $table = $tc[0]
  $chain = $tc[1]

  $order = $iptables::order
  $separator = $iptables::join_separator
  $config = $iptables::ipv6::config

  # ensure our name is reasonable, according to iptables at least
  if $chain !~ /^[^-].*$/ {
    $error = "Iptables::Ipv6::Chain[${chain}] : chain name cannot begin with a \
'-' : '#{chain}'"
    fail($error)
  }

  # build our table if it has not been defined yet
  if ! defined( Iptables::Ipv6::Table[$table] ) {
    iptables::ipv6::table{ $table: }
  }
  $table_order_arr = [ $order['table'][$table], $table ]
  $table_order = join( $table_order_arr, $separator )

  # grab the builtin chains for this table
  $builtin = $iptables::ipv6::builtin_chains[$table]

  # if the chain is a builtin, apply the policy
  if member( $builtin, $chain ) {
    $policy_r = upcase( $policy )
    validate_re( $policy_r, '^(ACCEPT|DROP)$',
      "invalid chain policy - ${policy_r}" )
  } else {
    $policy_r = '-'
  }

  $chain_order_arr = [ $table_order, $order['chain']['name'], $chain ]
  $chain_order = join( $chain_order_arr, $separator )

  $file_content = $comment ? {
    undef   => ":${chain} ${policy_r} [0:0]\n",
    default => "# ${comment}\n:${chain} ${policy_r} [0:0]\n",
  }

  concat::fragment { "ip6tables-table-${table}-chain-${chain}":
    order   => $chain_order,
    target  => $config,
    content => $file_content,
  }
}
