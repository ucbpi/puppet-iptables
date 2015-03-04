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
define iptables::ipv4::chain (
  $comment = undef,
  $policy = 'ACCEPT',
) {
  include iptables::ipv4

  $ct = split($title,':')
  $chain = $ct[1]
  $table = $ct[0]

  if size($ct) != 2 {
    fail("resource title expected to be 'TABLE:CHAIN', instead it looks like I only got ${title}")
  }

  $order = $iptables::order
  $config = $iptables::ipv4::config
  $separator = $iptables::join_separator

  # ensure our name is reasonable, according to iptables at least
  if $chain !~ /^[^-].*$/ {
    fail( "invalid chain - name cannot begin with a '-' character - '${chain}'" )
  }

  # build our table if it has not been defined yet
  if ! defined( Iptables::Ipv4::Table[$table] ) {
    iptables::ipv4::table{ $table: }
  }
  $table_order_arr = [ $order['table'][$table], $table ]
  $table_order = join( $table_order_arr, $separator )

  # grab the builtin chains for this table
  $builtin = $iptables::ipv4::builtin_chains[$table]

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

  concat::fragment { "iptables-table-${table}-chain-${chain}":
    order   => $chain_order,
    target  => $config,
    content => $file_content,
  }
}
