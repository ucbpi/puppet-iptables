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
# [*table*]
#
# Which table should this be associated with? Default is 'filter'
#
define iptables::chain (
  $comment = undef,
  $policy = 'ACCEPT',
  $table = 'filter'
) {
  include iptables

  $chain_r = upcase( $title )
  $table_r = downcase( $table )

  if ! has_key( $iptables::priority[table], $table_r ) {
    # this is not a valid table, otherwise we would have noted the built-in
    # tables for the chain. go for the punt!
    fail( "invalid iptables table - ${table_r}" )
  } else {
    # let's determine our policy for the chain
    $builtin_chains = $iptables::builtin_chains[$table_r]
    if member( $builtin_chains, $chain_r ) {
      # this is a built-in chain, policy must be one of ACCEPT or DROP
      $policy_r = upcase( $policy )
      validate_re( $policy_r, '^(ACCEPT|DROP)$',
        "invalid chain policy - ${policy_r}")
      $chain_pri = $iptables::priority[chain][builtin]
    } else {
      $policy_r = '-'
      $chain_pri = $iptables::priority[chain][other]
    }
  }

  $separator='_'
  $table_pri = $iptables::priority[table][$table_r]
  $secondary_pri = lead( $chain_pri, $iptables::secondary_priority_width )
  $priorities =
    [ $table_pri, $table_r, $secondary_pri, $chain_r ]
  $file_pri = join( $priorities, $separator )

  $file_content = $comment ? {
    undef   => ":${chain_r} ${policy_r} [0:0]\n",
    default => "# ${comment}\n:${chain_r} ${policy_r} [0:0]\n",
  }

  concat::fragment { "iptables-table-${table_r}-chain-${chain_r}":
    order   => $file_pri,
    target  => $iptables::file_r,
    content => $file_content,
  }

  if ! defined( Iptables::Table[$table_r] ) {
    iptables::table { $table_r: }
  }
}
