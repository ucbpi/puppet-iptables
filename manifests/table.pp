# == Define: iptables::table
# Setup an iptable, table.  Must be one of:
#
# - filter
# - nat
# - mangle
# - raw
#
define iptables::table {
  include iptables

  $name_r = downcase( $name )
  validate_re( $name_r, '^(filter|nat|mangle|raw)$' )
  $separator = $iptables::join_separator
  $secondary_pri = lead( $iptables::priority[table][name],
                          $iptables::secondary_priority_width )
  $priorities = [ $iptables::priority[table][$name_r], $name_r, $secondary_pri ]

  $priority_r = join( $priorities, $separator )

  concat::fragment { "iptables-table-${name_r}":
    target  => $iptables::file_r,
    order   => $priority_r,
    content => "*${name_r}\n",
  }
}
