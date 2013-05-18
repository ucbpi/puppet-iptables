# == Define: iptables::table
# Setup an iptable, table.  Must be one of:
#
# - filter
# - nat
# - mangle
# - raw
#
# === Dependencies:
#
# - concat
# - stdlib
# - oski
#
define iptables::table {
  include iptables

  if $name !~ /^(filter|nat|mangle|raw)$/ {
    fail ( "Iptables::Table[${name}] : invalid table title - ${name}" )
  } else {
    $name_r = $name
  }

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
