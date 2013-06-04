# == Class: iptables::ipv6
#
# Sets up our iptables (ipv6 rules)
#
class iptables::ipv6 {
  include iptables

  # We define these at in iptables, so we can limit our entry into the class
  # to just the iptables top-level class, and so we can re-use code.
  $config = $iptables::config6
  $order = $iptables::order
  $table_order_width = $iptables::table_order_width

  ########
  # iptables
  #
  concat { $config:
    owner => 'root',
    group => 'root',
    mode  => '0440',
  }

  $commit_order = lead($order['table']['commit'], $table_order_width)
  concat::fragment { 'ip6tables-commit-line':
    ensure  => 'present',
    target  => $config,
    order   => $commit_order,
    content => "COMMIT\n",
  }

  $header_order = lead($order['table']['comment'], $table_order_width)
  concat::fragment { 'ip6tables-header-comment':
    target  => $config,
    content => "# Firewall Managed by Puppet\n\n",
    order   => $header_order,
  }

  # This is used to ensure consistent join separators when generating the order
  # for the concat fragments
  $join_separator = '_'
}
