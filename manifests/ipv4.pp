# == Class: iptables::ipv4
#
# Sets up our iptables (ipv4 rules)
#
class iptables::ipv4 {
  include iptables

  $config = $iptables::config
  $order = $iptables::order
  $table_order_width = $iptables::table_order_width

  $builtin_chains = {
    nat    => [ 'PREROUTING', 'OUTPUT', 'POSTROUTING' ],
    raw    => [ 'PREROUTING', 'OUTPUT' ],
    filter => [ 'INPUT', 'FORWARD', 'OUTPUT' ],
    mangle => [ 'PREROUTING', 'OUTPUT', 'INPUT', 'FORWARD', 'POSTROUTING' ]
  }

  ########
  # iptables
  #
  concat { $config:
    owner => 'root',
    group => 'root',
    mode  => '0440',
  }

  $commit_order = lead($order['table']['commit'], $table_order_width)
  concat::fragment { 'iptables-commit-line':
    ensure  => 'present',
    target  => $config,
    order   => $commit_order,
    content => "COMMIT\n",
  }

  $header_order = lead($order['table']['comment'], $table_order_width)
  concat::fragment { 'iptables-header-comment':
    target  => $config,
    content => "# Firewall Managed by Puppet\n\n",
    order   => $header_order,
  }
}