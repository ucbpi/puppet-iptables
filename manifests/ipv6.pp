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

  # taken from the man page of ip6tables 1.4.7 on rhel6
  $builtin_chains = {
    filter => [ 'INPUT', 'FORWARD', 'OUTPUT' ],
    mangle => [ 'PREROUTING', 'OUTPUT', 'INPUT', 'FORWARD', 'POSTROUTING' ],
    raw    => [ 'PREROUTING', 'OUTPUT' ],
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

  # ensure we have at least the filter table defined, so if no rules are defined
  # we can restart the firewall without errors
  $filter_table_obj = Iptables::Ipv6::Table['filter']
  if ! defined( $filter_table_obj ) { iptables::ipv6::table { 'filter': } }
}
