# == Class: iptables::ipv4
#
# Sets up our iptables (ipv4 rules)
#
# === Parameters:
#
# [*file*]
#
# The location of the target file where our rules will live.  Defaults to
# /etc/sysconfig/iptables
#
class iptables::ipv4 {
  include concat::setup

  $file = $iptables::iptables_file

  $table_order_width = 1
  $table_order = {
    comment => 0,
    filter  => 1,
    nat     => 2,
    mangle  => 3,
    raw     => 4,
    commit  => 9,
  }

  $chain_order_width = 1
  $chain_order = {
    table       => 0,
    input       => 1,
    output      => 2,
    forward     => 3,
    prerouting  => 4,
    postrouting => 5,
    other       => 9,
  }

  $rule_order_width = 1
  # These are more as a guideline, and not set in stone
  # infra_allow    - infrastructure rules that should rarely change and not be
  #                   overridden
  # temp_rules      - temporary rules
  # specific_allows - host-specific allows
  # specific_denys  - host-specific denies
  # global_allows   - global allows
  # catchall_reject - reject any non-matching rules
  $rule_order = {
    infra_rules     => 0,
    temp_rules      => 200,
    specific_allow  => 400,
    specific_deny   => 600,
    global_allows   => 800,
    catchall_reject => 999,
  }

  $order = {
    table => $table_order,
    chain => $chain_order,
    rule  => $rule_order,
  }

  # Define our valid icmp_reject_types here, this will be used by our
  # generate_iptables_fragment function
  #
  $icmp_reject_types = [
    'icmp-net-unreachable',
    'icmp-host-unreachable',
    'icmp-port-unreachable',
    'icmp-proto-unreachable',
    'icmp-net-prohibited',
    'icmp-host-prohibited',
    'icmp-admin-prohibited'
  ]

  # Define our builtin chains
  #
  $builtin_chains = {
    nat    => [ 'PREROUTING', 'OUTPUT', 'POSTROUTING' ],
    raw    => [ 'PREROUTING', 'OUTPUT' ],
    filter => [ 'INPUT', 'FORWARD', 'OUTPUT' ],
    mangle => [ 'PREROUTING', 'OUTPUT', 'INPUT', 'FORWARD', 'POSTROUTING' ],
  }

  ########
  # iptables
  #
  concat { $file:
    owner => 'root',
    group => 'root',
    mode  => '0440',
  }

  $commit_order = lead($order[table][commit], $primary_order_width)
  concat::fragment { 'iptables-commit-line':
    ensure  => 'present',
    target  => $file,
    order   => $commit_order,
    content => "COMMIT\n",
  }

  $header_order = lead($order[comment][start], $primary_order_width)
  concat::fragment { 'iptables-header-comment':
    target  => $file,
    content => "# Firewall Managed by Puppet\n\n",
    order   => $header_order,
  }

  #######
  # ip6tables
  #
  concat { $file6_r:
    owner => 'root',
    group => 'root',
    mode  => '0440',
  }

  concat::fragment { 'ip6tables-commit-line':
    target  => $file6_r,
    order   => $commit_order,
    content => "COMMIT\n",
  }

  concat::fragment { 'ip6tables-header-comment':
    target  => $file6_r,
    content => "# Firewall Managed by Puppet\n\n",
    order   => $header_order,
  }

  # This is used to ensure consistent join separators when generating the order
  # for the concat fragments
  $join_separator = '_'

  $protocol_versions = [ '4', '6' ]
}
