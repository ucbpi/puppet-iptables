# == Class: iptables
#
# Sets up our iptables module
#
# === Parameters:
#
# [*file*]
#
# The location of the target file where our rules will live.  Defaults to
# /etc/sysconfig/iptables
#
class iptables ( $file = undef ) {
  include concat::setup

  $file_r = $file ? {
    undef   => '/etc/sysconfig/iptables',
    default => $file,
  }

  validate_absolute_path( $file_r )

  # PRIORITY DEFINITIONS

  # The filenames we generate will end up with two key numbers, the first
  # numeric is our primary priority, and facilitates the grouping together of
  # rules with their table
  #
  # The second numeric is our secondary priority, and facilitates the specific
  # ordering of rules with respect to each other, but within the same table
  $primary_priority_width = 1

  # These should all be the same, and are just multiple variables to make
  # reading code a bit easier
  $secondary_priority_width = 3
  $rule_priority_width = 3

  $priority = {
    'comment' => {
      start   => 0,
      end     => 4,
    },

    'table'  => {
      filter => 5,
      nat    => 6,
      mangle => 7,
      raw    => 8,
      commit => 9, # not actually a table, but we'll call it one
      name   => 0, # this is actually used as a secondary priority
    },

    'chain' => {
      builtin => 1,
      other   => 9,
    },

    'rule' => {
      start   => 10,
      end     => 999,
      'default' => 500,
    }
  }

  $builtin_chains = {
    nat    => [ 'PREROUTING', 'OUTPUT', 'POSTROUTING' ],
    raw    => [ 'PREROUTING', 'OUTPUT' ],
    filter => [ 'INPUT', 'FORWARD', 'OUTPUT' ],
    mangle => [ 'PREROUTING', 'OUTPUT', 'INPUT', 'FORWARD', 'POSTROUTING' ]
  }

  $syslog = {
    severity => {
      emerg  => 0,
      panic  => 0,
      alert  => 1,
    }
  }

  concat { $file_r:
    owner => 'root',
    group => 'root',
    mode  => '0440',
  }

  $commit_priority = lead($priority[table][commit], $primary_priority_width)
  concat::fragment { 'iptables-commit-line':
    ensure  => 'present',
    target  => $file_r,
    order   => $commit_priority,
    content => "COMMIT\n",
  }

  $header_priority = lead($priority[comment][start], $primary_priority_width)
  concat::fragment { 'header_comment':
    target  => $file_r,
    content => "# Firewall Managed by Puppet\n\n",
    order   => $header_priority,
  }

  # This is used to ensure consistent join separators when generating the order
  # for the concat fragments
  $join_separator = '_'

  $icmp_reject_types = [
    'icmp-net-unreachable',
    'icmp-host-unreachable',
    'icmp-port-unreachable',
    'icmp-proto-unreachable',
    'icmp-net-prohibited',
    'icmp-host-prohibited',
    'icmp-admin-prohibited'
  ]
}
