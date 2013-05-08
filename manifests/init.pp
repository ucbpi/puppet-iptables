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
# [*file6*]
#
# The location of the target file where our ip6tables rules will reside.
# Defaults to /etc/sysconfig/ip6tables
#
class iptables (
  $file = undef,
  $file6 = undef
) {
  include concat::setup

  ##############################################################################
  # Parameter Validation
  ##############################################################################
  $file_r = $file ? {
    undef   => '/etc/sysconfig/iptables',
    default => $file,
  }

  $file6_r = $file ? {
    undef   => '/etc/sysconfig/iptables',
    default => $file6,
  }

  validate_absolute_path( $file_r )
  validate_absolute_path( $file6_r )

  ##############################################################################
  # Module-wide definitions
  ##############################################################################

  # Priorities

  # To setup our iptables file in a sane order, we make use of the 'priority'
  # construct.  Currently, there are 2 priorities per file -- with each file
  # being a single rule, chain, table or comment 'definition'

  # The first priority is to align the tables and chains with their respective
  # rules, as well as set aside some space at the top of our files for comments.
  # In particular -- 0-4 are for comments.  5-8 are for the tables, 9 is used
  # exclusively for the COMMIT at the end.

  # To make it easy to expand the width of the primary priority, we'll control
  # it here.  Setting this will enforce leading zeroes be added to a primary
  # priority, until the width of the resulting string is $primary_priority_width
  # chars long.
  $primary_priority_width = 1

  # The second priority determines the order of the rules, inline comments and
  # the initial chain definitions.  In particular -- 0 is reserved for table
  # names exclusively. 1 is used for builtin chain definitions, 2-8 are unused
  # currently. 9 is for user chain definitions.  10 - 999 are used for actual
  # rules, and are up to the user to organize for their own use.

  # To make it easy to expand the width of the secondary priority, we'll control
  # it here.  Setting this will enforce leading zeroes be added to a secondary
  # priority, until the width of the resulting string is
  # $secondary_priority_width chars long.
  $secondary_priority_width = 3
  $rule_priority_width = 3

  # An example scheme is provided for you below. Note that all rules have
  # leading zeroes prepended if they are not $rule_priority_width digits of
  # length.

  # Rule Priority Scheme
  #
  #   0 -   0 : table name declaration (ie. *filter)
  #   1 -   1 : built-in chain declaration (ie. :INPUT ACCEPT [0:0])
  #   2 -   8 : reserved for future use
  #   9 -   9 : user chain declaration (ie. :ETH0 - [0:0])
  #  10 -  49 : reserved for overflow
  #  50 -  99 : infrastructure rules (ie. admin ssh, mcollective, etc.)
  # 100 - 199 : reserved for overflow
  # 200 - 299 : temporary allow/deny rules
  # 300 - 399 : reserved for overflow
  # 400 - 499 : host specific allows
  # 500 - 599 : reserved for overflow
  # 600 - 699 : host specific denials
  # 700 - 799 : reserved for overflow
  # 800 - 899 : global allows
  # 900 - 998 : reserved for overflow
  # 999 - 999 : global drop

  $priority = {
    'comment' => { # primary priority
      start   => 0,
      end     => 4,
    },

    'table'  => { # primary priority, except where noted
      filter => 5,
      nat    => 6,
      mangle => 7,
      raw    => 8,
      commit => 9,  # not actually a table, but we'll call it one since it is
                    # aligned with the tables
      name   => 0,  # this is actually used as a secondary priority. we should
                    # move it at some point
    },

    'chain' => { # secondary priority
      builtin => 1,
      other   => 9,
    },

    'rule' => { # secondary priority
      start   => 10,
      end     => 999,
      'default' => 500,
    }
  }

  # Rule Logic Helpers
  #
  # Issue #6 would likely see most of these put into the
  # generate_iptables_fragment and generate_ip6tables_fragment functions.
  #
  # link: https://github.com/arusso23/puppet-iptables/issues/6

  $icmp_reject_types = [
    'icmp-net-unreachable',
    'icmp-host-unreachable',
    'icmp-port-unreachable',
    'icmp-proto-unreachable',
    'icmp-net-prohibited',
    'icmp-host-prohibited',
    'icmp-admin-prohibited'
  ]

  $icmp6_reject_types = [
    'icmp6-no-route',
    'no-route',
    'icmp6-adm-prohibited',
    'adm-prohibited',
    'icmp6-addr-unreachable',
    'addr-unreachable',
    'icmp6-port-unreachable',
    'port-unreach'
  ]

  $builtin_chains = {
    nat    => [ 'PREROUTING', 'OUTPUT', 'POSTROUTING' ],
    raw    => [ 'PREROUTING', 'OUTPUT' ],
    filter => [ 'INPUT', 'FORWARD', 'OUTPUT' ],
    mangle => [ 'PREROUTING', 'OUTPUT', 'INPUT', 'FORWARD', 'POSTROUTING' ],
  }

  $builtin_chains6 = {
    raw    => [ 'PREROUTING', 'OUTPUT' ],
    filter => [ 'INPUT', 'FORWARD', 'OUTPUT' ],
    mangle => [ 'PREROUTING', 'OUTPUT', 'INPUT', 'FORWARD', 'POSTROUTING' ],
  }

  $syslog = {
    severity => {
      emerg  => 0,
      panic  => 0,
      alert  => 1,
    }
  }

  ########
  # iptables
  #
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
  concat::fragment { 'iptables-header-comment':
    target  => $file_r,
    content => "# Firewall Managed by Puppet\n\n",
    order   => $header_priority,
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
    order   => $commit_priority,
    content => "COMMIT\n",
  }

  concat::fragment { 'ip6tables-header-comment':
    target  => $file6_r,
    content => "# Firewall Managed by Puppet\n\n",
    order   => $header_priority,
  }

  # This is used to ensure consistent join separators when generating the order
  # for the concat fragments
  $join_separator = '_'

  $protocol_versions = [ '4', '6' ]
}
