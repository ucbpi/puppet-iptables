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
  $iptables_file = undef,
  $ip6tables_file = undef,
  $version = undef
) {
  include concat::setup

  ##############################################################################
  # Parameter Validation
  ##############################################################################
  $config = $iptables_file ? {
    undef   => '/etc/sysconfig/iptables',
    default => $iptables_file,
  }

  $config6 = $ip6tables_file ? {
    undef   => '/etc/sysconfig/ip6tables',
    default => $ip6tables_file,
  }

  validate_absolute_path( $config )
  validate_absolute_path( $config6 )

  # This is used to ensure consistent join separators when generating the order
  # for the concat fragments
  $join_separator = '_'
}
