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

  # http://tools.ietf.org/html/rfc5424 - severities
  # http://tools.ietf.org/html/rfc3164 - priorities
  #
  $syslog = {
    priority   => {
      emerg    => 0,
      alert    => 1,
      critical => 2,
      error    => 3,
      warn     => 4,
      notice   => 5,
      info     => 6,
      debug    => 7,
    },

    facility    => {
      kern      => 0,
      user      => 1,
      mail      => 2,
      daemon    => 3,
      auth      => 4,
      syslog    => 5,
      lpr       => 6,
      news      => 7,
      uucp      => 8,
      clock     => 9, # not official
      authpriv  => 10,
      ftp       => 11,
      ntp       => 12, # not official
      log_audit => 13, # not official
      log_alert => 14, # not official
      cron      => 15,
      local0    => 16,
      local1    => 17,
      local2    => 18,
      local3    => 19,
      local4    => 20,
      local5    => 21,
      local6    => 22,
      local7    => 23,
    }
  }

  # This is used to ensure consistent join separators when generating the order
  # for the concat fragments
  $join_separator = '_'
}
