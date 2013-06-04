# == Define: iptables::ipv4::rule
#
# Defines a iptables rule to be applied to the system
#
# === Parameters
#
# [*options*]
#
# A hash table of all the options available to the rule
#
define iptables::ipv4::rule ( $options = undef ) {
  include iptables::ipv4

  $rule = iptables_generate_rule( $options )
  $rule_order = iptables_generate_order( $options['order'], 'rule' )

  concat::fragment { "iptables-rule-${name}":
    target  => $iptables::ipv4::config,
    order   => $rule_order,
    content => $rule,
  }
}
