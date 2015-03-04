#iptables

[![Build Status](https://travis-ci.org/arusso/puppet-iptables.png?branch=master)](https://travis-ci.org/arusso/puppet-iptables)

####Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Design Philosophy - Why did we decide to do things a certain way?](#design-philosophy)
4. [Setup - The basics of getting started with iptables](#getting-started)
    * [Examples - Demonstration of common features](#examples)
5. [Usage - The classes and defined types available for configuration](#usage)
6. [Reference](#reference)

##Overview

This module allows you to manage your iptables rules through the management of
the on-disk iptables configuration.

##Module Description

iptables is a widely used firewall tool found on most Linux systems. This module
provides the ability to create complex iptables rulesets.

##Design Philosophy

The general philosophy of this module is to maintain pristine on-disk
configurations, rather than modifying the running rules. This has some nice
benefits, such as being able to add comments into your firewall rules making
them easier to read in cases of debugging.

In addition, we try expose a more iptables-specific interface for our resources,
making it easier to read what you're doing inside of your manifest files.

We also try hard to catch any obvious errors early, to prevent bad
configurations from ever running in production.

##Setup

###Scope of Management
**Warning**: iptables rules not managed by Puppet will be purged!

* This module manipulates the on-disk iptables rules
* This module can manage the iptables service (TODO)

###The Basic Concepts

The foundation of this module is understanding every rule has an order, from
000-999, and that the rules will be placed in ascending order in the specified
chain.

Rules assume only three defaults -- the default table is 'filter',the default
chain is 'INPUT' and the default action is 'ACCEPT'.  So creating an empty rule
will always result in the rule '-A INPUT -j ACCEPT' being generated in the
'filter' table.

The module also takes into account when IPv6 address are supplied, and will
generate IPv6 rules accordingly.  If you specify options that are only valid
for IPv4, it will throw an error (hopefully a useful one -- if not, file an
issue!).  We'd rather throw an error and make you aware of an issue early on,
then to discover later that your rule only partially applied.

##Usage

###Classes and Defined Types

####Class: `iptables`

The iptables module base class. This class is not generally necessary unless you
you need or want to override the iptables or ip6tables file location.

**Parameters within `iptables`:**

#####`iptables_file`

This sets the iptables file location. If left unset, the default is `/etc/sysconfig/iptables`

#####`ip6tables_file`

This sets the ip6tables file location. If left unset, the default is `/etc/sysconfig/ip6tables`

####Defined Type: `iptables::rule`

The iptables rule defined type. This defined type does all the hard work and includes functionality for generating both iptables and ip6tables rules.

**Parameters within `iptables::rule`:**

#####`action`

This sets the rule target. This should be either a custom chain, or one of the built-in target's such as 'ACCEPT' or 'REJECT'. If left unset, this defaults to 'ACCEPT'

#####`chain`

This sets the chain the rule is declared on. If left unset, this defaults to 'INPUT'

#####`comment`

A comment to place above the rule in the iptables file. By default no comment is placed above the rule.

#####`destination`

The destination ip or hostname for a rule.

If multiple ips or hostnames are specified, either as an array or as a comma-separated string (very useful when working with hiera), the multiple rules will be created to accomodate them.

#####`destination_port`

The destination port for a rule.

If multiple ports are specified, either as an array or as a comma-separated string (very useful when working with hiera), the rule will gracefully handle setting the appropraite options for multiport rules.

#####`incoming_interface`

The incoming interface to witch the rule should be applied to. only works on the 'INPUT' chain, or any chain that is jumped to from the 'INPUT' chain.

#####`log_level`

**Note: you must set the `action` parameter to the 'LOG' target for this to be effective**

Sets the syslog logging priority of the rule. Must set the `action` parameter to the 'LOG' target for it to be effective.

#####`log_prefix`

**Note: you must set the `action` parameter to the 'LOG' target for this to be effective**

Sets the syslog entry prefix of the rule. Packets matching rules with this set will have their log entries prefix with this value.

#####`outgoing_interface`

The outgoing interface to which the rule should be applied to. Only works on the 'OUTPUT' chain, or any chain that is jumped to from the 'OUTPUT' chain.

#####`order`

Specifies the order of the rule in the table/chain. Valid values are 0-999. The default value is '500'.

#####`protocol`

The protocol the rule should match. This parameter is required when setting either the `source_port` or `destination_port` parameters.

#####`raw`

The value of this string will be inserted into the rule without modification just prior to the '-j TARGET' component of a rule.

#####`raw_after`

The value of this string will be inserted into the rule without modification just after the '-j TARGET' component of a rule.

#####`reject_with`

When using the built-in 'REJECT' target, this sets the '--reject-with' directive.

Due to some differences with the ICMP return codes between IPv4 and IPv6, rules using IPv4 or IPv6 specific values will be silently converted to a similar valid value for the appropriate protocol.

#####`source`

The source address(s) to match packets. Multiple addresses may be specified by supply an array or comma separated list of values.

#####`source_port`

The source port(s) to match packets. Multiple ports may be specified by supply an array or comma separated list of values.

#####`state`

Match packets with a particular state.

#####`strict_protocol_checking`

When set to true, protocols other than those baked into iptables/ip6tables must be specified by their IP protocol number.

When set to false, any protocol name can be specified that exists in /etc/protocols on the node the rule is applied on.

Default is true

**Warning: puppet does not check the existance of protocols in /etc/protocols**

#####`table`

The table this rule is placed in. This defaults to the 'filter' table.

#####`to_port`

When using the built-in 'REDIRECT' target on the 'nat' chain, this sets the '--to-port' directive.

#####`version`

The IP version of this rule. This can be one of '4' for an IPv4 rule, '6' for an IPv6 rule or '46' for both. By default, this is set to '46'

##Examples

Create a trivial 'complex' rule that:

1. Creates a chain `ADMIN` in addition to the `INPUT` and `OUTPUT` chains
2. Place incoming packets from `$admin_network` onto the `ADMIN` chain for processing
3. Allow `$admin_network` to access `$admin_ports`
4. Reject `$admin_ports` from non-Admin systems

```puppet
    $admin_network = '10.0.0.0/24,2001:db8:1000::/64'
    $admin_ports = '22,636,5666'
    iptables::rule { 'allow admin ssh':
      comment          => 'Allow admin workstations to connect to admin ports',
      chain            => 'ADMIN',
      order            => '100',
      protocol         => 'tcp',
      destination_port => $admin_ports,
    }
    iptables::rule { 'SA network jumps to ADMIN chain':
      comment          => 'SA workstations should traverse the ADMIN chain',
      order            => '10',
      destination_port => $admin_ports,
      protocol         => 'tcp',
      action           => 'ADMIN',
      source           => $admin_network,
    }
    iptables::rule { 'Reject all other admin connections':
      comment          => 'Reject SSH from all other workstations',
      order            => '150',
      destination_port => $admin_ports,
      protocol         => 'tcp',
      action           => 'REJECT',
    }
```

Prevent hosts from sending outbound SMTP packets to unauthorized servers:

```puppet
    # place some outbound restrictions
    iptables::rule { 'allow-outbound-smtp-to-authorized-servers':
      comment          => 'only allow smtp to our internal mail servers',
      order            => '500',
      destination_port => '25',
      protocol         => 'tcp',
      destination      => '10.0.10.10,10.0.10.11,2001:db8:1001::10/126',
      action           => 'ACCEPT',
      chain            => 'OUTPUT',
    }
    iptables::rule { 'restrict-outbound-smtp-to-unauthorized-servers':
      comment          => 'do not allow any further smtp outbound',
      order            => '999',
      destination_port => '25',
      protocol         => 'tcp',
      action           => 'REJECT',
      chain            => 'OUTPUT,
    }
```

##Reference

This section provides insight into the internal operations of the module. This
information is only for reference, and is not consider to be a stable interface
for using the module. As a result, this information may change periodically,
even between minor version changes.

###Classes

####Class: `iptables::ipv4`

This class handles the setup of the iptables concat target, and the initial
fragments required for iptables to operate, such as the commit line.

This class also contains variables used by classes and defines under the
iptables::ipv4 namespace, such as information about builtin chains for iptables.

####Class: `iptables::ipv6`

This class handles the setup of the ip6tables concat target, and the initial
fragments required for ip6tables to operate, such as the commit line.

This class also contains variables used by classes and defines under the
iptables::ipv6 namespace, such as information about builtin chains for ip6tables.

###Defined Types

####Define: `iptables::ipv4::chain`

Handles setting up our iptables chain entry in our iptables file. Called by
`iptables::ipv4::rule` exclusively.

**Parameters for `iptables::ipv4::chain`:**

#####`comment`

**Deprecated**: This parameter will be removed in a future version

a string comment to place above the chain entry in the iptables file.

#####`policy`:

the default policy for the chain. if not specified, the default value is 'ACCEPT'

####Define: `iptables::ipv4::rule`

Defined type that handles building our ipv4 rule lines, and ensuring the proper
chains and tables are created as necessary.

**Parameters for `iptables::ipv4::rule`:**

#####`options`

a hash of options that is passed through from iptables::rule that mostly mirrors
the parameters available to the iptables::rule define. parameters that do not
make sense for ipv4 rules are excluded.

#####`defaults`

**Deprecated**: This parameter will be removed in a future version

a hash of options that is merged with the passed in parameters. we dont use this
since we ended up making this part of the private api, so we can get rid of it.

####Define: `iptables::ipv4::table`

Handles setting up our iptables table entry in our iptables file. Called by
`iptables::ipv4::chain` and `iptables::ipv4` exclusively.

####Define: `iptables::ipv6::chain`

Handles setting up our ip6tables chain entry in our ip6tables file. Called by
`iptables::ipv6::rule` exclusively.

**Parameters for `iptables::ipv6::chain`:**

#####`comment`

**Deprecated**: This parameter will be removed in a future version

a string comment to place above the chain entry in the ip6tables file.

#####`policy`:

the default policy for the chain. if not specified, the default value is 'ACCEPT'

####Define: `iptables::ipv6::rule`

Defined type that handles building our ipv6 rule lines, and ensuring the proper
chains and tables are created as necessary.

**Parameters for `iptables::ipv6::rule`:**

#####`options`

a hash of options that is passed through from iptables::rule that mostly mirrors
the parameters available to the iptables::rule define. parameters that do not
make sense for ipv6 rules are excluded.

#####`defaults`

**Deprecated**: This parameter will be removed in a future version

a hash of options that is merged with the passed in parameters. we dont use this
since we ended up making this part of the private api, so we can get rid of it.

####Define: `iptables::ipv6::table`

Handles setting up our ip6tables table entry in our ip6tables file. Called by
`iptables::ipv6::chain` and `iptables::ipv6` exclusively.
