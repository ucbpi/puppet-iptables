# iptables Firewall Module #

[![Build Status](https://travis-ci.org/arusso/puppet-iptables.png?branch=master)](https://travis-ci.org/arusso/puppet-iptables)

This is yet another iptables module for Puppet.  It supports both IPv4 and IPv6
and tries to maintain compatibility with iptables/ip6tables v1.3.5 and above.

# Why Another iptables Modules? #

Mostly because some of us don't like modifying the running rules directly, and 
instead would prefer to modify the on-disk rules.  This has the advantage of
allowing us to comment them inside of the rule file itself, making them easier 
to read in cases of debugging.  Unfortunately, some hosts will always be
snowflakes, so this is a big plus for some.

Second, we can expose a more iptables-specific interface in our objects, making
it easier to read what you're doing inside of your manifests files.

Lastly, I've tried very hard to do as much error-checking as possible, so that
we catch the errors before being deployed to the host.  If you come up with a
combination of parameters that puts an entry into the iptables file that causes
an error, please file an issue.

# Usage #

The foundation of this module is understanding every rule has an order, from
000-999, and that the rules will be placed in ascending order in the specified
chain.

Rules assume only three defaults -- the default table is `filter`,the default
chain is `INPUT` and the default action is `ACCEPT`.  So creating an empty rule
will always result in the rule `-A INPUT -j ACCEPT` being generated in the
`filter` table.

The module also takes into account when IPv6 address are supplied, and will
generate IPv6 rules accordingly.  If you specify options that are only valid
for IPv4, it will throw an error (hopefully a useful one -- if not, file an
issue!).  We'd rather throw an error and make you aware of an issue early on,
then to discover later that your rule only partially applied.

## Examples ##

The following rules will create a chain `ADMIN` in addition to the `INPUT` and
`OUTPUT` chains, and will place any incoming packets from `$admin_network` onto
the `ADMIN` chain for processing.  Admins should be allowed `$admin_ports` over
tcp protocol.

    $admin_network = '10.0.0.0/24,2001:db8:1000::/64'
    $admin_ports = '22,636,5666'
  
    iptables::rule { 'allow admin ssh':
      comment          => 'Allow admin workstations to connect to admin ports',
      order            => '100',
      protocol         => 'tcp',
      destination_port => $admin_ports,
      chain            => 'ADMIN',
    }
  
    iptables::rule { 'SA network jumps to ADMIN chain':
      comment          => 'SA workstations should traverse the ADMIN chain',
      order            => '10',
      destination_port => '22',
      protocol         => 'tcp',
      action           => 'ADMIN',
      source           => $admin_network,
    }
  
    iptables::rule { 'allow-puppet-local':
      comment          => 'Reject SSH from all other workstations',
      order            => '150',
      destination_port => '22',
      protocol         => 'tcp',
      action           => 'REJECT',
    }
   
    # place some outbound restrictions
    iptables::rule { 'allow-outbound-smtp':
      comment          => 'only allow smtp to our internal mail servers',
      order            => '500',
      destination_port => '25',
      protocol         => 'tcp',
      destination      => '10.0.10.10,10.0.10.11,2001:db8:1001::10/126',
      action           => 'ACCEPT',
      chain            => 'OUTPUT',
    }
  
    iptables::rule { 'restrict-outbound-smtp':
      comment          => 'do not allow any further smtp outbound',
      order            => '999',
      destination_port => '25',
      protocol         => 'tcp',
      action           => 'REJECT',
      chain            => 'OUTPUT,
    }

License
-------

None

Contact
-------

Aaron Russo <arusso@berkeley.edu>

Support
-------

Please log tickets and issues at the
[Projects site](https://github.com/arusso/puppet-iptables/issues/)
