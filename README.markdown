# iptables Module #

This module provides mechanisms to manage your iptables firewall file

# Functions #

split_ip_by_version
-------------------

- ips : array of ips, any combination of ipv4 and ipv6

Returns a hash with 3 keys - 'ipv4' and 'ipv6' with each contain an array of
addresses/networks from their respective family.  'other' contains all entries
that weren't valid addresses.

# Examples #

<pre><code>
  iptables::rule { 'allow-global-ssh':
    comment          => 'global allow for SSH',
    priority         => '10',
    destination_port => '22',
    action           => 'ACCEPT',
  }

  iptables::rule { 'allow-puppet-local':
    comment          => 'allow access to puppet master',
    priority         => '500',
    source           => '10.0.0.0/8,192.168.0.0/24',
    destination_port => '6140',
    action           => 'ACCEPT',
  }
  
  # place some outbound restrictions
  iptables::rule { 'allow-outbound-smtp':
    comment          => 'only allow smtp to our internal mail servers',
    priority         => '500',
    destination_port => '25',
    destination      => '10.0.10.10,10.0.10.11',
    action           => 'ACCEPT',
  }

  iptables::rule { 'restrict-outbound-smtp':
    comment          => 'do not allow any further smtp outbound',
    priority         => '999',
    destination_port => '25',
    action           => 'DROP',
  }
</code></pre>
 

License
-------

None

Contact
-------

Aaron Russo <arusso@berkeley.edu>

Support
-------

Please log tickets and issues at the
[Projects site](https://github.com/arusso23/puppet-iptables/issues/)
