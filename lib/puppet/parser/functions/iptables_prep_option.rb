module Puppet::Parser::Functions
  newfunction(:iptables_prep_option, :type => :rvalue, :doc => <<-EOS
Used internally by the iptables module, handles the determination of the initial
value of our option by taking the provided name, values hash, defaults hash and
default value, and returning the appropriate value.

Example:

  vals = { 'opt2' => '1', 'opt3' => '2' }
  defs = { 'opt' => '0', 'opt3' => '4' }
  default = '-1'

  # returns '0'
  opt_val = iptables_prep_option( 'opt', vals, defs, default )

  # returns '1'
  opt2_val = iptables_prep_option( 'opt2', vals, defs, default )

  # returns '2'
  opt3_val = iptables_prep_option( 'opt3', vals, defs, default )

  # returns -1
  opt4_val = iptables_prep_option( 'opt4', vals, defs, default )
  EOS
) do |args|
    vals = { }
    defs = { }
    name = args[0]
    vals = args[1] unless args[1] == nil
    defs = args[2] unless args[2] == nil
    default = ''
    default = args[3] unless ! args[3]

    # just run through the values
    ret = default
    ret = defs[name] unless ! defs[name]
    ret = vals[name] unless ! vals[name]

    return ret
  end
end
