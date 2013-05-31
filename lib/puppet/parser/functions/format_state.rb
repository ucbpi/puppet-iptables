module Puppet::Parser::Functions
  newfunction(:format_state, :type => :rvalue,:doc => <<-EOS
  EOS
) do |args|
    Puppet::Parser::Functions.function('warning')

    states = ""
    states = args[0].dup unless args[0] == nil
    valid = [ 'NEW', 'REL', 'EST', 'INV' ]

    states = states.split(',') unless states.kind_of?(Array)

    # handle if we were not passed any states
    return { 'state' => '', 'raw' => ''} if states.size == 0

    # limit each state to the first 3 letters since we just need to provide
    # enough information for iptables such that the state is not ambigous
    states.map! { |s| s=s[0,3] }
    states.uniq!

    # remove invalid states
    to_delete = [ ]
    states.each { |s| to_delete.push(s) unless valid.include?(s) }

    if to_delete.size > 0 and states.size > 0
      function_warning(["skipping invalid states -- #{to_delete.join(',')}"])
      to_delete.each { |s| states.delete(s) }
    elsif to_delete.size > 0 and states.size == 0
      raise Puppet::ParseError, "no valid states were passed"
    end

    states.compact!

    state = ""
    state = "-m state --state #{states.join(',')}" if states.size > 0

    r_h = {
      'state' => state,
      'raw' => args[0],
    }
  end
end
