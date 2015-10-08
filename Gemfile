source 'https://rubygems.org'

if ENV.key?('PUPPET_VERSION')
  puppetversion = "#{ENV['PUPPET_VERSION']}"
 else
   puppetversion = "~> 2.7.0"
end

gem 'rake'
gem 'puppet-lint'
# we must pin rspec-puppet until we no longer support puppet < 4.x due to a
# monkey patch of Symbol#to_proc that breaks shit when rspec-puppet > 2.0.0
# begins using rspec3.
#
# moar info: https://github.com/rspec/rspec-core/issues/1864
gem "rspec-puppet", :git => 'https://github.com/rodjek/rspec-puppet.git', :tag => 'v2.0.0'
gem 'puppet', puppetversion
gem 'puppetlabs_spec_helper'
