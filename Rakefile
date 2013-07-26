require 'rake'

begin
    require 'rspec/core/rake_task'
    require 'puppet-lint/tasks/puppet-lint'
rescue LoadError
    require 'rubygems'
      retry
end

module_root = Dir.getwd
module_name = File.basename(module_root)
module_fixtures_dir = "spec/fixtures/modules/#{module_name}"
modules_fixtures_dir = "spec/fixtures/modules/"
manifests_dir = '../../../../manifests'

#
# Setup our fixtures directory to ensure we are ready for testing
task :setup do
  # setup our fixtures
  if !File.exist?("#{module_fixtures_dir}")
    FileUtils.mkdir("#{module_fixtures_dir}")
  end

  if !File.exist?("#{module_fixtures_dir}/manifests")
    Dir.chdir(module_fixtures_dir)
    File.symlink(manifests_dir,'manifests')
    Dir.chdir(module_root)
  end
end

#
# only teardown our symlink to this module
task :teardown do
  File.unlink("spec/fixtures/modules/#{module_name}/manifests")
end

task :teardown_all do
  Dir.foreach(modules_fixtures_dir) do |f|
    if ! f =~ /^\.\.?$/
      FileUtils.rm_rf(File.join(modules_fixtures_dir, f))
    end
  end
end

RSpec::Core::RakeTask.new(:spec) do |t|
  t.pattern = 'spec/*/*_spec.rb'
end

task :sub do
  %x[git submodule init]
  %x[git submodule update]
end

task :build do
  Rake::Task["teardown_all"].invoke
  %x[puppet module build ./]
  Rake::Task["setup"].invoke
  # we always leave the symlink out
  Rake::Task["teardown"].invoke
end

task :test => [:setup,:spec,:teardown]

task :default => [:test]
