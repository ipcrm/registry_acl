# frozen_string_literal: true

require 'beaker-rspec'
require 'beaker/puppet_install_helper'
require 'beaker/module_install_helper'

# This works around beaker-puppet 1.19.1 using
# an incorrect name for the puppet-agent MSI.
module Beaker::DSL::InstallUtils::FOSSUtils
  def compute_puppet_msi_name(host, opts)
    version = opts[:version]
    install32 = host['install_32'] || opts['install_32']

    # If there's no version declared, install the latest in the 3.x series
    if !version
      host['dist'] = if !host.is_x86_64? || install32
                       'puppet-agent-x86-latest'
                     else
                       'puppet-agent-x64-latest'
                     end

    elsif !host.is_x86_64? || install32
      host['dist'] = "puppet-agent-#{version}-x86"

    elsif host.is_x86_64?
      host['dist'] = "puppet-agent-#{version}-x64"

    else
      raise "I don't understand how to install Puppet version: #{version}"
    end
  end
end

unless ENV['BEAKER_provision'] == 'no'
  hosts.each do |host|
    # Install Puppet
    install_puppet_on(host)
  end
end

install_module_on(hosts)
install_module_dependencies_on(hosts)
