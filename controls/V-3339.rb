# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-3339' do
  title "Unauthorized remotely accessible registry paths must not be
  configured."
  desc "The registry is integral to the function, security, and stability of
  the Windows system.  Some processes may require remote access to the registry.
  This setting controls which registry paths are accessible from a remote
  computer.  These registry paths must be limited, as they could give
  unauthorized individuals access to the registry."
  impact 0.7
  tag "gtitle": 'Remotely Accessible Registry Paths'
  tag "gid": 'V-3339'
  tag "rid": 'SV-52883r2_rule'
  tag "stig_id": 'WN12-SO-000056'
  tag "fix_id": 'F-45809r2_fix'
  tag "cci": %w[CCE-23899-8 CCI-001090]
  tag "cce": ['CCE-23899-8']
  tag "nist": %w[SC-4 Rev_4]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths\\

  Value Name: Machine

  Value Type: REG_MULTI_SZ
  Value: see below

  System\\CurrentControlSet\\Control\\ProductOptions
  System\\CurrentControlSet\\Control\\Server Applications
  Software\\Microsoft\\Windows NT\\CurrentVersion

  Legitimate applications may add entries to this registry value.  If an
  application requires these entries to function properly and is documented with
  the ISSO, this would not be a finding. Documentation must contain supporting
  information from the vendor's instructions."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network access: Remotely accessible registry paths\" with the following
  entries:

  System\\CurrentControlSet\\Control\\ProductOptions
  System\\CurrentControlSet\\Control\\Server Applications
  Software\\Microsoft\\Windows NT\\CurrentVersion"

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths') do
    it { should have_property 'Machine' }
  end

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths') do
    its('Machine') { should include 'System\\CurrentControlSet\\Control\\ProductOptions' }
    its('Machine') { should include 'System\\CurrentControlSet\\Control\\Server Applications' }
    its('Machine') { should include 'Software\\Microsoft\\Windows NT\\CurrentVersion' }
  end
end
