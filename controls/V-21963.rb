# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-21963' do
  title "Windows Update must be prevented from searching for point and print
  drivers."
  desc "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting will prevent Windows from searching Windows Update for point
  and print drivers.  Only the local driver store and server driver cache will be
  searched.
  "
  impact 0.3
  tag "gtitle": 'Windows Update Point and Print Driver Search'
  tag "gid": 'V-21963'
  tag "rid": 'SV-53184r1_rule'
  tag "stig_id": 'WN12-CC-000016'
  tag "fix_id": 'F-46110r1_fix'
  tag "cci": ['CCI-001812']
  tag "cce": ['CCE-24139-8']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Printers\\

  Value Name: DoNotInstallCompatibleDriverFromWindowsUpdate

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
Administrative Templates -> Printers -> \"Extend Point and Print connection to
search Windows Update\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should have_property 'DoNotInstallCompatibleDriverFromWindowsUpdate' }
    its('DoNotInstallCompatibleDriverFromWindowsUpdate') { should cmp == 1 }
  end
end
