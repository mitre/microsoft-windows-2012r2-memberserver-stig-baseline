# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-14261' do
  title "Windows must be prevented from using Windows Update to search for
  drivers."
  desc "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents Windows from searching Windows Update for device
  drivers when no local drivers for a device are present.
  "
  impact 0.5
  tag "gtitle": 'Windows Update Device Drive Searching'
  tag "gid": 'V-14261'
  tag "rid": 'SV-53000r1_rule'
  tag "stig_id": 'WN12-CC-000047'
  tag "fix_id": 'F-45927r1_fix'
  tag "cci": ['CCI-001812']
  tag "cce": ['CCE-24071-3']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

  Value Name: DontSearchWindowsUpdate

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
Administrative Templates -> System -> Internet Communication Management ->
Internet Communication settings -> \"Turn off Windows Update device driver
searching\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DriverSearching') do
    it { should have_property 'DontSearchWindowsUpdate' }
    its('DontSearchWindowsUpdate') { should cmp == 1 }
  end
end
