# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-21971' do
  title "The Application Compatibility Program Inventory must be prevented from
  collecting data and sending the information to Microsoft."
  desc "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting will prevent the Program Inventory from collecting data about
  a system and sending the information to Microsoft.
  "
  impact 0.3
  tag "gtitle": 'Application Compatibility Program Inventory'
  tag "gid": 'V-21971'
  tag "rid": 'SV-53127r1_rule'
  tag "stig_id": 'WN12-CC-000071'
  tag "fix_id": 'F-46053r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-25331-0']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\AppCompat\\

  Value Name: DisableInventory

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Application Compatibility ->
  \"Turn off Inventory Collector\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\AppCompat') do
    it { should have_property 'DisableInventory' }
    its('DisableInventory') { should cmp == 1 }
  end
end
