# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-36678' do
  title "Device driver updates must only search managed servers, not Windows
  Update."
  desc "Uncontrolled system updates can introduce issues to a system.
  Obtaining update components from an outside source may also potentially provide
  sensitive information outside of the enterprise.  Device driver updates must be
  obtained from an internal source."
  impact 0.3
  tag "gtitle": 'WINCC-000025'
  tag "gid": 'V-36678'
  tag "rid": 'SV-51607r1_rule'
  tag "stig_id": 'WN12-CC-000025'
  tag "fix_id": 'F-44728r1_fix'
  tag "cci": ['CCI-001812']
  tag "cce": ['CCE-25002-7']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

  Value Name: DriverServerSelection

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Device Installation -> \"Specify the
  search server for device driver updates\" to \"Enabled\" with \"Search Managed
  Server\" selected."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DriverSearching') do
    it { should have_property 'DriverServerSelection' }
    its('DriverServerSelection') { should cmp == 1 }
  end
end
