# frozen_string_literal: true

control 'V-14269' do
  title "Mechanisms for removing zone information from file attachments must be
  hidden."
  desc "Preserving zone of origin (internet, intranet, local, restricted)
  information on file attachments allows Windows to determine risk.  This setting
  prevents users from manually removing zone information from saved file
  attachments."
  impact 0.5
  tag "gtitle": 'Attachment Mgr - Hide Mech to Remove Zone Info'
  tag "gid": 'V-14269'
  tag "rid": 'SV-53004r1_rule'
  tag "stig_id": 'WN12-UC-000010'
  tag "fix_id": 'F-45931r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24611-6']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

  Value Name: HideZoneInfoOnProperties

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for User Configuration ->
Administrative Templates -> Windows Components -> Attachment Manager -> \"Hide
mechanisms to remove zone information\" to \"Enabled\"."

  describe registry_key('HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments') do
    it { should have_property 'HideZoneInfoOnProperties' }
    its('HideZoneInfoOnProperties') { should cmp == 1 }
  end
end
