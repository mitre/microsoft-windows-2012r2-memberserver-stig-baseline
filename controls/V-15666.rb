# frozen_string_literal: true

control 'V-15666' do
  title 'Windows Peer-to-Peer networking services must be turned off.'
  desc  "Peer-to-Peer applications can allow unauthorized access to a system
  and exposure of sensitive data.  This setting will turn off the Microsoft
  Peer-to-Peer Networking Service."
  impact 0.5
  tag "gtitle": 'Windows Peer to Peer Networking '
  tag "gid": 'V-15666'
  tag "rid": 'SV-53012r1_rule'
  tag "stig_id": 'WN12-CC-000003'
  tag "fix_id": 'F-45939r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24398-0']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Peernet\\

  Value Name: Disabled

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking
  Services -> \"Turn off Microsoft Peer-to-Peer Networking Services\" to
  \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Peernet') do
    it { should have_property 'Disabled' }
    its('Disabled') { should cmp == 1 }
  end
end
