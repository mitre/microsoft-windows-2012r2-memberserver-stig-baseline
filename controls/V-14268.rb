control 'V-14268' do
  title 'Zone information must be preserved when saving attachments.'
  desc  "Preserving zone of origin (internet, intranet, local, restricted)
  information on file attachments allows Windows to determine risk."
  impact 0.5
  tag "gtitle": 'Attachment Mgr - Preserve Zone Info'
  tag "gid": 'V-14268'
  tag "rid": 'SV-53002r1_rule'
  tag "stig_id": 'WN12-UC-000009'
  tag "fix_id": 'F-45929r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24747-8']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

  Value Name: SaveZoneInformation

  Type: REG_DWORD
  Value: 2"
  tag "fix": "Configure the policy value for User Configuration ->
  Administrative Templates -> Windows Components -> Attachment Manager -> \"Do
  not preserve zone information in file attachments\" to \"Disabled\"."
  describe registry_key('HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments') do
    it { should have_property 'SaveZoneInformation' }
    its('SaveZoneInformation') { should cmp == 2 }
  end
end
