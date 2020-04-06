control 'V-14270' do
  title 'The system must notify antivirus when file attachments are opened.'
  desc  "Attaching malicious files is a known avenue of attack.  This setting
  configures the system to notify antivirus programs when a user opens a file
  attachment."
  impact 0.5
  tag "gtitle": 'Attachment Mgr - Scan with Antivirus'
  tag "gid": 'V-14270'
  tag "rid": 'SV-53006r1_rule'
  tag "stig_id": 'WN12-UC-000011'
  tag "fix_id": 'F-45933r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-25538-0']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

  Value Name: ScanWithAntiVirus

  Type: REG_DWORD
  Value: 3"
  tag "fix": "Configure the policy value for User Configuration ->
  Administrative Templates -> Windows Components -> Attachment Manager ->
  \"Notify antivirus programs when opening attachments\" to \"Enabled\"."
  
  describe registry_key('HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments') do
    it { should have_property 'ScanWithAntiVirus' }
    its('ScanWithAntiVirus') { should cmp == 3 }
  end
end
