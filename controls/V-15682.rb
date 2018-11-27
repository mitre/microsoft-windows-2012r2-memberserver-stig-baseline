control 'V-15682' do
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc  "Attachments from RSS feeds may not be secure.  This setting will
  prevent attachments from being downloaded from RSS feeds."
  impact 0.5
  tag "gtitle": 'RSS Attachment Downloads'
  tag "gid": 'V-15682'
  tag "rid": 'SV-53040r1_rule'
  tag "stig_id": 'WN12-CC-000105'
  tag "fix_id": 'F-45966r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-25340-1']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

  Value Name: DisableEnclosureDownload

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> RSS Feeds -> \"Prevent
  downloading of enclosures\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds') do
    it { should have_property 'DisableEnclosureDownload' }
    its('DisableEnclosureDownload') { should cmp == 1 }
  end
end
