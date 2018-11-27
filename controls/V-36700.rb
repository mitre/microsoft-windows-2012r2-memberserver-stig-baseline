control 'V-36700' do
  title 'The password reveal button must not be displayed.'
  desc  "Visible passwords may be seen by nearby persons, compromising them.
  The password reveal button can be used to display an entered password and must
  not be allowed."
  impact 0.5
  tag "gtitle": 'WINCC-000076'
  tag "gid": 'V-36700'
  tag "rid": 'SV-51740r1_rule'
  tag "stig_id": 'WN12-CC-000076'
  tag "fix_id": 'F-44815r1_fix'
  tag "cci": ['CCI-000206']
  tag "cce": ['CCE-23228-0']
  tag "nist": ['IA-6', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'IAIA-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\CredUI\\

  Value Name: DisablePasswordReveal

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Credential User Interface ->
  \"Do not display the password reveal button\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI') do
    it { should have_property 'DisablePasswordReveal' }
    its('DisablePasswordReveal') { should cmp == 1 }
  end
end
