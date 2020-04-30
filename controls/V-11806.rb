# frozen_string_literal: true

control 'V-11806' do
  title "The system must be configured to prevent the display of the last
  username on the logon screen."
  desc "Displaying the username of the last logged on user provides half of
  the userid/password equation that an unauthorized person would need to gain
  access.  The username of the last user to log on to a system must not be
  displayed."
  impact 0.3
  tag "gtitle": 'Display of Last User Name'
  tag "gid": 'V-11806'
  tag "rid": 'SV-52941r1_rule'
  tag "stig_id": 'WN12-SO-000018'
  tag "fix_id": 'F-45867r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24748-6']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: DontDisplayLastUserName

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Interactive logon: Do not display last user name\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'DontDisplayLastUserName' }
    its('DontDisplayLastUserName') { should cmp == 1 }
  end
end
