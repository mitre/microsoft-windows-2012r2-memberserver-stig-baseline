control 'V-36687' do
  title 'App notifications on the lock screen must be turned off.'
  desc  "App notifications that are displayed on the lock screen could display
  sensitive information to unauthorized personnel.  Turning off this feature will
  limit access to the information to a logged on user."
  impact 0.5
  tag "gtitle": 'WINCC-000052'
  tag "gid": 'V-36687'
  tag "rid": 'SV-51612r1_rule'
  tag "stig_id": 'WN12-CC-000052'
  tag "fix_id": 'F-44733r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24092-9']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\System\\

  Value Name: DisableLockScreenAppNotifications

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Logon -> \"Turn off app notifications on
  the lock screen\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'DisableLockScreenAppNotifications' }
    its('DisableLockScreenAppNotifications') { should cmp == 1 }
  end
end
