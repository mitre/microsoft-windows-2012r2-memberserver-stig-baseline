control 'V-1075' do
  title 'The shutdown option must not be available from the logon dialog box.'
  desc  "Displaying the shutdown button may allow individuals to shut down a
  system anonymously.  Only authenticated users should be allowed to shut down
  the system.  Preventing display of this button in the logon dialog box ensures
  that individuals who shut down the system are authorized and tracked in the
  system's Security event log."
  impact 0.3
  tag "gtitle": 'Display Shutdown Button'
  tag "gid": 'V-1075'
  tag "rid": 'SV-52840r1_rule'
  tag "stig_id": 'WN12-SO-000073'
  tag "fix_id": 'F-45766r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-25100-9']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: ShutdownWithoutLogon

  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Shutdown: Allow system to be shutdown without having to log on\" to
  \"Disabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'ShutdownWithoutLogon' }
    its('ShutdownWithoutLogon') { should cmp == 0 }
  end
end
