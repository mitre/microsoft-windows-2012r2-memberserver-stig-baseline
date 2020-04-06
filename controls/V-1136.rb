control 'V-1136' do
  title 'Users must be forcibly disconnected when their logon hours expire.'
  desc  "Users must not be permitted to remain logged on to the network after
  they have exceeded their permitted logon hours.  In many cases, this indicates
  that a user forgot to log off before leaving for the day.  However, it may also
  indicate that a user is attempting unauthorized access at a time when the
  system may be less closely monitored.  Forcibly disconnecting users when logon
  hours expire protects critical and sensitive network data from exposure to
  unauthorized personnel with physical access to the computer."
  impact 0.3
  tag "gtitle": 'Forcibly Disconnect when Logon Hours Expire'
  tag "gid": 'V-1136'
  tag "rid": 'SV-52860r1_rule'
  tag "stig_id": 'WN12-SO-000034'
  tag "fix_id": 'F-45786r1_fix'
  tag "cci": ['CCI-001133']
  tag "cce": ['CCE-24148-9']
  tag "nist": ['SC-10', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

  Value Name: EnableForcedLogoff

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Microsoft network server: Disconnect clients when logon hours expire\" to
  \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should have_property 'EnableForcedLogOff' }
    its('EnableForcedLogOff') { should cmp == 1 }
  end
end
