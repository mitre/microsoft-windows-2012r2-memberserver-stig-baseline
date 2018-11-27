control 'V-1162' do
  title 'The Windows SMB server must perform SMB packet signing when possible.'
  desc  "The server message block (SMB) protocol provides the basis for many
  network operations.   Digitally signed SMB packets aid in preventing
  man-in-the-middle attacks.  If this policy is enabled, the SMB server will
  negotiate SMB packet signing as requested by the client."
  impact 0.5
  tag "gtitle": 'SMB Server Packet Signing (if client agrees)'
  tag "gid": 'V-1162'
  tag "rid": 'SV-52870r2_rule'
  tag "stig_id": 'WN12-SO-000033'
  tag "fix_id": 'F-45796r1_fix'
  tag "cci": ['CCI-002418', 'CCI-002421']
  tag "cce": ['CCE-24354-3']
  tag "nist": ['SC-8', 'Rev_4']
  tag "nist": ['SC-8 (1)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

  Value Name: EnableSecuritySignature

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Microsoft network server: Digitally sign communications (if client agrees)\"
  to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters') do
    it { should have_property 'EnableSecuritySignature' }
    its('EnableSecuritySignature') { should cmp == 1 }
  end
end
