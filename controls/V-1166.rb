control 'V-1166' do
  title "The Windows SMB client must be enabled to perform SMB packet signing
  when possible."
  desc "The server message block (SMB) protocol provides the basis for many
  network operations.   If this policy is enabled, the SMB client will request
  packet signing when communicating with an SMB server that is enabled or
  required to perform SMB packet signing."
  impact 0.5
  tag "gtitle": 'SMB Client Packet Signing (if server agrees)'
  tag "gid": 'V-1166'
  tag "rid": 'SV-52874r2_rule'
  tag "stig_id": 'WN12-SO-000029'
  tag "fix_id": 'F-45800r1_fix'
  tag "cci": ['CCI-002418', 'CCI-002421']
  tag "cce": ['CCE-24740-3']
  tag "nist": ['SC-8', 'SC-8 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

  Value Name: EnableSecuritySignature

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Microsoft network client: Digitally sign communications (if server agrees)\"
  to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should have_property 'EnableSecuritySignature' }
    its('EnableSecuritySignature') { should cmp == 1 }
  end
end
