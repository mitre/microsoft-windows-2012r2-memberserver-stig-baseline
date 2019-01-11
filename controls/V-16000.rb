control "V-16000" do
  title "The system must be configured to ensure smart card devices can be
  redirected to the Remote Desktop session.  (Remote Desktop Services Role)."
  desc  "Enabling the redirection of smart card devices allows their use within
  Remote Desktop sessions."
  impact 0.5
  tag "gtitle": "TS/RDS – Smart Card Device Redirection"
  tag "gid": "V-16000"
  tag "rid": "SV-52230r2_rule"
  tag "stig_id": "WN12-CC-000134"
  tag "fix_id": "F-45247r2_fix"
  tag "cci": ['CCI-002314']
  tag "cce": ['CCE-24260-2']
  tag "nist": ['AC-17 (1)', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": "ECSC-1"
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: fEnableSmartCard

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Device and Resource Redirection -> \"Do not
  allow smart card device redirection\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fEnableSmartCard' }
    its('fEnableSmartCard') { should cmp == 1 }
  end
end

