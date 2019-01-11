control "V-15998" do
  title "Users must be prevented from mapping local LPT ports and redirecting
  data from the Remote Desktop Session Host to local LPT ports.  (Remote Desktop
  Services Role)."
  desc  "Preventing the redirection of Remote Desktop session data to a client
  computer's LPT ports helps reduce possible exposure of sensitive data."
  impact 0.5
  tag "gtitle": "TS/RDS – LPT Port Redirection"
  tag "gid": "V-15998"
  tag "rid": "SV-52226r2_rule"
  tag "stig_id": "WN12-CC-000133"
  tag "fix_id": "F-45244r2_fix"
  tag "cci": ['CCI-002314']
  tag "cce": ['CCE-24381-6']
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

  Value Name: fDisableLPT

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Device and Resource Redirection -> \"Do not
  allow LPT port redirection\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableLPT' }
    its('fDisableLPT') { should cmp == 1 }
  end
end

