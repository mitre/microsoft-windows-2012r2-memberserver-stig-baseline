control "V-3470" do
  title "The system must be configured to prevent unsolicited remote assistance
  offers."
  desc  "Remote assistance allows another user to view or take control of the
  local session of a user.  Unsolicited remote assistance is help that is offered
  by the remote user.  This may allow unauthorized parties access to the
  resources on the computer."
  impact 0.5
  tag "gtitle": "Remote Assistance - Offer Remote Assistance"
  tag "gid": "V-3470"
  tag "rid": "SV-52917r1_rule"
  tag "stig_id": "WN12-CC-000058"
  tag "fix_id": "F-45843r1_fix"
  tag "cci": ['CCI-001090']
  tag "cce": ['CCE-23282-7']
  tag "nist": ['SC-4', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: fAllowUnsolicited

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Remote Assistance -> \"Configure Offer
  Remote Assistance\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fAllowUnsolicited' }
    its('fAllowUnsolicited') { should cmp == 0 }
  end
end

