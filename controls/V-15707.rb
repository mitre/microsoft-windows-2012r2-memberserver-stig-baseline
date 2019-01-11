control "V-15707" do
  title "Remote Assistance log files must be generated."
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  This setting will turn on
  session logging for Remote Assistance connections."
  impact 0.3
  tag "gtitle": "Remote Assistance – Session Logging"
  tag "gid": "V-15707"
  tag "rid": "SV-53133r1_rule"
  tag "stig_id": "WN12-CC-000062"
  tag "fix_id": "F-46059r1_fix"
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24603-3']
  tag "nist": ['CM-6 b', 'Rev_4']
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

  Value Name: LoggingEnabled

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Remote Assistance -> \"Turn on session
  logging\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'LoggingEnabled' }
    its('LoggingEnabled') { should cmp == 1 }
  end
end

