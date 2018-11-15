control "V-14228" do
  title "Auditing the Access of Global System Objects must be turned off."
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.
      This setting prevents the system from setting up a default system access
  control list for certain system objects, which could create a very large number
  of security events, filling the security log in Windows and making it difficult
  to identify actual issues.
  "
  impact 0.5
  tag "gtitle": "Audit Access of Global System Objects"
  tag "gid": "V-14228"
  tag "rid": "SV-53129r1_rule"
  tag "stig_id": "WN12-SO-000007"
  tag "fix_id": "F-46055r1_fix"
  tag "cci": ["CCI-001095"]
  tag "cce": ["CCE-24075-4"]
  tag "nist": ["SC-5 (2)", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: AuditBaseObjects

  Value Type: REG_DWORD
  Value: 0"
    tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"Audit:
  Audit the access of global system objects\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\Currentcontrolset\\Control\\Lsa") do
    it { should have_property "AuditBaseObjects" }
    its("AuditBaseObjects") { should cmp == 0 }
  end
end

