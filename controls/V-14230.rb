control "V-14230" do
  title "Audit policy using subcategories must be enabled."
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.
      This setting allows administrators to enable more precise auditing
  capabilities.
  "
  impact 0.5
  tag "gtitle": "Audit Policy Subcategory Setting"
  tag "gid": "V-14230"
  tag "rid": "SV-52944r1_rule"
  tag "stig_id": "WN12-SO-000009"
  tag "fix_id": "F-45870r1_fix"
  tag "cci": ["CCE-24252-9", "CCI-000169"]
  tag "nist": ["CCE-24252-9", "CCI-000169"]
  tag "nist": ["AU-12 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: SCENoApplyLegacyAuditPolicy

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"Audit:
  Force audit policy subcategory settings (Windows Vista or later) to override
  audit policy category settings\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\Currentcontrolset\\Control\\Lsa") do
    it { should have_property "scenoapplylegacyauditpolicy" }
    its("scenoapplylegacyauditpolicy") { should cmp == 1 }
  end
end

