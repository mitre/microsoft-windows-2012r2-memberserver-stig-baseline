control "V-26542" do
  title "The system must be configured to audit Logon/Logoff - Logon failures."
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

      Logon records user logons.  If this is an interactive logon, it is recorded
  on the local system.  If it is to a network share, it is recorded on the system
  accessed.
  "
  impact 0.5
  tag "gtitle": "Audit - Logon - Failure"
  tag "gid": "V-26542"
  tag "rid": "SV-52993r2_rule"
  tag "stig_id": "WN12-AU-000048"
  tag "fix_id": "F-45920r1_fix"
  tag "cci": ["CCI-000067", "CCI-000172"]
  tag "nist": ['AC-17 (1)', 'Rev_4']
  tag "nist": ['AU-12 c', 'Rev_4']
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
  tag "check": "Security Option \"Audit: Force audit policy subcategory
  settings (Windows Vista or later) to override audit policy category settings\"
  must be set to \"Enabled\" (V-14230) for the detailed auditing subcategories to
  be effective.

  Use the AuditPol tool to review the current Audit Policy configuration:
  -Open a Command Prompt with elevated privileges (\"Run as Administrator\").
  -Enter \"AuditPol /get /category:*\".

  Compare the AuditPol settings with the following.  If the system does not audit
  the following, this is a finding.

  Logon/Logoff -> Logon - Failure"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Advanced Audit Policy Configuration -> System
  Audit Policies -> Logon/Logoff -> \"Audit Logon\" with \"Failure\" selected."
  describe.one do
    describe audit_policy do
      its('Logon') { should eq 'Failure' }
    end
    describe audit_policy do
      its('Logon') { should eq 'Success and Failure' }
    end
  end
end

