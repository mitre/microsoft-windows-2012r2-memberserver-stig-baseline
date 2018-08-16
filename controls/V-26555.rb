control "V-26555" do
  title "The system must be configured to audit System - Security System
  Extension successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

  Security System Extension records events related to extension code being
  loaded by the security subsystem.
  "
  impact 0.5
  tag "gtitle": "Audit - Security System Extension - Success"
  tag "gid": "V-26555"
  tag "rid": "SV-52974r1_rule"
  tag "stig_id": "WN12-AU-000109"
  tag "fix_id": "F-45900r1_fix"
  tag "cci": ["CCI-000172", "CCI-002234"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "nist": ["AC-6 (9)", "Rev_4"]
  tag "documentable": false
  tag "check": "Security Option \"Audit: Force audit policy subcategory
  settings (Windows Vista or later) to override audit policy category settings\"
  must be set to \"Enabled\" (V-14230) for the detailed auditing subcategories to
  be effective.

  Use the AuditPol tool to review the current Audit Policy configuration:
  -Open a Command Prompt with elevated privileges (\"Run as Administrator\").
  -Enter \"AuditPol /get /category:*\".

  Compare the AuditPol settings with the following.  If the system does not audit
  the following, this is a finding.

  System -> Security System Extension - Success"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Advanced Audit Policy Configuration -> System
  Audit Policies -> System -> \"Audit Security System Extension\" with
  \"Success\" selected."
  describe audit_policy do
    its("Security System Extension") { should eq "Success" }
  end
end

