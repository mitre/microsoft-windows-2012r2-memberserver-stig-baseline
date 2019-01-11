control "V-26481" do
  title "The Create permanent shared objects user right must not be assigned to
  any groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Create permanent shared objects\" user right could
  expose sensitive data by creating shared objects.
  "
  impact 0.5
  tag "gtitle": "Create permanent shared objects"
  tag "gid": "V-26481"
  tag "rid": "SV-53059r2_rule"
  tag "stig_id": "WN12-UR-000014"
  tag "fix_id": "F-45985r2_fix"
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-23723-0']
  tag "nist": ['AC-6 (10)', 'Rev_4']
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
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups are granted the \"Create permanent shared objects\"
  user right, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Create permanent shared objects\" to be defined but containing no entries
  (blank)."
  describe security_policy do
    its('SeCreatePermanentPrivilege') { should eq [] }
  end
end

