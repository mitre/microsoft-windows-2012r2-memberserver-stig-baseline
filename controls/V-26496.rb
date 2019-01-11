control "V-26496" do
  title "The Manage auditing and security log user right must only be assigned
  to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

      Accounts with the \"Manage auditing and security log\" user right can
  manage the security log and change auditing configurations.  This could be used
  to clear evidence of tampering.
  "
  impact 0.5
  tag "gtitle": "Manage auditing and security log"
  tag "gid": "V-26496"
  tag "rid": "SV-53039r4_rule"
  tag "stig_id": "WN12-UR-000032"
  tag "fix_id": "F-45965r2_fix"
  tag "cci": ['CCI-000162', 'CCI-000163', 'CCI-000164',
              'CCI-000171', 'CCI-001914']
  tag "cce": ['CCE-23456-7']
  tag "nist": ['AU-9', 'Rev_4']
  tag "nist": ['AU-12 b', 'Rev_4']
  tag "nist": ['AU-12 (3)', 'Rev_4']
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

  If any accounts or groups other than the following are granted the \"Manage
  auditing and security log\" user right, this is a finding:

  Administrators

  If the organization has an Auditors group, the assignment of this group to the
  user right would not be a finding.

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN12-00-000010) and required frequency of changes
  (WN12-00-000011)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Manage auditing and security log\" to only include the following accounts or
  groups:

  Administrators"
  describe.one do
    describe security_policy do
      its('SeSecurityPrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeSecurityPrivilege') { should eq [] }
    end
  end
end

