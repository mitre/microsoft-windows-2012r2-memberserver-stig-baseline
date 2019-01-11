control "V-26472" do
  title "The Allow log on locally user right must only be assigned to the
  Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Allow log on locally\" user right can log on
  interactively to a system.
  "
  impact 0.5
  tag "gtitle": "Allow log on locally"
  tag "gid": "V-26472"
  tag "rid": "SV-52110r3_rule"
  tag "stig_id": "WN12-UR-000005"
  tag "fix_id": "F-45135r2_fix"
  tag "cci": ['CCI-000213']
  tag "cci": ['CCE-25228-8']
  tag "nist": ['AC-3', 'Rev_4']
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

  If any accounts or groups other than the following are granted the \"Allow log
  on locally\" user right, this is a finding:

  Administrators

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN12-00-000010) and required frequency of changes
  (WN12-00-000011)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Allow log on locally\" to only include the following accounts or groups:

  Administrators"
  describe.one do
    describe security_policy do
      its('SeInteractiveLogonRight') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeInteractiveLogonRight') { should eq [] }
    end
  end
end

