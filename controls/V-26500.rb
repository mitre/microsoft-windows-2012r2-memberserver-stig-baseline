control "V-26500" do
  title "The Profile single process user right must only be assigned to the
  Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

      Accounts with the \"Profile single process\" user right can monitor
  nonsystem processes performance.  An attacker could potentially use this to
  identify processes to attack.
  "
  impact 0.5
  tag "gtitle": "Profile single process"
  tag "gid": "V-26500"
  tag "rid": "SV-53022r2_rule"
  tag "stig_id": "WN12-UR-000036"
  tag "fix_id": "F-45948r2_fix"
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-23844-4']
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

  If any accounts or groups other than the following are granted the \"Profile
  single process\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Profile single process\" to only include the following accounts or groups:

  Administrators"
  describe.one do
    describe security_policy do
      its('SeProfileSingleProcessPrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeProfileSingleProcessPrivilege') { should eq [] }
    end
  end
  
end

