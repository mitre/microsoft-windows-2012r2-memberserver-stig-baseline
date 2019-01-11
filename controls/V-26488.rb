control "V-26488" do
  title "The Force shutdown from a remote system user right must only be
  assigned to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

      Accounts with the \"Force shutdown from a remote system\" user right can
  remotely shut down a system, which could result in a DoS.
  "
  impact 0.5
  tag "gtitle": "Force shutdown from a remote system"
  tag "gid": "V-26488"
  tag "rid": "SV-53050r2_rule"
  tag "stig_id": "WN12-UR-000023"
  tag "fix_id": "F-45976r2_fix"
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-24734-6']
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

  If any accounts or groups other than the following are granted the \"Force
  shutdown from a remote system\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Force shutdown from a remote system\" to only include the following accounts
  or groups:

  Administrators"
  describe.one do
    describe security_policy do
      its('SeRemoteShutdownPrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeRemoteShutdownPrivilege') { should eq [] }
    end
  end
end

