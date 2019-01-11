control "V-26470" do
  title "The Access this computer from the network user right must only be
  assigned to the Administrators and Authenticated Users groups on member
  servers."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Access this computer from the network\" user right may
  access resources on the system, and must be limited to those that require it.
  "
  impact 0.5
  tag "gtitle": "Access this computer from the network"
  tag "gid": "V-26470"
  tag "rid": "SV-51499r4_rule"
  tag "stig_id": "WN12-UR-000002-MS"
  tag "fix_id": "F-88203r1_fix"
  tag "cci": ['CCI-000213']
  tag "cci": ['CCE-24938-3']
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

  If any accounts or groups other than the following are granted the \"Access
  this computer from the network\" user right, this is a finding:

  Administrators
  Authenticated Users

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (V-36661) and required changes frequency (V-36662)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Access this computer from the network\" to only include the following
  accounts or groups:

  Administrators
  Authenticated Users"
  describe.one do
    describe security_policy do
      its('SeNetworkLogonRight') { should eq ['S-1-5-11', 'S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeNetworkLogonRight') { should eq ['S-1-5-11'] }
    end
    describe security_policy do
      its('SeNetworkLogonRight') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeNetworkLogonRight') { should eq [] }
    end
  end
end

