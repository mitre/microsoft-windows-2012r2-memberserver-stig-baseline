control "V-26472" do
  title "Unauthorized accounts must not have the Allow log on locally user
  right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Allow log on locally\" user right can log on
  interactively to a system.
  "
  impact 0.5
  tag "gtitle": "Allow log on locally"
  tag "gid": "V-26472"
  tag "rid": "SV-52110r2_rule"
  tag "stig_id": "WN12-UR-000005"
  tag "fix_id": "F-45135r1_fix"
  tag "cci": ["CCE-25228-8", "CCI-000213"]
  tag "nist": ["CCE-25228-8", "CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": "If an application requires this user
  right, this can be downgraded to not a finding if the following conditions are
  met:
  Vendor documentation must support the requirement for having the user right.
  The requirement must be documented with the ISSO.
  The application account must meet requirements for application account
  passwords, such as length (V-36661) and required changes frequency (V-36662)."
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Allow log
  on locally\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Allow log on locally\" to only include the following accounts or groups:

  Administrators"
  describe security_policy do
    its("SeInteractiveLogonRight") { should eq ['S-1-5-32-544'] }
  end
end
 
