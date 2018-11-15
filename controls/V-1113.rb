control "V-1113" do
  title "The built-in guest account must be disabled."
  desc  "A system faces an increased vulnerability threat if the built-in guest
  account is not disabled.  This account is a known account that exists on all
  Windows systems and cannot be deleted.  This account is initialized during the
  installation of the operating system with no password assigned."
  impact 0.5
  tag "gtitle": "Disable Guest Account"
  tag "gid": "V-1113"
  tag "rid": "SV-52855r1_rule"
  tag "stig_id": "WN12-SO-000003"
  tag "fix_id": "F-45781r1_fix"
  tag "cci": ["CCI-000804"]
  tag "cci": ["CCE-24387-3"]
  tag "nist": ["IA-8", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> Security Options.

  If the value for \"Accounts: Guest account status\" is not set to \"Disabled\",
  this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Accounts: Guest account status\" to \"Disabled\"."
  describe security_policy do
    its('EnableGuestAccount') { should cmp 0 }
  end
end

 