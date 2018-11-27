control 'V-1150' do
  title 'The built-in Windows password complexity policy must be enabled.'
  desc  "The use of complex passwords increases their strength against attack.
  The built-in Windows password complexity policy requires passwords to contain
  at least 3 of the 4 types of characters (numbers, upper- and lower-case
  letters, and special characters), as well as preventing the inclusion of user
  names or parts of."
  impact 0.5
  tag "gtitle": 'Microsoft Strong Password Filtering'
  tag "gid": 'V-1150'
  tag "rid": 'SV-52863r2_rule'
  tag "stig_id": 'WN12-AC-000008'
  tag "fix_id": 'F-45789r2_fix'
  tag "cci": ['CCI-000192', 'CCI-000193', 'CCI-000194',
              'CCI-001619']
  tag "cce": ['CCE-25602-4']
  tag "nist": ['IA-5 (1) (a)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Password Policy.

  If the value for \"Password must meet complexity requirements\" is not set to
  \"Enabled\", this is a finding.

  Note: If an external password filter is in use that enforces all 4 character
  types and requires this setting be set to \"Disabled\", this would not be
  considered a finding. If this setting does not affect the use of an external
  password filter, it must be enabled for fallback purposes."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings -> Security Settings >> Account Policies >> Password Policy >>
  \"Password must meet complexity requirements\" to \"Enabled\"."
  describe security_policy do
    its('PasswordComplexity') { should eq 1 }
  end
end
