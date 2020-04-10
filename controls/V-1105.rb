control 'V-1105' do
  title 'The minimum password age must meet requirements.'
  desc  "Permitting passwords to be changed in immediate succession within the
  same day allows users to cycle passwords through their history database.  This
  enables users to effectively negate the purpose of mandating periodic password
  changes."
  impact 0.5
  tag "gtitle": 'Minimum Password Age'
  tag "gid": 'V-1105'
  tag "rid": 'SV-52852r1_rule'
  tag "stig_id": 'WN12-AC-000006'
  tag "fix_id": 'F-45778r2_fix'
  tag "cci": ['CCI-000198']
  tag "cce": ['CCE-24018-4']
  tag "nist": ['IA-5 (1) (d)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Account Policies -> Password Policy.

  If the value for the \"Minimum password age\" is set to \"0\" days (\"Password
  can be changed immediately.\"), this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Account Policies -> Password Policy ->
  \"Minimum password age\" to at least \"1\" day."
  
  describe security_policy do
    its('MinimumPasswordAge') { should be >= input('min_pass_age') }
  end
end
