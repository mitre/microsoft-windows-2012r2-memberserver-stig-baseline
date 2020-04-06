control 'V-1115' do
  title 'The built-in administrator account must be renamed.'
  desc  "The built-in administrator account is a well-known account subject to
  attack.  Renaming this account to an unidentified name improves the protection
  of this account and the system."
  impact 0.5
  tag "gtitle": 'Rename Built-in Administrator Account'
  tag "gid": 'V-1115'
  tag "rid": 'SV-52857r1_rule'
  tag "stig_id": 'WN12-SO-000005'
  tag "fix_id": 'F-45783r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-23836-0']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> Security Options.

  If the value for \"Accounts: Rename administrator account\" is not set to a
  value other than \"Administrator\", this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Accounts: Rename administrator account\" to a name other than
  \"Administrator\"."
  
  describe user('Administrator') do
    it { should_not exist }
  end
end
