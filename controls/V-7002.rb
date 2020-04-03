control 'V-7002' do
  title 'Windows 2012/2012 R2 accounts must be configured to require passwords.'
  desc  "The lack of password protection enables anyone to gain access to the
  information system, which opens a backdoor opportunity for intruders to
  compromise the system as well as other resources.  Accounts on a system must
  require passwords."
  impact 0.7
  tag "gtitle": 'Password Requirement'
  tag "gid": 'V-7002'
  tag "rid": 'SV-52940r2_rule'
  tag "stig_id": 'WN12-GE-000015'
  tag "fix_id": 'F-85581r1_fix'
  tag "cci": ['CCI-000764']
  tag "nist": ['IA-2', 'Rev_4']
  tag "documentable": false
  tag "check": "Review the password required status for enabled user accounts.

  Open \"Windows PowerShell\".

  Domain Controllers:

  Enter \"Get-ADUser -Filter * -Properties PasswordNotRequired | Where
  PasswordNotRequired -eq True | FT Name, PasswordNotRequired, Enabled\".

  Exclude disabled accounts (e.g., Guest).

  If \"PasswordNotRequired\" is \"True\" for any enabled user account, this is a
  finding.

  Member servers and standalone systems:

  Enter 'Get-CimInstance -Class Win32_Useraccount -Filter
  \"PasswordRequired=False and LocalAccount=True\" | FT Name, PasswordRequired,
  Disabled, LocalAccount'.

  Exclude disabled accounts (e.g., Guest).

  If any enabled user accounts are returned with a \"PasswordRequired\" status of
  \"False\", this is a finding."
  tag "fix": "Configure all enabled accounts to require passwords.

  The password required flag can be set by entering the following on a command
  line: \"Net user [username] /passwordreq:yes\", substituting [username] with
  the name of the user account."

  is_domain_controller = powershell('Get-ADDomainController').stdout.strip

  if is_domain_controller == ''
  users_with_no_password_required = command("Get-CimInstance -Class Win32_Useraccount -Filter 'PasswordRequired=False and LocalAccount=True and Disabled=False' | FT Name | Findstr /V 'Name --'").stdout
  describe "Windows 2012/2012 R2 accounts configured to not require passwords" do
    subject {users_with_no_password_required}
    it { should be_empty }
  end
  else
     impact 0.0
    describe 'Review Domain Accounts' do
      skip 'Review Domain Accounts'
    end
  end
end
