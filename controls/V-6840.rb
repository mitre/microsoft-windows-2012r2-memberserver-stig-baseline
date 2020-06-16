control 'V-6840' do
  title 'Windows 2012/2012 R2 passwords must be configured to expire.'
  desc  "Passwords that do not expire or are reused increase the exposure of a
  password with greater probability of being discovered or cracked."
  impact 0.5
  tag "gtitle": 'Password Expiration'
  tag "gid": 'V-6840'
  tag "rid": 'SV-52939r4_rule'
  tag "stig_id": 'WN12-GE-000016'
  tag "fix_id": 'F-85579r1_fix'
  tag "cci": ['CCI-000199']
  tag "nist": ['IA-5 (1) (d)', 'Rev_4']
  tag "documentable": false
  tag "check": "Review the password never expires status for enabled user
  accounts.

  Open \"Windows PowerShell\" with elevated privileges (run as administrator).

  Domain Controllers:

  Enter \"Search-ADAccount -PasswordNeverExpires -UsersOnly | Where
  PasswordNeverExpires -eq True | FT Name, PasswordNeverExpires, Enabled\".

  Exclude application accounts and disabled accounts (e.g., Guest).
  Domain accounts requiring smart card (CAC/PIV) may also be excluded.

  If any enabled user accounts are returned with a \"PasswordNeverExpires\"
  status of \"True\", this is a finding.

  Member servers and standalone systems:

  Enter 'Get-CimInstance -Class Win32_Useraccount -Filter \"PasswordExpires=False
  and LocalAccount=True\" | FT Name, PasswordExpires, Disabled, LocalAccount'.

  Exclude application accounts and disabled accounts (e.g., Guest).

  If any enabled user accounts are returned with a \"PasswordExpires\" status of
  \"False\", this is a finding."
  tag "fix": "Configure all enabled user account passwords to expire.

  Uncheck \"Password never expires\" for all enabled user accounts in Active
  Directory Users and Computers for domain a
  ccounts and Users in Computer
  Management for member servers and standalone systems. Document any exceptions
  with the ISSO."

  application_accounts = input('application_accounts_domain')
  excluded_accounts = input('excluded_accounts_domain')
  smart_card_check = json({ command: "Get-ADUser -Filter * -Properties SmartcardLogonRequired | Where-Object {$_.SmartcardLogonRequired -eq 'True' } | Select -ExpandProperty SamAccountName | ConvertTo-Json" })
  list_smart_card_acct = smart_card_check.params

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
    list_of_accounts = json({ command: "Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object {$_.PasswordNeverExpires -eq 'True' -and $_.Enabled -eq 'True'} | Select -ExpandProperty Name | ConvertTo-Json" })
    ad_accounts = list_of_accounts.params
    untracked_accounts = ad_accounts - list_smart_card_acct - application_accounts_domain - excluded_accounts_domain

    describe 'Untracked Accounts' do
      it 'No Enabled Domain Account should be set to have Password Never Expire' do
        failure_message = "Users Accounts are set to Password Never Expire: #{untracked_accounts}"
        expect(untracked_accounts).to be_empty, failure_message
      end
    end
  end
  if domain_role != '4' || domain_role != '5'
    local_users = json({ command: "Get-CimInstance -Class Win32_Useraccount -Filter 'PasswordExpires=False and LocalAccount=True and Disabled=False' | Select -ExpandProperty Name | ConvertTo-Json" })
    local_users_list = local_users.params
    if local_users_list == ' '
      impact 0.0
      describe 'The system does not have any local accounts where password is set to Password Never Expires, control is NA' do
        skip 'The system does not have any local accounts where password is set to Password Never Expires, controls is NA'
      end
    else
      describe 'Account or Accounts exists' do
        it 'Server should not have Accounts with Password Never Expire' do
          failure_message = "User or Users #{local_users_list} have Password set to not expire"
          expect(local_users_list).to be_empty, failure_message
        end
      end
    end
 end
end