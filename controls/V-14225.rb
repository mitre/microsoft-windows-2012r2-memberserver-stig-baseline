# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-14225' do
  title "Windows 2012/2012 R2 password for the built-in Administrator account
  must be changed at least annually or when a member of the administrative team
  leaves the organization."
  desc "The longer a password is in use, the greater the opportunity for
  someone to gain unauthorized knowledge of the password. The password for the
  built-in Administrator account must be changed at least annually or when any
  member of the administrative team leaves the organization.

  Organizations that use an automated tool, such as Microsoft's Local
  Administrator Password Solution (LAPS), on domain-joined systems can configure
  this to occur more frequently. LAPS will change the password every \"30\" days
  by default.
  "
  impact 0.5
  tag "gtitle": 'Administrator Account Password Changes'
  tag "gid": 'V-14225'
  tag "rid": 'SV-52942r3_rule'
  tag "stig_id": 'WN12-00-000007'
  tag "fix_id": 'F-85583r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Review the password last set date for the built-in
  Administrator account.

  Domain controllers:

  Open \"Windows PowerShell\".

  Enter \"Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like
  \"*-500\" | FL Name, SID, PasswordLastSet\".

  If the \"PasswordLastSet\" date is greater than one year old, this is a finding.

  Member servers and standalone systems:

  Open \"Windows PowerShell\" or \"Command Prompt\".

  Enter 'Net User [account name] | Find /i \"Password Last Set\"', where [account
  name] is the name of the built-in administrator account.

  (The name of the built-in Administrator account must be changed to something
  other than \"Administrator\" per STIG requirements.)

  If the \"PasswordLastSet\" date is greater than one year old, this is a
  finding."
  tag "fix": "Change the built-in Administrator account password at least
  annually or whenever an administrator leaves the organization. More frequent
  changes are recommended.

  Automated tools, such as Microsoft's LAPS, may be used on domain-joined member
  servers to accomplish this."

  administrator = input('local_administrator')

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    password_set_date = json({ command: "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where-Object {$_.SID -like '*-500' -and $_.PasswordLastSet -lt ((Get-Date).AddDays(-365))} | Select-Object -ExpandProperty PasswordLastSet | ConvertTo-Json" })
    date = password_set_date['DateTime']
    if date.nil?
      describe 'Administrator Account is within 365 days since password change' do
        skip 'Administrator Account is within 365 days since password change'
      end
    else
      describe 'Password Last Set' do
        it 'Administrator Account Password Last Set Date is' do
          failure_message = "Password Date should not be more that 365 Days: #{date}"
          expect(date).to be_empty, failure_message
        end
      end
     end
  end
  if domain_role != '4' || domain_role != '5'
    # Input local_administrator is critical here
    local_password_set_date = json({ command: "Get-LocalUser -name #{administrator} | Where-Object {$_.PasswordLastSet -le (Get-Date).AddDays(-365)} | Select-Object -ExpandProperty PasswordLastSet | ConvertTo-Json" })
    local_date = local_password_set_date['DateTime']
    if local_date.nil?
      describe 'Local Administrator Account is within 365 days since password change' do
        skip 'Local Administrator Account is within 365 days since password change'
      end
    else
      describe 'Password Last Set' do
        it 'Local Administrator Account Password Last Set Date is' do
          failure_message = "Password Date should not be more that 365 Days: #{local_date}"
          expect(local_date).to be_empty, failure_message
        end
      end
      end
  end
end
