control "V-1112" do
  title "Outdated or unused accounts must be removed from the system or
  disabled."
  desc  "Outdated or unused accounts provide penetration points that may go
  undetected.  Inactive accounts must be deleted if no longer necessary or, if
  still required, disabled until needed."
  impact 0.3
  tag "gtitle": "Dormant Accounts"
  tag "gid": "V-1112"
  tag "rid": "SV-52854r4_rule"
  tag "stig_id": "WN12-GE-000014"
  tag "fix_id": "F-45780r2_fix"
  tag "cci": ["CCI-000795"]
  tag "nist": ["CCI-000795"]
  tag "nist": ["IA-4 e", "Rev_4"]
  tag "documentable": false
  tag "check": "Run \"PowerShell\".

  Member servers and standalone systems:
  Copy or enter the lines below to the PowerShell window and enter. (Entering
  twice may be required. Do not include the quotes at the beginning and end of
  the query.)

  ([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where {
  $_.SchemaClassName -eq 'user' } | ForEach {
   $user = ([ADSI]$_.Path)      <status>draft</status>

   $lastLogin = $user.Properties.LastLogin.Value
   $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
   if ($lastLogin -eq $null) {
   $lastLogin = 'Never'
   }
   Write-Host $user.Name $lastLogin $enabled
  }

  This will return a list of local accounts with the account name, last logon,
  and if the account is enabled (True/False).
  For example: User1 10/31/2015 5:49:56 AM True

  Domain Controllers:
  Enter the following command in PowerShell.
  \"Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00\"

  This will return accounts that have not been logged on to for 35 days, along
  with various attributes such as the Enabled status and LastLogonDate.

  Review the list of accounts returned by the above queries to determine the
  finding validity for each account reported.

  Exclude the following accounts:
  Built-in administrator account (Renamed, SID ending in 500)
  Built-in guest account (Renamed, Disabled, SID ending in 501)
  Application accounts

  If any enabled accounts have not been logged on to within the past 35 days,
  this is a finding.

  Inactive accounts that have been reviewed and deemed to be required must be
  documented with the ISSO."
  tag "fix": "Regularly review accounts to determine if they are still active.
  Disable or delete any active accounts that have not been used in the last 35
  days."

  users = command("net user | Findstr /V 'command -- accounts'").stdout.strip.split(' ')

  get_sids = []
  get_names = []
  names = []
  sids = []
  users.each do |user|
    get_sids = command("wmic useraccount where \"Name='#{user}'\" get name,sid | Findstr /v SID").stdout.strip
    get_last = get_sids[get_sids.length-3, 3]
    loc_colon = get_sids.index(' ')
    names = get_sids[0,loc_colon]
    if (get_last != '500'  && get_last != '501')
      get_names.push(names)
     end
  end

  get_names.each do |user|

    get_last_logon = command("Net User #{user} | Findstr /i 'Last Logon' | Findstr /v 'Password script hours'").stdout.strip

    last_logon = get_last_logon[29..33]

    if (last_logon != 'Never')
      month = get_last_logon[28..29]
      day = get_last_logon[31..32]
      year = get_last_logon[34..37]

      if (get_last_logon[32] == '/')
        month = get_last_logon[28..29]
        day = get_last_logon[31]
        year = get_last_logon[33..37]
      end
      date = day +  "/" + month + "/" + year

      date_last_logged_on = DateTime.now.mjd - DateTime.parse(date).mjd
      describe "#{user}'s last logon" do
        describe date_last_logged_on do
          it { should cmp <= 35 }
        end 
      end
    end

    if (last_logon == 'Never')
      date_last_logged_on = 'Never'
      describe "#{user}'s last logon" do
        describe date_last_logged_on do
          it { should_not == 'Never' }
        end 
      end
    end
  end 
end
