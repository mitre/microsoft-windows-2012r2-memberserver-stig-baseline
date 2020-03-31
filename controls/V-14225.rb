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
  
  administrators = input('administrators')

  if !administrators.empty?
    administrators.each do |admin|
      password_age = json({ command:"NEW-TIMESPAN –End (GET-DATE) –Start ([datetime]((net user #{admin} | \
                        Select-String \"Password last set\").Line.Substring(29,10))) | convertto-json"}).Days

      describe "Administrator Password age for #{admin}" do
        subject { password_age }
        it { should cmp <= 365 }
      end
    end
  end

  if administrators.empty?
    describe 'There are no administrative accounts on this system' do
      skip 'There are no administrative accounts on this system'
    end
  end
end
