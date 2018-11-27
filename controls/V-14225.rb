ADMINISTRATOR_ACCOUNT = attribute('administrators')

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

  require 'date'
  get_password_last_set = command("Net User #{ADMINISTRATOR_ACCOUNT} | Findstr /i 'Password Last Set' | Findstr /v 'expires changeable required may logon'").stdout.strip
  month = get_password_last_set[27..29]
  day = get_password_last_set[31..32]
  year = get_password_last_set[34..38]

  if get_password_last_set[32] == '/'
    month = get_password_last_set[27..29]
    day = get_password_last_set[31]
    year = get_password_last_set[33..37]
  end

  date = day + '/' + month + '/' + year

  date_password_last_set = DateTime.now.mjd - DateTime.parse(date).mjd
  describe "Administrator account's password last set" do
    describe date_password_last_set do
      it { should cmp <= 365 }
    end
  end
end
