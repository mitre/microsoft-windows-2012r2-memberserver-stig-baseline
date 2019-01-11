control "V-36662" do
  title "Windows 2012/2012 R2 manually managed application account passwords
  must be changed at least annually or when a system administrator with knowledge
  of the password leaves the organization."
  desc  "Setting application accounts to expire may cause applications to stop
  functioning. However, not changing them on a regular basis exposes them to
  attack. If managed service accounts are used, this alleviates the need to
  manually change application account passwords."
  impact 0.5
  tag "gtitle": "WIN00-000010-02"
  tag "gid": "V-36662"
  tag "rid": "SV-51580r3_rule"
  tag "stig_id": "WN12-00-000011"
  tag "fix_id": "F-85585r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Determine if manually managed application/service accounts
  exist. If none exist, this is NA.

  If passwords for manually managed application/service accounts are not changed
  at least annually or when an administrator with knowledge of the password
  leaves the organization, this is a finding.

  Identify manually managed application/service accounts.

  To determine the date a password was last changed:

  Domain controllers:

  Open \"Windows PowerShell\".

  Enter \"Get-ADUser -Identity [application account name] -Properties
  PasswordLastSet | FL Name, PasswordLastSet\", where [application account name]
  is the name of the manually managed application/service account.

  If the \"PasswordLastSet\" date is more than one year old, this is a finding.

  Member servers and standalone systems:

  Open \"Windows PowerShell\" or \"Command Prompt\".

  Enter 'Net User [application account name] | Find /i \"Password Last Set\"',
  where [application account name] is the name of the manually managed
  application/service account.

  If the \"Password Last Set\" date is more than one year old, this is a finding."
  tag "fix": "Change passwords for manually managed application/service
  accounts at least annually or when an administrator with knowledge of the
  password leaves the organization.

  It is recommended that system-managed service accounts be used where possible."
  users = command("net user | Findstr /V 'command -- accounts'").stdout.strip.split(' ')

  users.each do |user|

    get_password_last_set = command("Net User #{user}  | Findstr /i 'Password Last Set' | Findstr /v 'expires changeable required may logon'").stdout.strip

    month = get_password_last_set[27..29]
    day = get_password_last_set[31..32]
    year = get_password_last_set[34..38]

    date = day + '/' + month + '/' + year

    date_password_last_set = DateTime.now.mjd - DateTime.parse(date).mjd
    describe "#{user}'s data password last set" do
      describe date_password_last_set do
        it { should cmp <= 365 }
      end
    end
  end
  if users.empty?
    impact 0.0
    describe 'There are no system users' do
      skip 'This control is not applicable'
    end
  end
end

