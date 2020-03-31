control 'V-57655' do
  title "Windows 2012 / 2012 R2 must automatically remove or disable emergency
  accounts after the crisis is resolved or within 72 hours."
  desc "Emergency administrator accounts are privileged accounts which are
  established in response to crisis situations where the need for rapid account
  activation is required. Therefore, emergency account activation may bypass
  normal account authorization processes. If these accounts are automatically
  disabled, system maintenance during emergencies may not be possible, thus
  adversely affecting system availability.

  Emergency administrator accounts are different from infrequently used
  accounts (i.e., local logon accounts used by system administrators when network
  or normal logon/access is not available). Infrequently used accounts are not
  subject to automatic termination dates. Emergency accounts are accounts created
  in response to crisis situations, usually for use by maintenance personnel. The
  automatic expiration or disabling time period may be extended as needed until
  the crisis is resolved; however, it must not be extended indefinitely. A
  permanent account should be established for privileged users who need long-term
  maintenance accounts.

  To address access requirements, many operating systems can be integrated
  with enterprise-level authentication/access mechanisms that meet or exceed
  access control policy requirements.
  "
  impact 0.5
  tag "gtitle": 'WINGE-000057'
  tag "gid": 'V-57655'
  tag "rid": 'SV-72065r3_rule'
  tag "stig_id": 'WN12-GE-000057'
  tag "fix_id": 'F-82985r1_fix'
  tag "cci": ['CCI-001682']
  tag "nist": ['AC-2 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "Determine if emergency administrator accounts are used and
  identify any that exist. If none exist, this is NA.

  If emergency administrator accounts cannot be configured with an expiration
  date due to an ongoing crisis, the accounts must be disabled or removed when
  the crisis is resolved.

  If emergency administrator accounts have not been configured with an expiration
  date or have not been disabled or removed following the resolution of a crisis,
  this is a finding.

  Domain Controllers:

  Enter \"Search-ADAccount -AccountExpiring -TimeSpan 3:00:00:00 | FT Name,
  AccountExpirationDate\"
  This will return any accounts configured to expire within the next 3 days.
  (The \"TimeSpan\" value to can be changed to find accounts configured to expire
  at various times such as 30 for the next month.)

  If any accounts identified as emergency administrator accounts are not listed,
  this is a finding.

  For any emergency administrator accounts returned by the previous query:
  Enter \"Get-ADUser -Identity [Name] -Property WhenCreated\" to determine when
  the account was created.

  If the \"WhenCreated\" date and \"AccountExpirationDate\" from the previous
  query are greater than 3 days apart, this is a finding.

  Member servers and standalone systems:

  Enter \"Net User [username]\", where [username] is the name of the emergency
  administrator accounts.

  If \"Account expires\" has not been defined within 72 hours for any emergency
  administrator accounts, this is a finding.

  If the \"Password last set\" date and \"Account expires\" date are greater than
  72 hours apart, this is a finding. (Net User does not provide an account
  creation date.)"
  tag "fix": "Remove emergency administrator accounts after a crisis has been
  resolved or configure the accounts to automatically expire within 72 hours.

  Domain accounts can be configured with an account expiration date, under
  \"Account\" properties.

  Local accounts can be configured to expire with the command \"Net user
  [username] /expires:[mm/dd/yyyy]\", where username is the name of the emergency
  administrator account."

  emergency_account = input('emergency_account')
  if !emergency_account .empty?

    emergency_account.each do |user|

      get_account_expires = command("Net User #{user} | Findstr /i 'expires' | Findstr /v 'password'").stdout.strip

      month_account_expires = get_account_expires[28..30]
      day_account_expires = get_account_expires[32..33]
      year_account_expires = get_account_expires[35..39]

      if get_account_expires[30] == '/'
        month_account_expires = get_account_expires[28..29]
        if get_account_expires[32] == '/'
          day_account_expires = get_account_expires[31]
        end
        if get_account_expires[32] != '/'
          day_account_expires = get_account_expires[31..32]
        end
        if get_account_expires[33] == '/'
          year_account_expires = get_account_expires[34..37]
        end
        if get_account_expires[33] != '/'
          year_account_expires = get_account_expires[33..37]
        end
      end

      date_expires = day_account_expires + '/' + month_account_expires + '/' + year_account_expires

      get_password_last_set = command("Net User #{user}  | Findstr /i 'Password Last Set' | Findstr /v 'expires changeable required may logon'").stdout.strip

      month = get_password_last_set[27..29]
      day = get_password_last_set[31..32]
      year = get_password_last_set[34..38]

      if get_password_last_set[32] == '/'
        month = get_password_last_set[27..29]
        day = get_password_last_set[31]
        year = get_password_last_set[33..37]
      end
      date = day + '/' + month + '/' + year

      date_expires_minus_password_last_set = DateTime.parse(date_expires).mjd - DateTime.parse(date).mjd

      account_expires = get_account_expires[27..33]

      if account_expires == 'Never'
        describe "#{user}'s account expires" do
          describe account_expires do
            it { should_not == 'Never' }
          end
        end
      end
      next unless account_expires != 'Never'
      describe "#{user}'s account expires" do
        describe date_expires_minus_password_last_set do
          it { should cmp <= 72 }
        end
      end
    end

  else
    impact 0.0
    describe 'No emergency accounts exist' do
      skip 'check not applicable'
    end
  end
end
