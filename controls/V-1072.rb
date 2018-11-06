
SHARED_ACCOUNTS = attribute('shared_accounts')

control "V-1072" do
  title "Shared user accounts must not be permitted on the system."
  desc  "Shared accounts (accounts where two or more people log in with the
  same user identification) do not provide adequate identification and
  authentication.  There is no way to provide for nonrepudiation or individual
  accountability for system access and resource usage."
  impact 0.5
  tag "gtitle": "Shared User Accounts"
  tag "gid": "V-1072"
  tag "rid": "SV-52839r2_rule"
  tag "stig_id": "WN12-00-000012"
  tag "fix_id": "F-86115r1_fix" 
  tag "cci": ["CCI-000764"]
  tag "nist": ["IA-2", "Rev_4"]
  tag "documentable": false
  tag "check": "Determine whether any shared accounts exist. If no shared
  accounts exist, this is NA.

  Shared accounts, such as required by an application, may be approved by the
  organization.  This must be documented with the ISSO. Documentation must
  include the reason for the account, who has access to the account, and how the
  risk of using the shared account is mitigated to include monitoring account
  activity.

  If unapproved shared accounts exist, this is a finding."
  tag "fix": "Remove unapproved shared accounts from the system.

  Document required shared accounts with the ISSO. Documentation must include the
  reason for the account, who has access to the account, and how the risk of
  using the shared account is mitigated to include monitoring account activity."
  get_accounts = command("net user | Findstr /v 'command -- accounts'").stdout.strip.split(' ')
  

   if SHARED_ACCOUNTS.empty?
    impact 0.0
    describe "The system does not have any shared accounts, control is NA" do
      skip "The system does not have any shared accounts, controls is NA"
    end 
  else
    get_accounts.each do |user|
      describe user do
        it { should_not be_in SHARED_ACCOUNTS}
      end
    end 
  end
end
