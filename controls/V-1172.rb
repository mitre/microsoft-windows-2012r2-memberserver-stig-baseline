# frozen_string_literal: true

control 'V-1172' do
  title 'Users must be warned in advance of their passwords expiring.'
  desc  "Creating strong passwords that can be remembered by users requires
  some thought.  By giving the user advance warning, the user has time to
  construct a sufficiently strong password.  This setting configures the system
  to display a warning to users telling them how many days are left before their
  password expires."
  impact 0.3
  tag "gtitle": 'Password Expiration Warning'
  tag "gid": 'V-1172'
  tag "rid": 'SV-52876r1_rule'
  tag "stig_id": 'WN12-SO-000025'
  tag "fix_id": 'F-45802r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-23704-0']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

  Value Name: PasswordExpiryWarning

  Value Type: REG_DWORD
  Value: 14 (or greater)"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Interactive Logon: Prompt user to change password before expiration\" to
  \"14\" days or more."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should have_property 'PasswordExpiryWarning' }
    its('PasswordExpiryWarning') { should cmp >= input('pass_expiry_warning') }
  end
end
