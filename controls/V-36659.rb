control 'V-36659' do
  title "Users with Administrative privileges must have separate accounts for
  administrative duties and normal operational tasks."
  desc "Using a privileged account to perform routine functions makes the
  computer vulnerable to malicious software inadvertently introduced during a
  session that has been granted full privileges."
  impact 0.7
  tag "gtitle": 'WIN00-000005-02'
  tag "gid": 'V-36659'
  tag "rid": 'SV-51576r1_rule'
  tag "stig_id": 'WN12-00-000005'
  tag "fix_id": 'F-44705r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECLP-1'
  tag "check": "Verify each user with administrative privileges has been
  assigned a unique administrative account separate from their standard user
  account.

  If users with administrative privileges do not have separate accounts for
  administrative functions and standard user functions, this is a finding."
  tag "fix": "Ensure each user with administrative privileges has a separate
  account for user duties and one for privileged duties."
  
  administrators = attribute('administrators')
  administrator_group = command("net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split('\n')
  administrator_group.each do |user|
    describe user.to_s do
      it { should be_in administrators }
    end
  end
  if administrator_group.empty?
    impact 0.0
    describe 'There are no users with administrative privileges' do
      skip 'This control is not applicable'
    end
  end
end
