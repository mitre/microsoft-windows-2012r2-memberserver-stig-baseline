control 'V-36658' do
  title 'Users with administrative privilege must be documented.'
  desc  "Administrative accounts may perform any action on a system.  Users
  with administrative accounts must be documented to ensure those with this level
  of access are clearly identified."
  impact 0.5
  tag "gtitle": 'WIN00-000005-01'
  tag "gid": 'V-36658'
  tag "rid": 'SV-51575r2_rule'
  tag "stig_id": 'WN12-00-000004'
  tag "fix_id": 'F-44704r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Review the necessary documentation that identifies the members
  of the Administrators group.  If a list of all users belonging to the
  Administrators group is not maintained with the ISSO, this is a finding."
  tag "fix": "Create the necessary documentation that identifies the members of
  the Administrators group."

  administrators = input('administrators')
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
