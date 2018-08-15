 ADMINISTRATORS2 = attribute(
  'administrators',
  description: 'List of authorized users in the local Admionistrators group',
  default: %w[
            Administrators
            Admn
           ]
)


control "V-36658" do
  title "Users with administrative privilege must be documented."
  desc  "Administrative accounts may perform any action on a system.  Users
  with administrative accounts must be documented to ensure those with this level
  of access are clearly identified."
  impact 0.5
  tag "gtitle": "WIN00-000005-01"
  tag "gid": "V-36658"
  tag "rid": "SV-51575r2_rule"
  tag "stig_id": "WN12-00-000004"
  tag "fix_id": "F-44704r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Review the necessary documentation that identifies the members
  of the Administrators group.  If a list of all users belonging to the
  Administrators group is not maintained with the ISSO, this is a finding."
  tag "fix": "Create the necessary documentation that identifies the members of
  the Administrators group."

  administrator_group = command("net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split('\n')
  administrator_group.each do |user|
    describe "#{user}" do
      it { should be_in ADMINISTRATORS2}
    end  
  end 
end

