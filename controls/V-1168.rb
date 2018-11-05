BACKUP_OPERATORS = attribute('backup_operators')

control "V-1168" do
  title "Members of the Backup Operators group must be documented."
  desc  "Backup Operators are able to read and write to any file in the system,
  regardless of the rights assigned to it.  Backup and restore rights permit
  users to circumvent the file access restrictions present on NTFS disk drives
  for backup and restore purposes.  Visibility of members of the Backup Operators
  group must be maintained."
   backup_operators_group = command("net localgroup 'Backup Operators' | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split("\r\n")
   if backup_operators_group == []
    impact 0.0
  else
    impact 0.5
  end
  tag "gtitle": "Members of the Backup Operators Group"
  tag "gid": "V-1168"
  tag "rid": "SV-52156r2_rule"
  tag "stig_id": "WN12-00-000009-01"
  tag "fix_id": "F-45181r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If no accounts are members of the Backup Operators group, this
  is NA.

  Any accounts that are members of the Backup Operators group, including
  application accounts, must be documented with the ISSO.  If documentation of
  accounts that are members of the Backup Operators group is not maintained this
  is a finding."
  tag "fix": "Create the necessary documentation that identifies the members of
  the Backup Operators group."
 
  if backup_operators_group != []
    backup_operators_group.each do |user|
      describe user do
        it { should be_in BACKUP_OPERATORS}
      end  
    end 
   else
    describe 'Backup Operators Group Empty' do
      skip 'The control is N/A as there are no users in the Backup Operators group'
    end   
  end
end

 