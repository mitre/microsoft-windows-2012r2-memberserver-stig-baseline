control "V-40172" do
  title "Backups of system-level information must be protected."
  desc  "A system backup will usually include sensitive information such as
  user accounts that could be used in an attack.  As a valuable system resource,
  the system backup must be protected and stored in a physically secure location."
  impact 0.3
  tag "gtitle": "WN00-000016"
  tag "gid": "V-40172"
  tag "rid": "SV-52130r2_rule"
  tag "stig_id": "WN12-00-000016"
  tag "fix_id": "F-45156r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "CODB-2"
  tag "check": "Determine if system-level information backups are protected
  from destruction and stored in a physically secure location.  If they are not,
  this is a finding."
  tag "fix": "Ensure system-level information backups are stored in a secure
  location and protected from destruction."
  describe "Backups of system-level information must be protected" do
    skip "is a manual check"
  end
end

