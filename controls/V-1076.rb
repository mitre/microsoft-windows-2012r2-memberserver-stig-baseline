control "V-1076" do
  title "System-level information must be backed up in accordance with local
  recovery time and recovery point objectives."
  desc  "Operating system backup is a critical step in maintaining data
  assurance and availability.

  System-level information includes system-state information, operating
  system and application software, and licenses.

  Backups must be consistent with organizational recovery time and recovery
  point objectives.
  "
  impact 0.3
  tag "gtitle": "System Recovery Backups"
  tag "gid": "V-1076"
  tag "rid": "SV-52841r2_rule"
  tag "stig_id": "WN12-00-000014"
  tag "fix_id": "F-63413r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Determine whether system-level information is backed up in
  accordance with local recovery time and recovery point objectives.  If
  system-level information is not backed up in accordance with local recovery
  time and recovery point objectives, this is a finding."
  tag "fix": "Implement system-level information backups in accordance with
  local recovery time and recovery point objectives."
  describe "System-level information must be backed up in accordance with local
  recovery time and recovery point objectives." do
    skip "is a manual check"
  end
end
 
