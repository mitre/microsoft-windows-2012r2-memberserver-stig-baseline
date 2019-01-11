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
  tag "check": "Determine whether system-level information is backed up in
  accordance with local recovery time and recovery point objectives.  If
  system-level information is not backed up in accordance with local recovery
  time and recovery point objectives, this is a finding."
  tag "fix": "Implement system-level information backups in accordance with
  local recovery time and recovery point objectives."
  describe "System-level information must be backed up in accordance with local
  recovery time and recovery point objectives." do
    skip 'is a manual check'
  end
end

