control "V-40173" do
  title "System-related documentation must be backed up in accordance with
  local recovery time and recovery point objectives."
  desc  "Operating system backup is a critical step in maintaining data
  assurance and availability.

      Information system and security-related documentation contains information
  pertaining to system configuration and security settings.

      Backups shall be consistent with organizational recovery time and recovery
  point objectives.
  "
  impact 0.3
  tag "gtitle": "WN00-000017"
  tag "gid": "V-40173"
  tag "rid": "SV-52131r3_rule"
  tag "stig_id": "WN12-00-000017"
  tag "fix_id": "F-63427r1_fix"
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
  tag "check": "Determine whether system-related documentation is backed up in
  accordance with local recovery time and recovery point objectives.  If
  system-related documentation is not backed up in accordance with local recovery
  time and recovery point objectives, this is a finding."
  tag "fix": "Back up system-related documentation in accordance with local
  recovery time and recovery point objectives."
  describe "A manual review is required to ensure system-related documentation is backed up in accordance with
  local recovery time and recovery point objectives" do
    skip 'A manual review is required to ensure system-related documentation is backed up in accordance with
  local recovery time and recovery point objectives'
  end
end

