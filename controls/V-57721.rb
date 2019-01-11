control "V-57721" do
  title "Event Viewer must be protected from unauthorized modification and
  deletion."
  desc  "Protecting audit information also includes identifying and protecting
  the tools used to view and manipulate log data. Therefore, protecting audit
  tools is necessary to prevent unauthorized operation on audit information.

      Operating systems providing tools to interface with audit information will
  leverage user permissions and roles identifying the user accessing the tools
  and the corresponding rights the user enjoys in order to make access decisions
  regarding the modification or deletion of audit tools.
  "
  impact 0.5
  tag "gtitle": "WINAU-000213"
  tag "gid": "V-57721"
  tag "rid": "SV-72135r2_rule"
  tag "stig_id": "WN12-AU-000213"
  tag "fix_id": "F-62927r2_fix"
  tag "cci": ["CCI-001494", "CCI-001495"]
  tag "nist": ['AU-9', 'Rev_4']
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
    tag "check": "Verify the permissions on Event Viewer only allow
  TrustedInstaller permissions to change or modify.  If any groups or accounts
  other than TrustedInstaller have Full control or Modify, this is a finding.

  Navigate to \"%SystemRoot%\\SYSTEM32\".
  View the permissions on \"Eventvwr.exe\".

  The default permissions below satisfy this requirement.
  TrustedInstaller - Full Control
  Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES - Read & Execute"
  tag "fix": "Ensure only TrustedInstaller has permissions to change or modify
  Event Viewer (\"%SystemRoot%\\SYSTEM32\\Eventvwr.exe).

  The default permissions below satisfy this requirement.
  TrustedInstaller - Full Control
  Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES - Read & Execute"
  get_system_root = command('env | Findstr SYSTEMROOT').stdout.strip
  system_root = get_system_root[11..get_system_root.length]

  describe command("Get-Acl -Path '#{system_root}\\SYSTEM32\\Eventvwr.exe' | Format-List | Findstr All") do
    its('stdout') { should eq "Access : NT AUTHORITY\\SYSTEM Allow  ReadAndExecute, Synchronize\r\n         BUILTIN\\Administrators Allow  ReadAndExecute, Synchronize\r\n         BUILTIN\\Users Allow  ReadAndExecute, Synchronize\r\n         NT SERVICE\\TrustedInstaller Allow  FullControl\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize\r\n" }
  end
end

