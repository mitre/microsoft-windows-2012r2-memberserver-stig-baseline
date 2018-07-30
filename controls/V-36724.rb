control "V-36724" do
  title "Permissions for the System event log must prevent access by
  nonprivileged accounts."
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.  The
  System event log may be  susceptible to tampering if proper permissions are not
  applied."
  impact 0.5
  tag "gtitle": "WINAU-000206"
  tag "gid": "V-36724"
  tag "rid": "SV-51572r1_rule"
  tag "stig_id": "WN12-AU-000206"
  tag "fix_id": "F-44701r1_fix"
  tag "cci": ["CCI-000162", "CCI-000163", "CCI-000164"]
  tag "nist": ["CCI-000162", "CCI-000163", "CCI-000164"]
  tag "nist": ["AU-9", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECTP-1"
  tag "check": "Verify the permissions on the System event log (System.evtx).
  Standard user accounts or groups must not have greater than Read access.  The
  default permissions listed below satisfy this requirement:

  Eventlog - Full Control
  SYSTEM - Full Control
  Administrators - Full Control

  The default location is the \"%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS\" directory.
   They may have been moved to another folder.

  If the permissions for these files are not as restrictive as the ACLs listed,
  this is a finding."
  tag "fix": "Ensure the permissions on the System event log (System.evtx) are
  configured to prevent standard user accounts or groups from having greater than
  Read access.  The default permissions listed below satisfy this requirement:

  Eventlog - Full Control
  SYSTEM - Full Control
  Administrators - Full Control

  The default location is the \"%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS\" directory.

  If the location of the logs has been changed, when adding Eventlog to the
  permissions, it must be entered as \"NT Service\\Eventlog\"."
  get_system_root = command("env | Findstr SYSTEMROOT").stdout.strip
  system_root = get_system_root[11..get_system_root.length]

  describe command("Get-Acl -Path '#{system_root}\\SYSTEM32\\WINEVT\\LOGS\' | Format-List | Findstr All") do
   its('stdout') { should eq "Access : NT AUTHORITY\\Authenticated Users Allow  Read, Synchronize\r\n         NT AUTHORITY\\SYSTEM Allow  FullControl\r\n         BUILTIN\\Administrators Allow  FullControl\r\n         NT SERVICE\\EventLog Allow  FullControl\r\n" }
  end
end 
