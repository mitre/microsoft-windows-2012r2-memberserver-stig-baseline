control 'V-36723' do
  title "Permissions for the Security event log must prevent access by
  nonprivileged accounts."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.  The
  Security event log may disclose sensitive information or be  susceptible to
  tampering if proper permissions are not applied."
  impact 0.5
  tag "gtitle": 'WINAU-000205'
  tag "gid": 'V-36723'
  tag "rid": 'SV-51571r1_rule'
  tag "stig_id": 'WN12-AU-000205'
  tag "fix_id": 'F-44700r2_fix'
  tag "cci": ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag "nist": ['AU-9', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECTP-1'
  tag "check": "Verify the permissions on the Security event log
  (Security.evtx).  Standard user accounts or groups must not have access.  The
  default permissions listed below satisfy this requirement:

  Eventlog - Full Control
  SYSTEM - Full Control
  Administrators - Full Control

  The default location is the \"%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS\" directory.
   They may have been moved to another folder.

  If the permissions for these files are not as restrictive as the ACLs listed,
  this is a finding."
  tag "fix": "Ensure the permissions on the Security event log (Security.evtx)
  are configured to prevent standard user accounts or groups from having access.
  The default permissions listed below satisfy this requirement:

  Eventlog - Full Control
  SYSTEM - Full Control
  Administrators - Full Control

  The default location is the \"%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS\" directory.

  If the location of the logs has been changed, when adding Eventlog to the
  permissions, it must be entered as \"NT Service\\Eventlog\"."
  get_system_root = command('Get-ChildItem Env: | Findstr SystemRoot').stdout.strip
  system_root = get_system_root[11..get_system_root.length]

  systemroot = system_root.strip

  describe windows_registry("#{systemroot}\\SYSTEM32\\WINEVT\\LOGS\\Security.evtx") do
    it { should be_allowed('full-control', by_user: 'NT SERVICE\\EventLog') }
    it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
    it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
  end
end
