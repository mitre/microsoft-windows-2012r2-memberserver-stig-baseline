control 'V-57721' do
  title "Event Viewer must be protected from unauthorized modification and
  deletion."
  desc "Protecting audit information also includes identifying and protecting
  the tools used to view and manipulate log data. Therefore, protecting audit
  tools is necessary to prevent unauthorized operation on audit information.

  Operating systems providing tools to interface with audit information will
  leverage user permissions and roles identifying the user accessing the tools
  and the corresponding rights the user enjoys in order to make access decisions
  regarding the modification or deletion of audit tools.
  "
  impact 0.5
  tag "gtitle": 'WINAU-000213'
  tag "gid": 'V-57721'
  tag "rid": 'SV-72135r2_rule'
  tag "stig_id": 'WN12-AU-000213'
  tag "fix_id": 'F-62927r2_fix'
  tag "cci": ['CCI-001494', 'CCI-001495']
  tag "nist": ['AU-9', 'Rev_4']
  tag "documentable": false
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
  get_system_root = command('Get-ChildItem Env: | Findstr SystemRoot').stdout.strip
  system_root = get_system_root[11..get_system_root.length]

  systemroot = system_root.strip

   describe windows_registry("#{systemroot}\\SYSTEM32\\Eventvwr.exe") do
    it { should be_allowed('read', by_user: 'NT AUTHORITY\\SYSTEM') }
    it { should be_allowed('read', by_user: 'BUILTIN\\Administrators') }
    it { should be_allowed('read', by_user: 'BUILTIN\\Users') }
    it { should be_allowed('full-control', by_user: 'NT SERVICE\\TrustedInstaller') }
    it { should be_allowed('read', by_user: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES') }
  end
end
