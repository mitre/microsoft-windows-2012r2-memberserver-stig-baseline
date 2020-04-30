# -*- encoding : utf-8 -*-
# frozen_string_literal: true

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
  tag "cci": %w[CCI-001494 CCI-001495]
  tag "nist": %w[AU-9 Rev_4]
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

  eventvwr = <<-EOH
  $output = (Get-Acl -Path #{systemroot}\\SYSTEM32\\Eventvwr.exe).AccessToString
  write-output $output
  EOH

  # raw powershell output
  raw_eventvwr = powershell(eventvwr).stdout.strip

  # clean results cleans up the extra line breaks
  clean_eventvwr = raw_eventvwr.lines.collect(&:strip)

  describe 'Verify the default registry permissions for the keys note below of the C:\Windows\System32\Eventvwr.exe' do
    subject { clean_eventvwr }
    it { should cmp input('eventvwr_perms') }
  end
end
