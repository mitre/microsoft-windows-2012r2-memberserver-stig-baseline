# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-4108' do
  title "The system must generate an audit event when the audit log reaches a
  percentage of full threshold."
  desc "When the audit log reaches a given percent full, an audit event is
  written to the security log.  It is recorded as a successful audit event under
  the category of System.  This option may be especially useful if the audit logs
  are set to be cleared manually."
  impact 0.3
  tag "gtitle": 'Audit Log Warning Level'
  tag "gid": 'V-4108'
  tag "rid": 'SV-52923r2_rule'
  tag "stig_id": 'WN12-SO-000049'
  tag "fix_id": 'F-45849r2_fix'
  tag "cci": %w[CCI-000139 CCI-001855 CCI-001858]
  tag "cce": ['CCE-25110-8']
  tag "nist": ['AU-5 a', 'AU-5 (1)', 'AU-5 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the system is configured to write to an audit server, or is
  configured to automatically archive full logs, this is NA.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\Eventlog\\Security\\

  Value Name: WarningLevel

  Value Type: REG_DWORD
  Value: 90 (or less)"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (WarningLevel) Percentage threshold for the security event log at which the
  system will generate a warning\" to \"90\" or less.

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security') do
    it { should have_property 'WarningLevel' }
    its('WarningLevel') { should cmp <= 90 }
  end
end
