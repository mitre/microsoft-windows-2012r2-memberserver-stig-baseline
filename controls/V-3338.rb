# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-3338' do
  title "Named pipes that can be accessed anonymously must be configured to
  contain no values on member servers."
  desc "Named pipes that can be accessed anonymously provide the potential for
  gaining unauthorized system access.  Pipes are internal system communications
  processes.  They are identified internally by ID numbers that vary between
  systems.  To make access to these processes easier, these pipes are given names
  that do not vary between systems.  This setting controls which of these pipes
  anonymous users may access."
  impact 0.7
  tag "gtitle": 'Anonymous Access to Named Pipes'
  tag "gid": 'V-3338'
  tag "rid": 'SV-51497r2_rule'
  tag "stig_id": 'WN12-SO-000055-MS'
  tag "fix_id": 'F-44296r2_fix'
  tag "cci": ['CCI-001090']
  tag "cce": ['CCE-25466-4']
  tag "nist": %w[SC-4 Rev_4]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

  Value Name: NullSessionPipes

  Value Type: REG_MULTI_SZ
  Value: (blank)

  Legitimate applications may add entries to this registry value. If an
  application requires these entries to function properly and is documented with
  the ISSO, this would not be a finding.  Documentation must contain supporting
  information from the vendor's instructions."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network access: Named pipes that can be accessed anonymously\" to be defined
  but containing no entries (blank)."

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should have_property 'NullSessionPipes' }
    its('NullSessionPipes') { should eq [] }
  end
end
