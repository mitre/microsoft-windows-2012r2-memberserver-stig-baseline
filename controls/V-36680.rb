# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-36680' do
  title 'Access to the Windows Store must be turned off.'
  desc  "Uncontrolled installation of applications can introduce various
  issues, including system instability, and allow access to sensitive
  information.  Installation of applications must be controlled by the
  enterprise.  Turning off access to the Windows Store will limit access to
  publicly available applications."
  impact 0.5
  tag "gtitle": 'WINCC-000030'
  tag "gid": 'V-36680'
  tag "rid": 'SV-51609r2_rule'
  tag "stig_id": 'WN12-CC-000030'
  tag "fix_id": 'F-74883r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24981-3']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "The Windows Store is not installed by default. If the
  \\Windows\\WinStore directory does not exist, this is NA.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

  Value Name: NoUseStoreOpenWith

  Type: REG_DWORD
  Value: 1"
  tag "fix": "If the \\Windows\\WinStore directory exists, configure the policy
  value for Computer Configuration >> Administrative Templates >> System >>
  Internet Communication Management >> Internet Communication settings >> \"Turn
  off access to the Store\" to \"Enabled\".

  Alternately, uninstall the \"Desktop Experience\" feature from Windows 2012.
  This is located under \"User Interfaces and Infrastructure\" in the \"Add Roles
  and Features Wizard\".  The \\Windows\\WinStore directory may need to be
  manually deleted after this."

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer') do
      it { should have_property 'NoUseStoreOpenWith' }
      its('NoUseStoreOpenWith') { should cmp == 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer') do
      it { should_not have_property 'NoUseStoreOpenWith' }
    end
  end
end
