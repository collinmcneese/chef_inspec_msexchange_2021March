# exchange_hotfix_check.rb

control 'exchange_hotfix_check_2021March' do
  impact 1.0
  title 'Microsoft Exchange Hotfix check for March 2021'
  desc 'This vulnerability is part of an attack chain. The initial attack requires the ability to make an untrusted connection to Exchange server port 443. This can be protected against by restricting untrusted connections, or by setting up a VPN to separate the Exchange server from external access. Using this mitigation will only protect against the initial portion of the attack. Other portions of the chain can be triggered if an attacker already has access or can convince an administrator to open a malicious file.'
  tag cve: 'CVE-2021-26855'
  tag cve: 'CVE-2021-26857'
  tag cve: 'CVE-2021-26858'
  tag cve: 'CVE-2021-27065'
  ref 'CVE-2021-26855', url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855'
  ref 'CVE-2021-26857', url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26857'
  ref 'CVE-2021-26858', url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26858'
  ref 'CVE-2021-27065', url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065'

  only_if do
    os[:family] == 'windows' &&
    inspec.powershell('(Get-WmiObject -Class Win32_Product).name').stdout.split("\r\n").any?  { |list| /Exchange Server/ =~ list }
  end

  # Verify that Hotfix has been installed for Microsoft Exchange Server
  describe.one do
    describe windows_hotfix('KB5000871') do
      it { should be_installed }
    end
    describe windows_hotfix('5000978') do
      it { should be_installed }
    end
  end
end
