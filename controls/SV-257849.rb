control 'SV-257849' do
  title 'The RHEL 9 file system automounter must be disabled.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, devices such as flash drives, external storage, and printers.'
  desc 'check', 'Verify that RHEL 9 file system automount function has been disabled and masked with the following command:

$ $ systemctl is-enabled  autofs
masked

If the returned value is not "masked", "disabled", or "not-found", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable and mask the ability to automount devices.

The "autofs" service can be disabled with the following command:

$ sudo systemctl mask --now autofs.service'
  impact 0.5
  tag check_id: 'C-61590r1262008_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163']
  tag gid: 'V-257849'
  tag rid: 'SV-257849r1262109_rule'
  tag stig_id: 'RHEL-09-231040'
  tag fix_id: 'F-61514r1262009_fix'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['IA-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  if input('autofs_required') == true
    describe systemd_service('autofs.service') do
      it { should be_running }
      it { should be_enabled }
      it { should be_installed }
    end
  elsif package('autofs').installed?
    describe systemd_service('autofs.service') do
      it { should_not be_running }
      it { should_not be_enabled }
      it { should_not be_installed }
    end
  else
    impact 0.0
    describe 'The autofs service is not installed' do
      skip 'The autofs service is not installed; this control is Not Applicable.'
    end
  end
end
