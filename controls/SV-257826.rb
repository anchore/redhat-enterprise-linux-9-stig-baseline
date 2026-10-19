control 'SV-257826' do
  title 'RHEL 9 must not have a File Transfer Protocol (FTP) server package installed.'
  desc 'The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.

Removing the "vsftpd" package decreases the risk of accidental activation.

If FTP is required for operational support (such as transmission of router configurations), its use must be documented with the information systems security manager (ISSM), restricted to only authorized personnel, and have access control rules established.'
  desc 'check', 'Verify RHEL 9 does not have an FTP server package installed with the following command:

$ sudo dnf list --installed | grep vsftpd

If the "vsftpd" package is installed, this is a finding.'
  desc 'fix', 'Remove the vsftpd package with the following command:

$ sudo dnf remove vsftpd'
  impact 0.7
  tag check_id: 'C-61567r1208477_chk'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000095-GPOS-00049', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-257826'
  tag rid: 'SV-257826r1208770_rule'
  tag stig_id: 'RHEL-09-215015'
  tag fix_id: 'F-61491r1208478_fix'
  tag cci: ['CCI-000197', 'CCI-000381']
  tag nist: ['IA-5 (1) (c)', 'CM-7 a']
  tag 'host'
  tag 'container'

  if input('ftp_required')
    describe package('vsftpd') do
      it { should be_installed }
    end
  else
    describe package('vsftpd') do
      it { should_not be_installed }
    end
  end
end
