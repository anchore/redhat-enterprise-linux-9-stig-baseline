control 'SV-257787' do
  title 'RHEL 9 must require authentication upon booting into single-user and maintenance modes.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoW-approved PKIs, all DoW systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Password protection on the boot loader configuration ensures users with physical access cannot trivially alter important bootloader settings. These include which kernel to use, and whether to enter single-user mode.'
  desc 'check', 'Verify that RHEL 9 requires a password for the GRUB 2 bootloader to prevent unauthorized modifications to boot parameters.

Check the unified configuration file where the GRUB 2 password is stored:

# sudo grep -iw "GRUB2_PASSWORD" /boot/grub2/user.cfg
GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]

If the "GRUB2_PASSWORD" entry does not exist, is commented out, or if the hash does not begin with "grub.pbkdf2.sha512", this is a finding.

Note for upgraded systems: If the system was upgraded from an early release of RHEL 8 to RHEL 9, legacy configurations might still reside in the EFI partition. If "/boot/grub2/user.cfg" does not exist, verify the legacy path:

# grep -iw "GRUB2_PASSWORD" /boot/efi/EFI/redhat/user.cfg

If the "GRUB2_PASSWORD" entry does not exist in either location, is commented out, or does not begin with "grub.pbkdf2.sha512", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to require a grub bootloader password for the grub superuser account.

Generate an encrypted grub2 password for the grub superuser account with the following command:

$ sudo grub2-setpassword
Enter password:
Confirm password:'
  impact 0.5
  tag check_id: 'C-61528r1261989_chk'
  tag severity: 'medium'
  tag gid: 'V-257787'
  tag rid: 'SV-257787r1268226_rule'
  tag stig_id: 'RHEL-09-212010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-61452r925347_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !virtualization.container_system?
  end

  grub_userfile = input('grub_user_conf_path')
  legacy_grub_userfile = '/boot/efi/EFI/redhat/user.cfg'

  # Upgraded systems may still keep the legacy user.cfg on the EFI partition
  userfile = file(grub_userfile).exist? || !file(legacy_grub_userfile).exist? ? grub_userfile : legacy_grub_userfile

  describe file(userfile) do
    it { should exist }
  end

  if file(userfile).exist?
    password_lines = file(userfile).content.to_s.lines.map(&:strip).grep(/^GRUB2_PASSWORD\s*=/i)

    describe "The GRUB bootloader superuser password in '#{userfile}'" do
      it 'should be set (GRUB2_PASSWORD, uncommented)' do
        expect(password_lines).to_not be_empty, "No uncommented GRUB2_PASSWORD entry found in '#{userfile}'"
      end
      it 'should be a grub.pbkdf2.sha512 hash' do
        bad_lines = password_lines.grep_v(/^GRUB2_PASSWORD\s*=\s*grub\.pbkdf2\.sha512/i)
        expect(bad_lines).to be_empty, "GRUB2_PASSWORD entries not beginning with 'grub.pbkdf2.sha512':\n\t- #{bad_lines.join("\n\t- ")}"
      end
    end
  end
end
