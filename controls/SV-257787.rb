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

  grubfile = input('grub_conf_path')
  grub_userfile = input('grub_user_conf_path')

  describe file(grubfile) do
    it { should exist }
  end

  describe file(grub_userfile) do
    it { should exist }
  end

  if file(grubfile).exist? && file(grub_userfile).exist?
    password_set = file(grubfile).content.lines.select { |line| line.match(/password_pbkdf2\s+\w+\s+\$\{\w+\}/) }

    describe 'The GRUB bootloader superuser password' do
      it "should be set in the GRUB config file ('#{grubfile}')" do
        expect(password_set).to_not be_empty, "No bootloader superuser password set in '#{grubfile}'"
      end

      grub_envar = password_set.first.match(/\$\{(?<grub_pw_envar>\w+)\}/).captures.first
      password_encrypted = file(grub_userfile).content.match?(/#{grub_envar}=grub.pbkdf2/)
      it "should be encrypted in the user config file ('#{grub_userfile}')" do
        expect(password_encrypted).to eq(true), "GRUB password environment variable not set to an encrypted value in '#{grub_userfile}'"
      end
    end
  end
end
