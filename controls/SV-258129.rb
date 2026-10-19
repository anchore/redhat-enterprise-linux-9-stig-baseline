control 'SV-258129' do
  title 'RHEL 9 must require authentication to access single-user mode.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoW-approved PKIs, all DoW systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

This requirement prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password.

To modify properties, such as dependencies or timeouts, of a service that is handled by a SysV initscript, do not modify the initscript itself. Instead, create a systemd drop-in configuration file for the service. Then manage this service in the same way as a normal systemd service.

For example, to extend the configuration of the network service, do not modify the /etc/rc.d/init.d/network initscript file. Instead, create new directory /etc/systemd/system/network.service.d/ and a systemd drop-in file /etc/systemd/system/network.service.d/my_config.conf. Then, put the modified values into the drop-in file. Note: systemd knows the network service as network.service, which is why the created directory must be called "network.service.d".'
  desc 'check', 'Verify RHEL 9 requires authentication for single-user mode with the following command:

$ grep sulogin /usr/lib/systemd/system/rescue.service

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

If the line is not returned from the default systemd file, use the following command to look for modifications to the rescue.service:

$ grep sulogin /etc/systemd/system/rescue.service.d/*.conf

If the line is not returned from either location this is a finding.

Note: The configuration setting can only be in either the default location, or in the drop in file, not both locations.'
  desc 'fix', 'Configure RHEL 9 to require authentication for single-user mode.

Create a directory for supplementary configuration files:

$ sudo mkdir /etc/systemd/system/rescue.service.d/

Create a new file:

$ sudo vi etc/systemd/system/rescue.service.d/rescue.service.conf

Add these lines to the new file:

[Service]
ExecStart=
ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

Apply changes to unit files without rebooting the system:

$ sudo systemctl daemon-reload'
  impact 0.5
  tag check_id: 'C-61870r1262032_chk'
  tag severity: 'medium'
  tag gid: 'V-258129'
  tag rid: 'SV-258129r1268226_rule'
  tag stig_id: 'RHEL-09-611200'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-61794r1262033_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  describe ini('/usr/lib/systemd/system/rescue.service') do
    its('Service.ExecStart') { should match %r{^-/usr/lib/systemd/systemd-sulogin-shell rescue$} }
  end
end
