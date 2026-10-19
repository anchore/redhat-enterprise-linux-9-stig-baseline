control 'SV-258149' do
  title 'RHEL 9 must be configured to forward audit records via TCP to a different system or media from the system being audited via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

RHEL 9 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the SSL, TLS and DTLS protocols) creates a method to securely encrypt and off-load auditing.

Rsyslog provides three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above.

Examples of each configuration:
UDP *.* @remotesystemname
TCP *.* @@remotesystemname
RELP *.* :omrelp:remotesystemname:2514
Note that a port number was given as there is no standard port for RELP.'
  desc 'check', %q(Verify RHEL 9 audit system off-loads audit records onto a different system or media from the system being audited via rsyslog using TCP with the following commands:

To check for legacy configuration syntax, perform the following:
$ sudo grep -ir '@@' /etc/rsyslog.conf /etc/rsyslog.d/

To check for Rainer script syntax, perform the following:
$ sudo grep -rq 'type="omfwd"' /etc/rsyslog.conf /etc/rsyslog.d/

If a remote server is not configured, or the line is commented out, ask the system administrator (SA) to indicate how the audit logs are off-loaded to a different system or media.

If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding.)
  desc 'fix', %q(Configure RHEL 9 to off-load audit records onto a different system or media from the system being audited via TCP using rsyslog by specifying the remote logging server in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf" with the name or IP address of the log aggregation server. The following are examples of the configuration for the legacy syntax and for the newer Rainer script. Only one should be used.

Using legacy '@host:port" syntax example:
*.* @@[remoteloggingserver]:[port]

Using Rainer script example:
action(
    type="omfwd"
    target="logserver.example.com"
    port="514"
    protocol="tcp"
    action.resumeRetryCount="-1"
    queue.type="linkedList"
    que.size="10000"
)

Note: The Rainer Script above does not contain the required encryption settings.)
  impact 0.5
  tag check_id: 'C-61890r1155578_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-258149'
  tag rid: 'SV-258149r1155580_rule'
  tag stig_id: 'RHEL-09-652055'
  tag fix_id: 'F-61814r1155579_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  if input('alternative_logging_method') == ''
    rsyslog_config_files = input('logging_conf_files').join(' ')
    active_rsyslog_config = command("grep -hsv '^[[:space:]]*#' #{rsyslog_config_files}").stdout
    legacy_tcp_forwarding = active_rsyslog_config.match?(/@@\S+/)
    rainer_tcp_forwarding = active_rsyslog_config.match?(/action\(\s*(?=[^)]*\btype\s*=\s*"omfwd")(?=[^)]*\bprotocol\s*=\s*"tcp")(?=[^)]*\btarget\s*=\s*"[^"]+")[^)]*\)/i)

    describe 'Rsyslog audit record forwarding' do
      it 'forwards audit records over TCP to a remote system' do
        expect(legacy_tcp_forwarding || rainer_tcp_forwarding).to be(true), "No active TCP forwarding rule found in #{rsyslog_config_files}"
      end
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
