control 'SV-258150' do
  title 'RHEL 9 must use cron logging.'
  desc 'Cron logging can be used to trace the successful or unsuccessful
execution of cron jobs. It can also be used to spot intrusions into the use of
the cron facility by unauthorized and malicious users.'
  desc 'check', 'Verify rsyslog is configured to log cron events with the following command:

Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files.

$ grep -s "cron.\\*" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
/etc/rsyslog.d/99-cron-stig.conf:cron.* action(type="omfile" file="/var/log/cron")

If the command does not return a line demonstrating logging to "/var/log/cron", perform a functional cron test.

Inject a message into the cron logging facility with the following command:

$ logger -p cron.info "STIG-TEST-CRON-LOGGING"

Check if it successfully wrote to the dedicated log file with the following command:

$ sudo grep "STIG-TEST-CRON-LOGGING" /var/log/cron
Jul 16 11:33:00 RHEL10Sim pdosadmin[33692]: STIG-TEST-CRON-LOGGING

If "rsyslog" is not logging messages for the cron facility or all facilities, this is a finding.'
  desc 'fix', 'Configure "rsyslog" to log all cron messages by adding or updating the following line to "/etc/rsyslog.conf" or a configuration file in the "/etc/rsyslog.d/" directory:

cron.* /var/log/cron

Restart the rsyslog daemon for the changes to take effect:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag check_id: 'C-61891r1262037_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258150'
  tag rid: 'SV-258150r1268251_rule'
  tag stig_id: 'RHEL-09-652060'
  tag fix_id: 'F-61815r1262038_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  if input('alternative_logging_method') == ''
    rsyslog_config_files = input('logging_conf_files').join(' ')
    active_rsyslog_config = command("grep -hsv '^[[:space:]]*#' #{rsyslog_config_files}").stdout
    # A selector list that includes cron.* (or *.*), sending to /var/log/cron in legacy or RainerScript syntax
    cron_selector = '^\s*(?:\S+;)?(?:cron|\*)\.\*(?:;\S+)?[ \t]+'
    legacy_cron_rule = %r{#{cron_selector}-?/var/log/cron\s*$}i
    rainer_cron_rule = %r{#{cron_selector}action\((?=[^)]*\btype\s*=\s*"omfile")(?=[^)]*\bfile\s*=\s*"/var/log/cron")[^)]*\)\s*$}i

    # DISA's fallback functional test (logger -p cron.info, then grep /var/log/cron) writes to the system
    # logs, so it is not run here; without a config rule the reviewer must perform it manually.
    describe 'Rsyslog cron logging configuration' do
      it 'logs cron events to /var/log/cron' do
        expect(active_rsyslog_config).to match(Regexp.union(legacy_cron_rule, rainer_cron_rule)),
                                         "No active 'cron.*' rule logging to /var/log/cron found in #{rsyslog_config_files}. " \
                                         'If cron events are logged by other means, verify manually with: logger -p cron.info "STIG-TEST-CRON-LOGGING"; ' \
                                         'grep "STIG-TEST-CRON-LOGGING" /var/log/cron'
      end
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
