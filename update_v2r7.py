#!/usr/bin/env python3
"""
Update RHEL 9 STIG InSpec controls to V2R7 XCCDF.

- Updates 146 controls that have metadata diffs (rid, fix_id, cci, descriptions)
- Creates SV-279936.rb (new XCCDF rule with no .rb file)
- Adds host/container tags to 9 controls missing them
- Leaves 7 extra controls (not in XCCDF) untouched
- Preserves all InSpec test logic (only_if, describe blocks, etc.)

Usage:
  python3 update_v2r7.py [--dry-run] [--sv SV-XXXXX]
"""

import xml.etree.ElementTree as ET
import re
import sys
from pathlib import Path

XCCDF_PATH = Path('/home/chadd/dev/stigs/redhat-enterprise-linux-9-stig-baseline/baseline/U_RHEL_9_STIG_V2R7_Manual-xccdf.xml')
CONTROLS_DIR = Path('/home/chadd/dev/stigs/redhat-enterprise-linux-9-stig-baseline/controls')
NS = {'xccdf': 'http://checklists.nist.gov/xccdf/1.1'}

SEVERITY_TO_IMPACT = {'high': 0.7, 'medium': 0.5, 'low': 0.3, 'critical': 1.0}

# .rb files that exist but are not in the V2R7 XCCDF — leave untouched
EXTRA_CONTROLS = {
    'SV-257987', 'SV-257988', 'SV-258062', 'SV-258076',
    'SV-258172', 'SV-258226', 'SV-258237'
}


# ---------------------------------------------------------------------------
# Ruby string helpers
# ---------------------------------------------------------------------------

def ruby_escape(text: str) -> str:
    """Escape text for a Ruby single-quoted string."""
    return text.replace('\\', '\\\\').replace("'", "\\'")


def scan_string_end(s: str, pos: int) -> int:
    """
    Given s with pos pointing to an opening string delimiter,
    return position just after the closing delimiter.
    Handles: 'string', "string", %q(string).
    """
    if s[pos:pos + 3] == '%q(':
        depth = 1
        i = pos + 3
        while i < len(s) and depth > 0:
            if s[i] == '(':
                depth += 1
            elif s[i] == ')':
                depth -= 1
            i += 1
        return i

    if s[pos] == "'":
        i = pos + 1
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s) and s[i + 1] in ("'", '\\'):
                i += 2
                continue
            if s[i] == "'":
                return i + 1
            i += 1
        return len(s)

    if s[pos] == '"':
        i = pos + 1
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                i += 2
                continue
            if s[i] == '"':
                return i + 1
            i += 1
        return len(s)

    # Fallback: treat as end-of-line
    end = s.find('\n', pos)
    return end if end != -1 else len(s)


def replace_string_after(content: str, pattern: str, new_value: str,
                         flags: int = re.MULTILINE) -> tuple:
    """
    Find regex pattern and replace the Ruby string immediately following it.
    Returns (new_content, changed: bool).
    """
    m = re.search(pattern, content, flags)
    if not m:
        return content, False

    pos = m.end()
    while pos < len(content) and content[pos] in (' ', '\t'):
        pos += 1

    if pos >= len(content):
        return content, False

    str_end = scan_string_end(content, pos)
    escaped = ruby_escape(new_value)
    return content[:pos] + f"'{escaped}'" + content[str_end:], True


# ---------------------------------------------------------------------------
# Per-field updaters
# ---------------------------------------------------------------------------

def update_tag_line(content: str, tag_name: str, new_value: str) -> str:
    """Replace a single-line string tag: tag NAME: 'VALUE'"""
    pattern = rf'^  tag {re.escape(tag_name)}: \'.*?\''
    return re.sub(pattern, f"  tag {tag_name}: '{new_value}'", content,
                  flags=re.MULTILINE)


def update_impact(content: str, new_impact: float) -> str:
    return re.sub(r'^  impact \S+$', f'  impact {new_impact}',
                  content, flags=re.MULTILINE)


def update_cci_tag(content: str, new_ccis: list) -> str:
    """Replace CCI array; handles single-line arrays."""
    cci_str = '[' + ', '.join(f"'{c}'" for c in new_ccis) + ']'
    # Match single-line array (no newline inside brackets)
    return re.sub(r'^  tag cci: \[[^\]]*\]$', f'  tag cci: {cci_str}',
                  content, flags=re.MULTILINE)


def update_title(content: str, new_title: str) -> str:
    result, _ = replace_string_after(content, r'^  title ', new_title)
    return result


def update_main_desc(content: str, new_desc: str) -> str:
    """Update main desc block (not check/fix). Opens with '  desc '...'"""
    # Pattern matches '  desc '' where the char after ' is NOT 'check or 'fix
    m = re.search(r"^  desc '(?!check'|fix')", content, re.MULTILINE)
    if not m:
        return content
    # m.end()-1 is the position of the opening quote
    str_start = m.end() - 1
    str_end = scan_string_end(content, str_start)
    return content[:str_start] + f"'{ruby_escape(new_desc)}'" + content[str_end:]


def update_named_desc(content: str, key: str, new_value: str) -> str:
    """Update desc 'check' or desc 'fix' block."""
    pattern = rf"^  desc '{re.escape(key)}',\s*"
    result, found = replace_string_after(content, pattern, new_value)
    return result


def update_check_id(content: str, new_check_id: str) -> str:
    """Update check_id tag only if it already exists in the file."""
    if not new_check_id:
        return content
    existing = re.search(r"^  tag check_id: '.*?'$", content, re.MULTILINE)
    if existing:
        return re.sub(r"^  tag check_id: '.*?'$",
                      f"  tag check_id: '{new_check_id}'",
                      content, flags=re.MULTILINE)
    return content  # don't add if not present — preserve existing format


def update_satisfies(content: str, satisfies: list) -> str:
    """Update satisfies tag if present and list differs."""
    if not satisfies:
        return content
    sat_str = '[' + ', '.join(f"'{s}'" for s in satisfies) + ']'
    existing = re.search(r"^  tag satisfies: \[.*?\]$", content,
                         re.MULTILINE | re.DOTALL)
    if existing:
        return re.sub(r"^  tag satisfies: \[.*?\]$",
                      f"  tag satisfies: {sat_str}",
                      content, flags=re.MULTILINE | re.DOTALL)
    return content


# ---------------------------------------------------------------------------
# XCCDF parsing
# ---------------------------------------------------------------------------

def parse_xccdf() -> dict:
    tree = ET.parse(XCCDF_PATH)
    root = tree.getroot()
    rules = {}

    for group in root.findall('.//xccdf:Group', NS):
        gid = group.get('id', '')
        gtitle_el = group.find('xccdf:title', NS)
        gtitle = (gtitle_el.text or '').strip() if gtitle_el is not None else ''

        for rule in group.findall('xccdf:Rule', NS):
            full_rid = rule.get('id', '')
            m = re.match(r'(SV-\d+)r', full_rid)
            if not m:
                continue
            sv_id = m.group(1)

            ver_el = rule.find('xccdf:version', NS)
            stig_id = (ver_el.text or '').strip() if ver_el is not None else ''

            title_el = rule.find('xccdf:title', NS)
            title = (title_el.text or '').strip() if title_el is not None else ''

            severity = rule.get('severity', 'medium')

            desc_el = rule.find('xccdf:description', NS)
            main_desc, satisfies = '', []
            if desc_el is not None and desc_el.text:
                mv = re.search(r'<VulnDiscussion>(.*?)</VulnDiscussion>',
                               desc_el.text, re.DOTALL)
                if mv:
                    main_desc = mv.group(1).strip()
                satisfies = re.findall(r'<SatisfiesRef>(.*?)</SatisfiesRef>',
                                       desc_el.text)

            cc_el = rule.find('.//xccdf:check-content', NS)
            check_content = (cc_el.text or '').strip() if cc_el is not None else ''

            check_el = rule.find('xccdf:check', NS)
            check_id = check_el.get('system', '') if check_el is not None else ''

            fix_el = rule.find('xccdf:fixtext', NS)
            fix_content = (fix_el.text or '').strip() if fix_el is not None else ''
            fix_id = fix_el.get('fixref', '') if fix_el is not None else ''

            ccis = [i.text for i in rule.findall('xccdf:ident', NS) if i.text]

            rules[sv_id] = {
                'full_rid': full_rid,
                'gid': gid,
                'gtitle': gtitle,
                'stig_id': stig_id,
                'title': title,
                'severity': severity,
                'impact': SEVERITY_TO_IMPACT.get(severity, 0.5),
                'main_desc': main_desc,
                'satisfies': satisfies,
                'check_content': check_content,
                'check_id': check_id,
                'fix_content': fix_content,
                'fix_id': fix_id,
                'ccis': ccis,
            }

    return rules


# ---------------------------------------------------------------------------
# Per-file update logic
# ---------------------------------------------------------------------------

def needs_update(content: str, xr: dict) -> bool:
    """True if any metadata tag in the .rb differs from XCCDF."""
    rid_m = re.search(r"tag rid: '(.*?)'", content)
    if not rid_m or rid_m.group(1) != xr['full_rid']:
        return True

    fix_m = re.search(r"tag fix_id: '(.*?)'", content)
    if not fix_m or fix_m.group(1) != xr['fix_id']:
        return True

    cci_m = re.search(r"tag cci: \[([^\]]*)\]", content)
    current_ccis = sorted(re.findall(r"'(CCI-\d+)'", cci_m.group(1))) if cci_m else []
    if current_ccis != sorted(xr['ccis']):
        return True

    return False


def update_control(rb_path: Path, xr: dict, dry_run: bool = False) -> bool:
    """
    Update a single control file. Returns True if the file was changed.
    Preserves all InSpec test logic.
    """
    content = rb_path.read_text()
    original = content

    # --- Single-line tag updates ---
    content = update_tag_line(content, 'rid', xr['full_rid'])
    content = update_tag_line(content, 'gid', xr['gid'])
    content = update_tag_line(content, 'stig_id', xr['stig_id'])
    content = update_tag_line(content, 'fix_id', xr['fix_id'])
    content = update_tag_line(content, 'severity', xr['severity'])
    content = update_tag_line(content, 'gtitle', xr['gtitle'])
    content = update_impact(content, xr['impact'])
    content = update_cci_tag(content, xr['ccis'])
    content = update_check_id(content, xr['check_id'])
    content = update_satisfies(content, xr['satisfies'])

    # --- Description block updates ---
    if xr['title']:
        content = update_title(content, xr['title'])
    if xr['main_desc']:
        content = update_main_desc(content, xr['main_desc'])
    if xr['check_content']:
        content = update_named_desc(content, 'check', xr['check_content'])
    if xr['fix_content']:
        content = update_named_desc(content, 'fix', xr['fix_content'])

    if content == original:
        return False

    if not dry_run:
        rb_path.write_text(content)
    return True


# ---------------------------------------------------------------------------
# Host/container tag enforcement
# ---------------------------------------------------------------------------

def ensure_host_container_tags(rb_path: Path, xccdf_rules: dict,
                                dry_run: bool = False) -> bool:
    """
    Add host/container tag(s) to controls missing them.
    Infers correct tag from existing only_if logic.
    Returns True if the file was changed.
    """
    content = rb_path.read_text()
    sv_id = rb_path.stem

    has_host = bool(re.search(r"^  tag 'host'$", content, re.MULTILINE))
    has_container = bool(re.search(r"^  tag 'container'$", content, re.MULTILINE))
    has_cc = bool(re.search(r"^  tag 'container-conditional'$", content, re.MULTILINE))

    if has_host or has_container or has_cc:
        return False

    # Infer tag: if there's a docker only_if skip it's host-only, else both
    has_docker_skip = "!virtualization.system.eql?('docker')" in content
    if has_docker_skip:
        new_tags = "  tag 'host'"
    else:
        new_tags = "  tag 'host'\n  tag 'container'"

    # Insert after last tag nist: line, else after last tag line
    nist_m = None
    for m in re.finditer(r"^  tag nist: \[.*?\]$", content, re.MULTILINE):
        nist_m = m
    if nist_m:
        insert_pos = nist_m.end()
    else:
        last_tag = None
        for m in re.finditer(r"^  tag .*$", content, re.MULTILINE):
            last_tag = m
        if not last_tag:
            return False
        insert_pos = last_tag.end()

    new_content = content[:insert_pos] + '\n' + new_tags + content[insert_pos:]

    if not dry_run:
        rb_path.write_text(new_content)
    return True


# ---------------------------------------------------------------------------
# New control: SV-279936
# ---------------------------------------------------------------------------

def create_sv279936(xr: dict, dry_run: bool = False) -> None:
    rb_path = CONTROLS_DIR / 'SV-279936.rb'
    if rb_path.exists():
        print(f'  SV-279936.rb already exists — skipping')
        return

    nist = ['AU-12 c']

    content = f"""control 'SV-279936' do
  title '{ruby_escape(xr['title'])}'
  desc '{ruby_escape(xr['main_desc'])}'
  desc 'check', '{ruby_escape(xr['check_content'])}'
  desc 'fix', '{ruby_escape(xr['fix_content'])}'
  impact {xr['impact']}
  tag check_id: '{xr['check_id']}'
  tag severity: '{xr['severity']}'
  tag gid: '{xr['gid']}'
  tag rid: '{xr['full_rid']}'
  tag stig_id: '{xr['stig_id']}'
  tag gtitle: '{xr['gtitle']}'
  tag fix_id: '{xr['fix_id']}'
  tag cci: [{', '.join(f"'{c}'" for c in xr['ccis'])}]
  tag nist: [{', '.join(f"'{n}'" for n in nist)}]
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {{
    !virtualization.system.eql?('docker')
  }}

  cron_paths = ['/etc/cron.d', '/var/spool/cron']
  audit_key = 'cronjobs'

  cron_paths.each do |cron_path|
    describe auditd do
      its('lines') {{ should include(/-w #{{cron_path}}[/]? -p wa -k #{{audit_key}}/) }}
    end
  end
end
"""

    action = '[DRY-RUN] Would create' if dry_run else 'Creating'
    print(f'  {action} SV-279936.rb (RHEL-09-654097 — audit cron scripts)')
    if not dry_run:
        rb_path.write_text(content)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    dry_run = '--dry-run' in sys.argv
    target_sv = next((a for a in sys.argv[1:] if a.startswith('SV-')), None)

    if dry_run:
        print('[DRY-RUN — no files will be written]\n')

    print('Parsing XCCDF V2R7...')
    xccdf_rules = parse_xccdf()
    print(f'  {len(xccdf_rules)} rules loaded\n')

    rb_files = sorted(CONTROLS_DIR.glob('SV-*.rb'))
    if target_sv:
        rb_files = [f for f in rb_files if f.stem == target_sv]

    updated, unchanged, skipped, tag_added, errors = [], [], [], [], []

    for rb_path in rb_files:
        sv_id = rb_path.stem

        if sv_id in EXTRA_CONTROLS:
            skipped.append(sv_id)
            continue

        if sv_id not in xccdf_rules:
            skipped.append(sv_id)
            continue

        xr = xccdf_rules[sv_id]
        content = rb_path.read_text()

        try:
            if needs_update(content, xr):
                changed = update_control(rb_path, xr, dry_run=dry_run)
                if changed:
                    updated.append(sv_id)
                    action = '[DRY-RUN] Would update' if dry_run else 'Updated'
                    print(f'  {action} {sv_id}')
                else:
                    unchanged.append(sv_id)
            else:
                unchanged.append(sv_id)

            if ensure_host_container_tags(rb_path, xccdf_rules, dry_run=dry_run):
                tag_added.append(sv_id)
                action = '[DRY-RUN] Would add tag to' if dry_run else 'Added host/container tag to'
                print(f'  {action} {sv_id}')

        except Exception as e:
            errors.append((sv_id, str(e)))
            print(f'  ERROR {sv_id}: {e}')

    # Create SV-279936
    if not target_sv or target_sv == 'SV-279936':
        if 'SV-279936' in xccdf_rules:
            create_sv279936(xccdf_rules['SV-279936'], dry_run=dry_run)

    print(f'\n{"="*60}')
    print(f'SUMMARY {"(DRY-RUN)" if dry_run else ""}')
    print(f'  Metadata updated:          {len(updated)}')
    print(f'  Host/container tag added:  {len(tag_added)}')
    print(f'  No change needed:          {len(unchanged)}')
    print(f'  Skipped (not in XCCDF):   {len(skipped)}')
    print(f'  Errors:                    {len(errors)}')
    if errors:
        print()
        for sv, err in errors:
            print(f'    {sv}: {err}')


if __name__ == '__main__':
    main()
