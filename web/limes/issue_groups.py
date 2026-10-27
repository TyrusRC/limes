"""The Issues page groups the per-asset issue rows (api.views.IssueList) into one row per risk: same source and key."""
ASSET_CAP = 100  # assets listed per group; `count` is the full number


def _status(rows):
    waived = sum(1 for r in rows if r['waiver'])
    if waived == len(rows):
        return 'waived'
    if waived:
        return 'partial'
    return 'expired' if any(r['expired_waiver'] for r in rows) else 'open'


def group(rows):
    """Rows -> groups, worst first: scored before provisional (informational), then severity, then more assets,
    then oldest, then title. `id` is the oldest row's id, the target of the detail link."""
    by = {}
    for r in rows:
        by.setdefault((r['source'], r['key']), []).append(r)
    out = []
    for members in by.values():
        members.sort(key=lambda r: (str(r['first_seen']), r['asset'], r['id']))
        head = members[0]
        epss = [r['epss'] for r in members if r['epss'] is not None]
        out.append({
            'id': head['id'], 'key': head['key'], 'source': head['source'], 'title': head['title'],
            'category': head['category'], 'category_label': head['category_label'], 'severity': max(r['severity'] for r in members),
            'provisional': head['provisional'], 'count': len(members), 'first_seen': head['first_seen'],
            'status': _status(members), 'waived_count': sum(1 for r in members if r['waiver']),
            'note_count': sum(r['note_count'] for r in members), 'kev': any(r['kev'] for r in members),
            'epss': max(epss) if epss else None, 'unwaived_ids': [r['id'] for r in members if not r['waiver']],
            'assets': [{'id': r['id'], 'asset': r['asset'], 'asset_kind': r['asset_kind'], 'first_seen': r['first_seen'],
                        'waiver': r['waiver'], 'expired_waiver': r['expired_waiver']} for r in members[:ASSET_CAP]],
        })
    out.sort(key=lambda g: (g['provisional'], -g['severity'], -g['count'], str(g['first_seen']), g['title']))
    return out
