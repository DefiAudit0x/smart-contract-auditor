import json
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parent
report = json.loads((root / 'metadata/selfdestruct_compatibility_measurement.json').read_text(encoding='utf-8'))
by_version = defaultdict(list)
for row in report['rows']:
    by_version[row['version_family']].append(row)

print('version,fixture,historical_compiler_status,ast_keywords,raw_ast_keywords,analyzer_selfdestruct,comparator')
for version in sorted(by_version):
    for row in sorted(by_version[version], key=lambda item: item['fixture']):
        historical = row['historical_compiler']
        print(','.join([
            version,
            row['fixture'],
            historical['status'],
            '+'.join(historical.get('ast_keywords', [])) or '-',
            '+'.join(historical.get('raw_ast_keywords', [])) or '-',
            'HIT' if row['current_analyzer']['selfdestruct_detector'] else 'MISS',
            row['current_comparator']['status'],
        ]))

print('\nAGGREGATES')
for version in sorted(by_version):
    rows = by_version[version]
    print(version, 'compiled=', sum(r['historical_compiler']['status'] == 'compiled' for r in rows), 'compile_failed=', sum(r['historical_compiler']['status'] == 'compile_failed' for r in rows), 'analyzer_hits=', sum(r['current_analyzer']['selfdestruct_detector'] for r in rows), 'comparator_confirmed=', sum(r['current_comparator']['status'] == 'Confirmed' for r in rows), 'comparator_rejected=', sum(r['current_comparator']['status'] == 'Rejected' for r in rows))
