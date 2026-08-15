import json
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parent
report = json.loads((root / 'metadata/cross_detector_compatibility_measurement.json').read_text(encoding='utf-8'))
rows = report['rows']
print('detector,version,form,compiler,raw_ast,normalized_ast,detector,comparator')
for row in rows:
    print(','.join([
        row['detector'],
        row['version_family'],
        row['raw_source']['form'],
        row['historical_compiler']['status'],
        '+'.join(row['historical_compiler'].get('raw_ast_keywords', [])) or '-',
        'normalized' if row['normalized_ast']['status'] == 'normalized' and any(row['normalized_ast']['signals'].values()) else row['normalized_ast']['status'],
        'HIT' if row['current_detector']['target_hit'] else 'MISS',
        row['comparator']['status'],
    ]))

print('\nAGGREGATES')
by_detector = defaultdict(list)
for row in rows:
    by_detector[row['detector']].append(row)
for detector, detector_rows in by_detector.items():
    print(detector)
    for form in ('canonical', 'legacy', 'fixed'):
        subset = [r for r in detector_rows if r['raw_source']['form'] == form]
        print(' ', form, 'compiled=', sum(r['historical_compiler']['status'] == 'compiled' for r in subset), 'normalized_signal=', sum(r['normalized_ast']['status'] == 'normalized' and any(r['normalized_ast']['signals'].values()) for r in subset), 'detector_hits=', sum(r['current_detector']['target_hit'] for r in subset), 'comparator_confirmed=', sum(r['comparator']['status'] == 'Confirmed' for r in subset), 'comparator_rejected=', sum(r['comparator']['status'] == 'Rejected' for r in subset))
