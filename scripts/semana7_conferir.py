import argparse
import csv
import hashlib
import json
from pathlib import Path


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def lines(path):
    return [json.loads(s) for s in path.read_text(encoding='utf-8').splitlines() if s.strip()]


def canonical(rows):
    return sorted(json.dumps(r, sort_keys=True, ensure_ascii=False) for r in rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--campaign', required=True, type=Path)
    args = parser.parse_args()
    root, campaign = args.root.resolve(), args.campaign.resolve()
    frozen = read_json(campaign / 'freeze.json')
    for name, digest in frozen['sha256'].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Fonte/configuracao alterada: {name}')
    reference = root / 'out/semana5/execucao-20261021T020309Z'
    outputs = ['alerts', 'transitions', 'decisions', 'critical_checks']
    for mode in ['B1', 'B2', 'B3', 'all']:
        p = campaign / mode
        if not (p / 'SUCCESS').is_file():
            raise ValueError(f'SUCCESS ausente: {mode}')
        manifest = read_json(p / 'manifest.json')
        for name, digest in manifest['outputs_sha256'].items():
            if hashlib.sha256((p / name).read_bytes()).hexdigest() != digest:
                raise ValueError(f'Saida alterada: {mode}/{name}')
        if manifest['git_head'] != frozen['git_head']:
            raise ValueError(f'Commit divergente: {mode}')
        for name, digest in manifest['sources_sha256'].items():
            if frozen['sha256'].get(name) != digest:
                raise ValueError(f'Fonte divergente no manifesto: {mode}/{name}')
        if manifest['config_sha256'] != frozen['sha256']['config/motor-semana5.json']:
            raise ValueError(f'Configuracao divergente: {mode}')
    for name in outputs:
        joint = lines(campaign / 'all' / f'{name}.jsonl')
        if canonical(joint) != canonical(lines(reference / f'{name}.jsonl')):
            raise ValueError(f'Divergencia da referencia: {name}')
        for mode in ['B1', 'B2', 'B3']:
            selected = [r for r in joint if r['mode'] == mode]
            if canonical(selected) != canonical(lines(campaign / mode / f'{name}.jsonl')):
                raise ValueError(f'Divergencia separado/conjunto: {mode}/{name}')
    comparison = read_json(campaign / 'all/comparison.json')
    if canonical(comparison) != canonical(read_json(reference / 'comparison.json')):
        raise ValueError('Unidades divergentes da referencia')
    for mode in ['B1', 'B2', 'B3']:
        if canonical([r for r in comparison if r['mode'] == mode]) != canonical(read_json(campaign / mode / 'comparison.json')):
            raise ValueError(f'Comparacao divergente: {mode}')
    if any(r['metrics_enabled'] is not False for r in comparison):
        raise ValueError('Metricas habilitadas indevidamente')
    destination = campaign / 'conferencia'
    destination.mkdir(exist_ok=False)
    fields = ['unit_id', 'classification', 'mode', 'any_alert_opened', 'alerts_opened', 'users', 'first_open_ns', 'alert_ids', 'metrics_enabled']
    with (destination / 'unidades.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in comparison:
            writer.writerow({k: json.dumps(row[k], ensure_ascii=False) if isinstance(row[k], list) else row[k] for k in fields})
    alerts = lines(campaign / 'all/alerts.jsonl')
    fields = ['id', 'mode', 'dataset', 'host', 'source_ip', 'user', 'opened_ns', 'ended_ns', 'trigger_Nh', 'trigger_Nn', 'score', 'critical', 'end_reason']
    with (destination / 'episodios.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in alerts: writer.writerow({k: row[k] for k in fields})
    result = {'equivalence': True, 'reference': str(reference), 'units_rows': len(comparison),
              'alerts': len(alerts), 'independent_new_samples': 0, 'metrics_enabled': False}
    (destination / 'resultado.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()