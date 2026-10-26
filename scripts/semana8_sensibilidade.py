"""Sensibilidade isolada: mesmo motor, somente janela dos contadores variável."""
import argparse
import copy
import csv
import hashlib
import json
import platform
import subprocess
from pathlib import Path

from motor.detect import build, preflight, verify as verify_detector
from motor.alerts import MODES
from motor.run import read_lines, save_json, save_lines

WINDOWS = (60, 300, 600)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def variants(core, cfg, seconds):
    if type(seconds) is not int or seconds not in WINDOWS:
        raise ValueError('Janela fora da grade registrada')
    if core['window_ns'] != 300_000_000_000 or cfg['window_ns'] != core['window_ns']:
        raise ValueError('Base nao corresponde a 300 s')
    if cfg['critical_horizon_ns'] != 300_000_000_000:
        raise ValueError('Horizonte critico divergente')
    a, b = copy.deepcopy(core), copy.deepcopy(cfg)
    a['window_ns'] = b['window_ns'] = seconds * 1_000_000_000
    return a, b


def run(root, baseline, out):
    if out.exists():
        raise ValueError('Destino ja existe: preservar e usar pasta nova')
    if root not in out.parents:
        raise ValueError('Saida deve estar no projeto')
    if subprocess.check_output(['git','-C',str(root),'status','--porcelain']).strip():
        raise ValueError('Commitar protocolo, executor e testes antes da campanha')
    verify_detector(baseline)
    cfg, core, rows, hits, ref = preflight(root, root/'config/motor-semana5.json')
    for local, expected in [('config.json',cfg),('core_config.json',core)]:
        if json.loads((baseline/local).read_text()) != expected:
            raise ValueError(f'Base Semana 7 divergente: {local}')
    if read_lines(baseline/'events.jsonl') != rows:
        raise ValueError('Eventos da base divergentes')
    out.mkdir(parents=True)
    save_json(out/'base-core.json',core)
    save_json(out/'base-detector.json',cfg)
    save_lines(out/'events.jsonl',rows)
    save_lines(out/'base_hits.jsonl',hits)
    # Dados de qualidade conservam seus próprios denominadores.
    quality = json.loads((ref/'summary.json').read_text())
    nets = [r for r in rows if r['kind']=='net']
    quality['selected_network_rows'] = len(nets)
    quality['selected_network_missing_duration'] = sum(r['duration'] is None for r in nets)
    save_json(out/'qualidade.json',quality)
    all_results = {}
    for seconds in WINDOWS:
        a,b = variants(core,cfg,seconds)
        folder=out/f'w{seconds:03d}'; folder.mkdir()
        save_json(folder/'core.json',a); save_json(folder/'detector.json',b)
        result=build(rows,a,b,MODES)
        save_json(folder/'result.json',result)
        all_results[seconds]=result
    # Comparar a estrutura completa, incluindo trace, sem exigir hash igual por formatação.
    for name,value in all_results[300].items():
        path=baseline/(name+'.json' if name in ('summary','comparison') else name+'.jsonl')
        expected=json.loads(path.read_text()) if path.suffix=='.json' else read_lines(path)
        if value != expected:
            raise ValueError(f'Ancora 300 s divergente: {name}')
    fields=['window_s','unit_id','mode','alerts_opened','any_alert_opened','users','first_open_ns','metrics_enabled']
    with (out/'comparacao.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for seconds,result in all_results.items():
            for row in result['comparison']:
                w.writerow({'window_s':seconds,**{k:json.dumps(row[k]) if isinstance(row[k],list) else row[k] for k in fields[1:]}})
    files=list((root/'src/motor').glob('*.py'))+[Path(__file__).resolve(),root/'docs/protocolo-semana8.md',root/'tests/test_semana8.py']
    files += [root/'config/motor-semana4.json',root/'config/motor-semana5.json']
    files += list((root/'rules/sigma').glob('*.yml'))
    manifest={'contract':'semana8_sensibilidade_v1','windows_s':list(WINDOWS),
              'primary_window_s':300,'metrics_enabled':False,'python':platform.python_version(),
              'git_head':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),
              'sources':{str(p.relative_to(root)):sha(p) for p in sorted(files)},
              'baseline_manifest_sha256':sha(baseline/'manifest.json'),'baseline':str(baseline),
              'reference_manifest_sha256':sha(ref/'manifest.json'),
              'outputs':{str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()}}
    save_json(out/'manifest.json',manifest)
    verify(root,out)
    (out/'SUCCESS').write_text('semana8: sensibilidade conferida; metricas desabilitadas\n')


def verify(root,out):
    m=json.loads((out/'manifest.json').read_text())
    if m['contract']!='semana8_sensibilidade_v1' or m['windows_s']!=list(WINDOWS) or m['metrics_enabled'] is not False:
        raise ValueError('Contrato de sensibilidade divergente')
    for name,digest in m['sources'].items():
        if sha(root/name)!=digest: raise ValueError(f'Fonte alterada: {name}')
    for name,digest in m['outputs'].items():
        if sha(out/name)!=digest: raise ValueError(f'Saida alterada: {name}')
    baseline=Path(m['baseline'])
    if sha(baseline/'manifest.json')!=m['baseline_manifest_sha256']:
        raise ValueError('Manifesto base alterado')
    verify_detector(baseline)
    core=json.loads((out/'base-core.json').read_text())
    cfg=json.loads((out/'base-detector.json').read_text())
    if core != json.loads((baseline/'core_config.json').read_text()) or cfg != json.loads((baseline/'config.json').read_text()):
        raise ValueError('Configuracoes base divergentes')
    rows=read_lines(out/'events.jsonl')
    if rows != read_lines(baseline/'events.jsonl'): raise ValueError('Eventos divergentes')
    for seconds in WINDOWS:
        a,b=variants(core,cfg,seconds); folder=out/f'w{seconds:03d}'
        if json.loads((folder/'core.json').read_text())!=a or json.loads((folder/'detector.json').read_text())!=b:
            raise ValueError('Alteracao alem da janela')
        result=build(rows,a,b,MODES)
        if result!=json.loads((folder/'result.json').read_text()): raise ValueError('Replay divergente')
        if seconds==300:
            for name,value in result.items():
                path=baseline/(name+'.json' if name in ('summary','comparison') else name+'.jsonl')
                expected=json.loads(path.read_text()) if path.suffix=='.json' else read_lines(path)
                if value!=expected: raise ValueError(f'Ancora divergente: {name}')
    print('OK: hashes, variacao exclusiva da janela, replay e ancora 300 s.')


def main():
    p=argparse.ArgumentParser()
    p.add_argument('command',choices=['run','verify'])
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--baseline',type=Path)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    if a.command=='run':
        if a.baseline is None: p.error('--baseline obrigatorio para run')
        run(a.root.resolve(),a.baseline.resolve(),a.out.resolve())
    else: verify(a.root.resolve(),a.out.resolve())


if __name__=='__main__': main()
