# Notas do gate — Semana 1
 
## 1.1 Estrutura do CAM-LDS (scenario_3_ssh_puppet)
 
Layout: <cenário>/<host>/{configs,logs,facts.json}
- auth.log:  <host>/logs/log/auth.log
- audit.log: <host>/logs/log/audit/audit.log
- rótulos:   attacker/logs/attackmate.json (+ attackmate.log)
- playbook:  attacker/configs/etc/attackmate.yml
 
| Diretório  | Hostname (facts) | IP              | auth.log | audit.log | Papel provável           |
|------------|------------------|-----------------|----------|-----------|--------------------------|
| attacker   | attacker         | 192.42.1.174    | sim      | não       | origem do ataque          |
| inetfw     | inetfw           | 192.42.0.254    | sim      | sim       | firewall de borda         |
| corpdns    | corpdns          | 192.42.0.233    | sim      | sim       | DNS                       |
| linuxshare | linuxshare       | 192.168.100.23  | sim      | sim       | servidor de arquivos      |
| reposerver | **puppet**       | 172.17.100.122  | sim      | sim       | servidor Puppet           |
| wazuh      | wazuh            | 192.168.100.130 | não      | não       | SIEM (só facts.json)      |
 
Observações:
- Diretório `reposerver` ≠ hostname `puppet`: nos logs aparece como `puppet`.
- `attacker/auth.log` é o log local do atacante — excluir do plano de host.
- Hipótese para o item 1: ATK = 192.42.1.174 (confirmar).
- Backup do playbook datado de 2025-12-12 → captura provavelmente de dez/2025 (confirmar pelo auditd no item 3).

## 1.2 Estrutura do AIT-LDSv2.0 (russellmitchell)
 
Layout: gather/<host>/logs/... · labels/<host>/... (caminho espelhado) · dataset.yaml (metadados)
Outros: environment/ (provisionamento e modelo do testbed), processing/ (logstash), rules/
 
Hosts com auth.log (10 — todos servidores, com rotação auth.log + auth.log.1):
cloud_share, davey_mail, inet-dns, inet-firewall, internal_share,
intranet_server, mail, morris_mail, vpn, webserver
 
Sem auth.log (13 — clientes/simuladores e atacante):
attacker_0, ext_user_0..2, internal_employee_0..3, remote_employee_0..2, monitoring
 
Hosts com rótulos de ataque (5): inet-firewall, internal_share, intranet_server, monitoring, vpn
→ interseção com auth.log (4): inet-firewall, internal_share, intranet_server, vpn
→ só nesses 4 pode haver linha de auth.log rotulada (verificar no item 5)
 
Observações:
- Unidade de medida de FP: host-dia sobre os 10 servidores com auth.log.
- `monitoring` tem rótulos sem auth.log → provável log de rede/IDS (verificar no item 5b).
- `attacker_0` excluído dos parsers (prefixo "attacker").
- dataset.yaml: janela de captura 2022-01-21T00:00:00 → 2022-01-25T00:00:00
  (4 dias, ano 2022; o horário não traz fuso)
- labels (tipos de log rotulados por host):
  - inet-firewall:   dnsmasq.log
  - internal_share:  audit/audit.log
  - intranet_server: auth.log, audit/audit.log, apache2 (access e error, rotação .2)
  - monitoring:      logstash/.../system.cpu.log (métrica de CPU)
  - vpn:             openvpn.log
  → auth.log rotulado APENAS em intranet_server
    → exclusão da classe benigna restrita a esse host
- inet-firewall/logs contém suricata/, kern.log, shorewall-init.log, journal/
  → evidência de plano de rede na classe benigna

  ## Item 1 — falhas do hydra com IP e usuário — ✅ APROVADO
 
Evidência:
  Dec 12 10:28:22 puppet sshd[3566]: Invalid user admin from 192.42.1.174 port 40674
  Dec 12 10:28:24 puppet sshd[3568]: Failed password for invalid user admin from 192.42.1.174 port 40682 ssh2
 
- ATK = 192.42.1.174 (= host attacker do facts.json; hipótese do 1.1 confirmada)
- Alvo = puppet (dir reposerver, 172.17.100.122) — único host com falhas
- 49 failed + 24 invalid_user, 100% de ATK, nas 3 variantes somadas
  - por variante (apt / healthcheck / puppet): __ / __ / __
- Usuários tentados: admin (21), root (15), john (13)
- Prévia do item 2: 6 accepted de ATK; john tem 6 accepted → provável login do atacante como john
 
Achados adicionais:
- Formatos mistos no CAM-LDS: ISO 8601 +00:00 (attacker, linuxshare) × syslog sem ano/fuso
  (puppet, corpdns, inetfw). Alvo em syslog → fuso a confirmar no item Extra.
- Ano = 2025 (linhas ISO: 2025-12-11 e 2025-12-12). Captura em 11–12/dez/2025.
- Tráfego SSH benigno de automação: usuário aecid, 47 accepted, de IPs .201 de cada sub-rede.
  Só sucessos, sem falhas → não afeta FP, mas precisa ser declarado no texto.
- Mensagens não classificadas: só PAM redundante e eventos de sessão; nenhuma variante
  de Failed/Accepted escapou das regras.