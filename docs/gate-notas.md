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

  ## Item 3 — evidência de corroboração encontrada. 
  No arquivo de auditoria selecionado do alvo reposerver (hostname puppet), foram encontrados 26 registros USER_AUTH, dos quais 16 apresentam res=failed. Todas as 16 falhas têm addr=192.42.1.174. O registro do PID 3610, conta admin, corresponde em PID, usuário e IP à falha observada no auth.log. Seu timestamp equivale a 2025-12-12 12:42:34.368 UTC; o auth.log registra 12:42:35, sem fuso explícito. Pendências: comparar a contagem com o auth.log da mesma variante e concluir a validação do fuso no item Extra.
  Ano confirmado para o CAM-LDS, variante puppet: **2025**.

Evidência: o timestamp Unix do primeiro registro USER_AUTH do atacante foi convertido para **2025-12-12 12:42:34 UTC**.
Na Semana 2, utilizar **`--year 2025`** no parser de `auth.log` dessa base, pois suas linhas syslog não informam o ano.

## Item 4
**Item 4 — timestamps e identificação dos passos do ataque**

**Estado:** parcialmente atendido. Foram identificados timestamps de início e metadados ATT&CK dos passos relevantes. A identificação dos términos permanece pendente.

**Fonte:** `$CAM/attacker/logs/attackmate.json`, da variante `scenario_3_ssh_puppet`. O arquivo apresenta objetos JSON por linha, com o campo `start-datetime`.

| Passo registrado | Início em `start-datetime` | IDs ATT&CK informados pela base |
|---|---|---|
| Força bruta SSH com `hydra`, direcionada a `fw.attackbed.com:10022` | `2025-12-12T12:42:33.203732` | `T1078.002`, `T1110.001`, `T1133` |
| Passo SSH configurado com usuário `john` e comando `id` | `2025-12-12T12:42:54.103696` | `T1078.003` |
| Passo posterior com comando de captura de tráfego | `2025-12-12T12:43:10.379478` | `T1040` |

**Correspondência dos IDs no MITRE ATT&CK:**

- [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/).
- [T1133 — External Remote Services](https://attack.mitre.org/techniques/T1133/).
- [T1078.002 — Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/).
- [T1078.003 — Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/).
- [T1040 — Network Sniffing](https://attack.mitre.org/techniques/T1040/).

**Inconsistência nos metadados:** o passo do `hydra` contém o ID `T1078.002`, mas seu campo `technique_name` menciona “Local Accounts”, correspondente a `T1078.003`. Os IDs acima foram preservados conforme a fonte; a divergência está registrada para revisão da rotulagem.

**Limites e pendências:**

- Os timestamps não incluem fuso explícito; o alinhamento com `auditd` e `auth.log` será verificado no item Extra.
- Não foi identificado um campo de término na saída inspecionada. O início do passo seguinte não será tratado automaticamente como término do anterior.
- O início do passo SSH com `john` deve ser confrontado com o evento `Accepted` do alvo para confirmar o sucesso e seu horário.
- O ataque utiliza a porta `10022` no endereço externo. No item 7, verificar o encaminhamento para o alvo e as portas visíveis no PCAP antes de aplicar filtros restritos à porta `22`.
**Conferência complementar do item 4 — `attackmate.log`**

O log textual confirma os inícios registrados no JSON: execução do `hydra` em 2025-12-12 às 12:42:33 e início do passo SSH `id` às 12:42:54. Os horários não apresentam fuso explícito.

O trecho inspecionado não contém mensagens explícitas de término ou códigos de saída desses dois passos. Assim, o intervalo entre seus inícios não foi interpretado como duração exata da força bruta. A limpeza de sessões às 12:56:16 pertence ao encerramento do roteiro mais amplo, não ao término específico do ataque SSH.

O item permanece parcialmente atendido: os passos e seus inícios são identificáveis; falta verificar a configuração da sequência e confrontar o passo SSH com o evento de autenticação aceita no alvo.
**Consolidação dos itens 2, 3 e 4 — CAM-LDS, variante puppet**

**Item 2 — aprovado.** Foram encontrados dois eventos `Accepted password` para `john`, com origem `192.42.1.174`, às 12:42:37 e 12:42:55 de 12/12/2025. Existem falhas anteriores para o mesmo IP e usuário. O primeiro sucesso ocorre antes da última falha observada, às 12:42:39.

**Item 3 — aprovado.** O `auth.log` apresenta 16 falhas: 7 para `admin`, 5 para `root` e 4 para `john`. O total coincide com os 16 registros `USER_AUTH` com `res=failed` no arquivo de auditoria selecionado, todos provenientes do atacante.

**Item 4 — parcialmente atendido.** Os inícios do `hydra` e do passo SSH `id` estão identificados no AttackMate. O término exato desses passos não foi demonstrado. O arquivo `attacker/configs/etc/attackmate.yml` inspecionado contém configurações globais, incluindo `command_delay: 15`, sem a lista de passos.

**Risco para o CP1:** com chave `(source.ip, user.name)` e `θh = 5`, o usuário `john` não atinge o limiar, apesar dos dois sucessos. As falhas de usuários diferentes não devem ser somadas para satisfazer uma regra definida por par. A demonstração do indicador de criticidade na configuração padrão permanece limitada nesta variante.

**Contagem de rede:** foram observadas falhas repetidas para o mesmo PID e porta de origem. Não interpretar as 16 falhas como 16 conexões distintas.

**Relógios:** o ano 2025 foi confirmado pelo `auditd`; o fuso do `auth.log` e do AttackMate permanece sujeito à validação do item Extra.
**Item 5 — análise preliminar do AIT-LDSv2.0, testbed russellmitchell**

O script reconheceu **6.818 linhas syslog**, incluindo **130 linhas do sshd**. Foram contabilizadas **29 autenticações aceitas** — 23 para `ait` e 6 para `jhall` —, **nenhuma falha** e **nenhum evento de usuário inválido**. Há **zero host-dias com falhas reconhecidas**; a mediana de falhas entre host-dias com falha é **não aplicável**, pois esse conjunto está vazio.

**Cobertura dos arquivos confirmada:** o relatório lista os **20 arquivos esperados**, correspondentes a `auth.log` e `auth.log.1` dos dez servidores do inventário local: `cloud_share`, `davey_mail`, `inet-dns`, `inet-firewall`, `internal_share`, `intranet_server`, `mail`, `morris_mail`, `vpn` e `webserver`. Todos os caminhos estão sob `$AIT/gather/`; nenhum arquivo do diretório de rótulos foi incluído. A análise contemplou, portanto, os logs atuais e rotacionados desses servidores. Os cinco hosts presentes na tabela de eventos representam aqueles com eventos classificados, não a quantidade total de hosts examinados.

**Relatório preservado:** `$TCC/docs/gate-ait-auth.txt`, com tamanho aproximado de 3,4 KB, confirmado por `ls -lh`.

**Estado: em verificação, ainda não aprovado.** A cobertura dos arquivos esperados foi conferida. Permanecem pendentes:

- Verificar possíveis mensagens de falha não reconhecidas pelo script, incluindo as omitidas da lista das mensagens mais comuns.
- Conferir os rótulos de ataque antes de classificar as autenticações aceitas como benignas.
- Revisar o período válido da avaliação, pois foram encontrados eventos em **20/01**, anteriores ao início de captura previamente considerado, em **21/01**.

Até o momento, não foram identificadas as falhas legítimas necessárias ao critério de aprovação do item 5. Se essa ausência for confirmada, deverá ser registrada como limitação deste testbed para avaliar falsos positivos do plano de host, sem extrapolar o resultado aos demais testbeds do AIT-LDSv2.0.
**Rótulos de ataque no `auth.log` do AIT**

O arquivo `$AIT/labels/intranet_server/logs/auth.log` contém **8 linhas de rotulagem**, no formato **JSON por linha**. Cada entrada informa o número da linha do log original (`line`), os rótulos atribuídos (`labels`) e as regras responsáveis (`rules`).

Exemplo:
{"line":145,"labels":["attacker_change_user","escalate"],"rules":{"attacker_change_user":["attacker.escalate.su.login"],"escalate":["attacker.escalate.su.login"]}}

A linha física 145 do log original contém `Successful su for jhall by www-data`, em 24/01 às 04:37:40. O evento é compatível com os rótulos `attacker_change_user` e `escalate` da entrada `"line": 145`. Trata-se de troca de usuário via `su`, não de autenticação SSH, portanto não integra os 29 eventos `Accepted` contabilizados. A correspondência indica possível numeração iniciada em 1, com confirmação pela entrada seguinte ainda pendente.
Verificação de validade: o AIT não é 100% benigno

O AIT-LDSv2.0 é uma base de avaliação de detecção de intrusão: cada testbed contém uma **cadeia de ataque multietapa** (varreduras, upload de webshell, quebra de senha, escalonamento de privilégio, exfiltração por DNS). O plano afirma que "todo disparo sobre o AIT é falso positivo por construção" — isso só é verdade **depois de excluir as linhas rotuladas como ataque**.

```bash
find $AIT -path '*labels*' -name 'auth.log*' | head
find $AIT -path '*labels*' -name 'auth.log*' -exec sh -c 'echo "== $1 ($(wc -l < "$1") linhas rotuladas)"; head -2 "$1"' _ {} \;
```

Se houver rótulos em `auth.log`, anote quantas linhas e o formato de uma entrada (em geral, um JSON por linha com o número da linha do log e os rótulos). Confira uma delas contra o log real — abra o `auth.log` correspondente na linha indicada (`sed -n '<N>p' <arquivo>`) e veja se é mesmo um evento de ataque. Isso confirma se a numeração começa em 1 ou em 0, detalhe que o parser da Semana 2 precisa.

**Aprovado se:** existem logins legítimos **e** falhas legítimas fora das linhas rotuladas.
Item 5b — existência de dados de rede no AIT

Resultado: aprovado quanto à existência dos arquivos. Foram encontrados:

Diretório

Arquivos identificados

$AIT/gather/inet-firewall/logs/suricata/

PCAPs, eve.json e fast.log

$AIT/gather/vpn/logs/suricata/

PCAPs, eve.json e fast.log

$AIT/gather/webserver/logs/suricata/

Pelo menos um PCAP

Também foram encontrados registros com campos SRC= e DST= nos arquivos syslog* e kern.log* de $AIT/gather/inet-firewall/logs/.

A primeira consulta foi limitada a dez resultados; portanto, a relação acima não constitui um inventário completo.

Consequência: existem fontes candidatas para construir o plano de rede do AIT. A disponibilidade não está restrita aos arquivos do firewall de borda.
**Item 6 — formatos compatíveis**

O relatório agregado do CAM-LDS apresenta 597 linhas ISO 8601 e 609 linhas syslog, incluindo 482 linhas do sshd. O relatório do AIT apresenta 6.818 linhas syslog, incluindo 130 linhas do sshd. Os formatos encontrados são suportados pelo parser previsto.

**Resultado: parcialmente atendido.** A compatibilidade de formatos está confirmada. Falhas e sucessos foram reconhecidos no CAM-LDS; no AIT, foram reconhecidos 29 sucessos e nenhuma falha. Permanece pendente a verificação completa das mensagens não classificadas para descartar variantes de autenticação não reconhecidas.

As consultas de exemplo com `find ... | head -1` não retornaram linhas de falha. Esse resultado não permite concluir ausência na base, pois cada consulta examinou apenas um arquivo `auth.log`, sem garantir a escolha de um host com falhas e sem incluir os arquivos rotacionados.
**Extra — alinhamento de relógios**

**CAM-LDS — alvo puppet**

O ano **2025** foi confirmado pelo timestamp Unix do `auditd`. A falha de autenticação do PID **3610**, usuário `admin` e origem `192.42.1.174`, aparece às **12:42:35** no `auth.log` e às **12:42:34 UTC** na conversão do `auditd`, em 12/12/2025.

A diferença exibida de um segundo atende ao critério do gate. O `facts.json` declara **`UTC` e `+0000`**, corroborando o deslocamento zero.

O início do `hydra` no `attackmate.json`, às **12:42:33.203732**, precede a primeira falha no `auth.log`, às **12:42:35**, por aproximadamente **1,8 segundo**. Essa comparação atende ao critério de proximidade temporal. Embora o timestamp do AttackMate não declare fuso, ele é consistente com o alinhamento observado nesse episódio.

**AIT-LDSv2.0 — testbed russellmitchell, host intranet_server**

O evento `Accepted publickey for jhall`, registrado no `auth.log` em **23/01 às 16:30:46**, foi correlacionado com a auditoria pelo PID **25184**, processo `/usr/sbin/sshd`, conta e IP de origem **`172.19.131.174`**.

No arquivo `$AIT/gather/intranet_server/logs/audit/audit.log`, foram encontrados:

| Registro | Timestamp Unix | Horário UTC |
|---|---|---|
| `USER_ACCT`, conta `jhall`, sucesso | `1642955446.971` | `2022-01-23 16:30:46.971 UTC` |
| `USER_START`, conta `jhall`, sucesso | `1642955448.187` | `2022-01-23 16:30:48.187 UTC` |
| `USER_LOGIN`, identificador `1002`, sucesso | `1642955448.243` | `2022-01-23 16:30:48.243 UTC` |

O `USER_ACCT` está no mesmo segundo do evento aceito no `auth.log`. Os registros seguintes correspondem à abertura da sessão e ao login. A comparação confirma o ano **2022** e é compatível com deslocamento **zero**, sem correção adicional de segundos.

**Parâmetros do parser**

| Base e host verificado | `--year` | `--tz-offset`, em minutos |
|---|---:|---:|
| CAM-LDS, variante puppet, alvo puppet | 2025 | 0 |
| AIT-LDSv2.0, russellmitchell, intranet_server | 2022 | 0 |

A validação acima foi realizada nos hosts e eventos identificados. O alinhamento com os PCAPs será conferido no item 7.
**Checkpoint da Parte 1 — consolidação**

A inspeção ampliada das mensagens SSH não classificadas do AIT apresentou 12 categorias, totalizando 101 mensagens. Com os 29 eventos `Accepted`, elas explicam as 130 linhas do `sshd`. Não foram encontradas mensagens adicionais de falha de autenticação. O resultado permanece: **29 sucessos, zero falhas, zero host-dias com falhas e mediana de falhas por host-dia com falha não aplicável**. Os sucessos continuam sendo uma contagem anterior à aplicação dos rótulos.

O arquivo `$AIT/labels/intranet_server/logs/auth.log` contém oito entradas JSON, referenciando as linhas 145 a 152. A comparação com o log original confirma **numeração iniciada em 1** no arquivo verificado, especialmente pela correspondência da linha 147 com a sessão do `su` e da linha 148 com a nova sessão do `systemd-logind`.

| Item | Resultado |
|---|---|
| 1 — falhas com IP e usuário | Aprovado. |
| 2 — login bem-sucedido após falhas | Aprovado. |
| 3 — corroboração pelo `auditd` | Aprovado: 16 falhas, coincidentes com o `auth.log` da variante puppet. |
| 4 — AttackMate utilizável | Parcial: passos e inícios identificados; términos exatos não demonstrados. |
| 5 — classe benigna no AIT | Parcial: não foram identificadas falhas legítimas. A contagem de sucessos ainda deve ser tratada conforme os rótulos e o período válido da avaliação. |
| 5b — plano de rede no AIT | Existência confirmada: PCAPs e `eve.json` disponíveis. |
| 6 — formatos compatíveis | Compatibilidade técnica verificada, sem variante de falha identificada entre as mensagens não classificadas. Permanece a ressalva de inexistência de exemplos de falha no AIT analisado. |
| Extra — relógios | Aprovado nos hosts verificados: CAM `--year 2025 --tz-offset 0`; AIT `--year 2022 --tz-offset 0`. |

A Parte 1 foi percorrida, com resultados parciais documentados. A ausência de falhas legítimas no testbed russellmitchell deve orientar o ajuste metodológico no CP1. O próximo passo operacional é o **Bloco B — item 7, inspeção dos PCAPs**.

**Item 7 — seleção do PCAP para investigar o ataque**

Os quatro arquivos encontrados pertencem ao diretório de captura do host `inetfw` e foram lidos pelo `capinfos`. Seus intervalos foram conferidos com apresentação explícita em UTC.

Foi selecionado o arquivo:

`$TCC/data/raw/camlds_pcaps/scenario_3_ssh_puppet/scenario_3_ssh_puppet/inetfw/logs/log/suricata/log.pcap.1765542807`

Características verificadas:

- **848.328 pacotes**.
- Início: **2025-12-12 12:33:27.736199 UTC**.
- Término: **2025-12-12 12:45:25.143118 UTC**.
- Duração: **717,406919 segundos**.

Esse intervalo abrange o episódio SSH identificado nos logs, aproximadamente entre 12:42:33 e 12:42:55 UTC. A escolha automática pelo maior tamanho havia selecionado um arquivo posterior ao episódio.

**Estado:** legibilidade e cobertura temporal confirmadas. A presença do tráfego do atacante, a contagem de conexões e o alinhamento dos eventos de rede com os logs de host permanecem em verificação. A consulta inicial considera as portas 22 e 10022.
**tráfego SSH identificado**

No PCAP selecionado, foram encontrados 313 pacotes com origem 192.42.1.174, destino 172.17.100.122 e porta de destino 22. Os IPs correspondem ao atacante e ao alvo reposerver/puppet identificados nos logs de host.

**Item 7 — PCAP legível, tráfego do atacante e alinhamento temporal**

**Resultado: aprovado no escopo do gate.**

Foi analisado o PCAP:

`$TCC/data/raw/camlds_pcaps/scenario_3_ssh_puppet/scenario_3_ssh_puppet/inetfw/logs/log/suricata/log.pcap.1765542807`

O arquivo é legível e cobre o episódio SSH investigado. Foram encontrados **313 pacotes** com origem `192.42.1.174`, destino `172.17.100.122` e porta de destino `22`, correspondentes ao atacante e ao alvo `reposerver/puppet`.

A consulta de pacotes com `SYN=1` e `ACK=0` retornou **21 registros**. Após remover repetições da combinação de `tcp.stream` e porta de origem, permaneceram **21 conexões distintas com SYN observado**.

**Alinhamento temporal — 12/12/2025:**

| Evento | Horário UTC |
|---|---|
| Início do `hydra` no AttackMate, interpretado conforme o alinhamento validado | 12:42:33.203732 |
| Primeiro SYN selecionado | 12:42:33.998535 |
| Primeira falha no `auth.log` do alvo | 12:42:35 |
| Último SYN selecionado | 12:42:54.804278 |

O primeiro SYN ocorre aproximadamente 0,795 segundo após o início do `hydra` e antecede a primeira falha de autenticação em aproximadamente um segundo, atendendo ao critério de proximidade temporal.

As 21 aberturas observadas concentram-se em **20,805743 segundos**, dentro da janela padrão de cinco minutos. O volume supera 10 aberturas, mas a contagem definitiva de `Nn` depende da verificação das durações e da aplicação da definição de conexão curta. O SYN isoladamente não comprova estabelecimento completo da conexão.

Evidência preservada em `$TCC/docs/gate-camlds-puppet-syn.tsv`.

## 2026-10-15 — Encerramento da triagem de `santos` — opção (b)

### Proveniência e preparação

- Base: AIT-LDS v2.1, testbed `santos`, registro Zenodo `19483937`, conforme o guia operacional. DOI específico ainda não conferido.
- Pacote adquirido: `santos_no-pcaps.zip`, com tamanho local exibido de `551M`.
- MD5 de referência: `cb484a2c55ea03c63c556f0531fe8367`. Conferência local: `SUCESSO`.
- Teste interno do ZIP: `No errors detected in compressed data`.
- Extração concluída com status `0`, volume de `6,8G` e **12.165 arquivos**.
- Raiz efetiva: `/dados/lucca/tcc-nids-hids/data/raw/ait_ldsv2_1/santos_triagem`, contendo `gather`, `labels` e `dataset.yaml`.
- `$SANTOS` persistido em `env/env.sh` e conferido após carregamento.
- `$AIT` preservado em `/dados/lucca/tcc-nids-hids/data/raw/ait_ldsv2/russellmitchell`; os resultados do primeiro testbed, adquirido na versão v2.0, permanecem separados.

Uma tentativa anterior de extração falhou com status `9` porque `SANTOS_ZIP` e `SANTOS_EXTRACT` estavam vazias. A contagem zero daquela tentativa era inválida. Após restaurar os caminhos, a extração foi concluída.

A busca encontrou três diretórios chamados `gather`: dois pertencem aos playbooks Ansible; a árvore de dados confirmada é `$SANTOS/gather`.

### Metadados e período

Conteúdo de `$SANTOS/dataset.yaml`:

- `name`: `processed_santos_scenario`
- `start`: `2022-01-14T00:00:00`
- `end`: `2022-01-18T00:00:00`

O intervalo previsto para avaliação é **[2022-01-14 00:00:00, 2022-01-18 00:00:00)**. Os metadados não apresentam fuso ou offset. O relógio dos hosts de `santos` ainda não foi validado; não foi assumido offset zero por analogia com outro testbed.

### Cobertura e resultados brutos

Foram encontrados **30 diretórios de hosts** diretamente em `gather`. O inventário identificou **20 arquivos de autenticação em dez hosts**, sendo um `auth.log` e um `auth.log.1` por host.

O relatório de `ssh_auth_stats.py`, executado com `--top 200`, leu exatamente esses 20 arquivos. Nenhum caminho lido pertence a `labels` ou `attacker_0`.

| Medida | Resultado bruto |
|---|---:|
| Linhas reconhecidas como syslog | 6.744 |
| Linhas de `sshd` | 148 |
| Sucessos (`accepted`) | 38 |
| Falhas (`failed`) | 0 |
| `invalid_user` | 0 |
| Host-dias com falhas | 0 |
| Mediana de falhas nos host-dias com falhas | Não aplicável — conjunto vazio |

Os sucessos distribuem-se em 36 eventos do usuário `ait`, originados de `10.229.3.27`, e dois de `gmorgan`, originados de `172.21.128.119`. Essas identificações não comprovam benignidade.

A distribuição nominal por data é: **29 sucessos em 13/01, dois em 16/01 e sete em 18/01**. Comparando apenas os carimbos apresentados, os grupos de 13/01 e 18/01 ficam fora da janela declarada. Essa observação não substitui a normalização temporal. Os dois sucessos de 16/01 também não foram aprovados como amostra benigna.

As 148 mensagens de `sshd` foram reconciliadas em **38 sucessos + 110 mensagens não classificadas**. As 110 mensagens aparecem em 11 categorias; `--top 200` comporta todas elas. Os grupos exibidos não revelaram falhas de autenticação omitidas pelo reconhecimento. Timeout, desconexão e ausência de identificação SSH não foram contados como erros de senha.

### Resultado e limites

A opção **(b) foi executada com resultado negativo para o requisito de encontrar falhas SSH benignas**: não foram observadas falhas SSH nos arquivos examinados, após conferir o inventário e as categorias não classificadas.

O **item 5 permanece parcial**. A validação de rótulos e relógios de `santos` não foi concluída; os números elegíveis de sucessos não foram apurados. A cobertura de rede de `santos` não foi validada nesta triagem.

Os resultados não constituem medição de falsos positivos: o motor B1/B2/B3 ainda não foi executado. Este recorte não permite demonstrar redução de FP de B3 em relação a B2 baseada em falhas SSH benignas.

**Encaminhamento recomendado para o CP1:** propor o caminho (a), preservar os resultados dos dois testbeds e explicitar os limites da comparação. A adoção de (a) ainda depende de decisão explícita. Não iniciar automaticamente outro testbed ou aquisição adicional de PCAPs.

### Evidências e horas

- `$TCC/docs/md5-ait-santos-v2_1.txt`
- `$TCC/docs/zip-test-ait-santos-v2_1.txt`
- `$TCC/docs/extracao-ait-santos-v2_1.txt`
- `$TCC/docs/gate-ait-santos-auth.txt` — existência conferida; tamanho exibido de `3,4K`.
- `$SANTOS/dataset.yaml`

Tempo ativo da aquisição, preparação e triagem: **pendente de informação**. Tempo de espera pelo download: **pendente de informação**. Registrar separadamente em `$TCC/docs/horas.md`; ainda não é possível verificar o cumprimento do orçamento de 2–3 horas ativas.

## 2026-10-15 — Decisão após a opção (b): adoção do caminho (a)

**Decisão: prosseguir com GO com ajuste de desenho, adotando o caminho (a).**

A investigação adicional prevista na opção (b) foi concluída em `santos`. Após conferir os arquivos examinados e o reconhecimento das mensagens, foram observados 38 sucessos SSH brutos e zero falhas. O primeiro testbed, `russellmitchell`, permanece registrado separadamente, com 29 sucessos brutos e zero falhas.

O item 5 permanece parcial: não foi encontrado o substrato de falhas SSH benignas necessário para testar a redução de falsos positivos de B3 em relação a B2 nesse recorte.

O trabalho prosseguirá com o CAM e com os recortes AIT cuja elegibilidade for validada. B1/B2/B3 serão mantidos como configurações do mesmo motor. A comparação entre elas ficará limitada aos recortes com telemetria correspondente e critérios de avaliação documentados.

Os sucessos brutos do AIT não serão tratados automaticamente como atividade benigna. Rótulos, período da simulação, relógios e exposição observável deverão ser definidos antes das métricas. Zero alertas ou zero falsos positivos somente poderão ser apresentados como resultados após a execução do motor.

Os dados e resultados negativos dos dois testbeds serão preservados. A inclusão de `santos` na ingestão não fica automaticamente aprovada por esta decisão.

O próximo entregável é o relatório CP1, conforme a seção 3.2, incorporando esta decisão, as evidências disponíveis, as limitações e as pendências. O tempo ativo da investigação permanece pendente de registro em `docs/horas.md`.

### 16/10/2026 — Disponibilidade das ferramentas — seção 4.0

`command -v apptainer suricata tshark` retornou somente `/usr/bin/tshark`. Apptainer e Suricata não foram encontrados no PATH da sessão. A ingestão de host pode prosseguir; `tshark` permanece como alternativa para a etapa de rede.

### 17/10/2026 — Seção 4.4: ingestão de autenticação do CAM `puppet`

Execução concluída com status 0: quatro arquivos processados e 32 eventos gravados em `$TCC/data/processed/ecs/host/authlog_camlds_puppet.parquet`. Existência conferida com `ls`; tamanho exibido de 14K.

Contagens:
- `ssh_login/failure`: 16, todas no host `puppet`.
- `ssh_login/success`: oito — quatro em `puppet`, dois em `inetfw`, um em `corpdns` e um em `linuxshare`.
- `ssh_invalid_user/failure`: oito em `puppet`, mantidos separados das falhas de login.

O total de falhas de login em `puppet` corresponde ao gate. A conferência detalhada por IP, usuário e horário permanece pendente. Os quatro sucessos do host ainda não foram discriminados por usuário.

### 17/10/2026 — Seção 4.4: ingestão de autenticação de `russellmitchell`

Execução concluída com status 0: 20 arquivos processados e 29 eventos gravados em `$TCC/data/processed/ecs/host/authlog_ait_russellmitchell.parquet`. Existência conferida com `ls`; tamanho exibido de 14K.

Todos os eventos são `ssh_login/success`: nove em `davey-mail`, sete em `inet-dns`, três em `intranet-server`, três em `mail` e sete em `morris-mail`. Nenhuma falha ou mensagem `ssh_invalid_user` foi produzida.

As contagens brutas correspondem ao gate. A seleção da amostra benigna e a conferência detalhada dos eventos permanecem pendentes.

17/10/2026 — Seção 4.5: executor `scripts/q.py` e consulta `sql/views_host.sql` executados com status 0. A view `host` retornou 61 eventos, compatíveis com os 32 do CAM e 29 de `russellmitchell`. Banco `data/processed/eventos.duckdb` conferido, com tamanho exibido de 268K. O total inclui oito eventos `ssh_invalid_user`.

### 17/10/2026 — Seção 4.5: conferência por cenário, host, IP e usuário

A consulta `sql/check_host.sql` terminou com status 0 e retornou 12 grupos, totalizando 53 eventos `ssh_login`: 16 falhas e 37 sucessos. Os oito eventos `ssh_invalid_user` foram excluídos pelo filtro de ação.

No CAM `puppet`, para o atacante `192.42.1.174`:

| Usuário | Falhas | Sucessos |
|---|---:|---:|
| admin | 7 | 0 |
| root | 5 | 0 |
| john | 4 | 2 |

As contagens correspondem ao gate. Os quatro sucessos do host `puppet` dividem-se em dois de `john`, do atacante, e dois de `aecid`, de `172.17.100.201`.

O CAM possui seis sucessos de `aecid` nos quatro hosts apresentados e dois sucessos de `john`, totalizando oito. O papel e a elegibilidade da atividade de `aecid` não foram certificados apenas pela identidade.

Em `russellmitchell`, os 29 sucessos brutos dividem-se em 23 de `ait`, de `192.168.230.221`, e seis de `jhall`, de `172.19.131.174`. Não foram encontradas falhas.

Os horários apresentados são os extremos de cada grupo, incluindo falhas e sucessos; não representam uma listagem individual dos logins aceitos. A seleção por período, rótulos e contexto permanece pendente.

- 17/10/2026 — Seção 4.5: configuração de processamento de
  russellmitchell examinada. `servers.yaml` declara UTC; o template
  obtém o fuso dos fatos Ansible; `input.conf` atribui esse fuso aos
  eventos e `system.conf` o utiliza.
  Para a consulta exploratória, adotada a janela
  [2022-01-21T00:00:00Z, 2022-01-25T00:00:00Z).
  A interpretação UTC dos limites é uma inferência apoiada na
  configuração local e no código documentado de `dataset.trim`;
  o metadado original não explicita offset e a versão exata do
  processador original não foi identificada.
  Contagens sem rótulo não constituem ainda a amostra benigna final.

  Referência:
  https://ait-aecid.github.io/kyoushi-dataset/reference/processors/

  - 17/10/2026 — Seção 4.5: `sql/ait_benigno.sql` executado com
  status 0, sob a interpretação operacional UTC documentada.
  Na janela [2022-01-21T00:00:00Z, 2022-01-25T00:00:00Z),
  permaneceram seis sucessos SSH sem rótulo: três em
  intranet-server e três em mail. Cada host apresentou dois
  sucessos em 21/01 e um em 23/01.
  Foram observadas zero falhas, zero autenticações rotuladas
  e zero valores nulos em `labels.attack`.
  Dos 29 sucessos brutos, 23 ficaram fora da janela.
  A classificação benigna e a cobertura observável permanecem
  em validação. As quatro linhas da consulta não constituem
  um denominador de exposição. Não houve medição de FP;
  o item 5 permanece parcial.

  - 17/10/2026 — Seção 4.6: ingestão da auditoria CAM puppet
  concluída com status 0: quatro arquivos e 84 registros.
  Saída: `data/processed/ecs/host/auditd_camlds_puppet.parquet`.
  Foram extraídas 16 falhas `auditd_user_auth`, concordantes
  em quantidade com o gate. Os 32 registros de falha
  `auditd_user_login` não serão somados como novas tentativas.
  A auditoria utiliza `host.name=reposerver`, enquanto o
  auth.log utiliza `puppet`; normalização pendente antes da
  correlação. A comparação dos IPs e horários entre os
  parquets ainda será executada.

  - 17/10/2026 — Auditoria AIT russellmitchell reprocessada após
  normalização de intranet_server → intranet-server.
  Execução com status 0; preservadas as contagens de sete
  arquivos e 30 registros, distribuídos igualmente entre
  intranet-server e mail. Comparação entre fontes ainda pendente.

  - 18/10/2026 — Seção 4.6: comparação entre fontes CAM executada
  com status 0 para puppet e origem 192.42.1.174.
  Ambas apresentam 16 falhas nas ações selecionadas.

  Horários em UTC, em 12/12/2025:

  | Fonte / ação | Falhas | Primeiro registro | Último registro |
  |---|---:|---|---|
  | auditd.log / auditd_user_auth | 16 | 12:42:34.368 | 12:42:36.864 |
  | system.auth / ssh_login | 16 | 12:42:35 | 12:42:39 |

  Diferenças entre os extremos: 0,632 s no início e 2,136 s
  no fim. Conferência agregada de contagem e alinhamento
  temporal atendida para esse recorte.
  A consulta não verifica correspondência individual entre
  todos os registros. As fontes não serão somadas em Nh.

  - 18/10/2026 — Seção 4.7: executados os testes de
  tests/test_authlog.py e tests/test_auditd.py.
  Resultado: 8 passed in 0.27s; status 0.
  Os testes complementam as conferências realizadas nos dados
  ingeridos e na comparação entre as fontes de host.