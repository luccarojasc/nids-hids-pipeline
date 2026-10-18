## 3.1.2 Sensores e processamento do plano de host

> Rascunho elaborado em 18/10/2026.
> Implementação de referência: commit `3d7026e`.
> A seleção final da amostra benigna permanece em validação.

O plano de host utiliza registros de autenticação SSH provenientes
de `auth.log` e registros de auditoria de `auditd`. Nesta etapa,
foram processados o cenário `scenario_3_ssh_puppet` do CAM-LDS e o
testbed `russellmitchell` do AIT-LDSv2.0. O testbed Santos foi
preservado como resultado negativo da investigação de viabilidade
e permaneceu fora da ingestão.

Foram implementados dois parsers em Python. O parser de `auth.log`
reconhece cabeçalhos nos formatos syslog e ISO 8601 e extrai mensagens
de falha e sucesso de autenticação, classificadas como `ssh_login`.
Mensagens `Invalid user` são conservadas separadamente, como
`ssh_invalid_user`, para evitar sua soma automática às falhas de
autenticação. O processamento contempla arquivos rotacionados e
comprimidos em GZIP e exclui da varredura os diretórios de rótulos
e de atacantes.

O parser de auditoria seleciona registros relacionados ao executável
`sshd` nos tipos `USER_AUTH`, `USER_LOGIN`, `USER_ACCT`, `USER_START`
e `CRED_ACQ`. A extração considera os campos aninhados da mensagem
de auditoria e a possibilidade de nomes de conta codificados em
hexadecimal. Como uma autenticação pode produzir registros de
credenciais, conta e sessão, essas ações permanecem distintas.
A auditoria é utilizada como fonte de corroboração, sem acrescentar
suas ocorrências à contagem de falhas obtida de `auth.log`.

A normalização emprega nomes de campos do Elastic Common Schema
(ECS), acompanhados de informações de proveniência específicas
do projeto.

| Campos | Informação representada |
|---|---|
| `@timestamp` | Instante do registro normalizado para UTC |
| `event.dataset` | Fonte: `system.auth` ou `auditd.log` |
| `event.action` e `event.outcome` | Tipo de ação e resultado reconhecido |
| `host.name` | Identificador normalizado do host |
| `source.ip`, `source.port` e `user.name` | Origem e conta, conforme disponibilidade na fonte |
| `process.name` e `process.pid` | Processo associado ao registro |
| `log.file.path` e `log.file.line` | Arquivo de origem e número físico da linha, iniciado em 1 |
| `event.original` | Conteúdo da linha utilizado pelo parser |
| `labels.dataset` e `labels.scenario` | Base e cenário de origem |
| `labels.attack` | Rótulos associados à linha de autenticação, quando disponíveis |
| `event.sequence` | Número de série do registro de auditoria |
| `labels.host_original` | Identificador obtido pela auditoria antes da normalização |

No parser de autenticação, o ano e o deslocamento temporal são
parâmetros explícitos para os registros que não fornecem essas
informações. Foram utilizados ano 2025 e deslocamento zero no CAM
puppet, e ano 2022 e deslocamento zero em russellmitchell. Timestamps
ISO 8601 com offset explícito têm esse offset respeitado. O parser
também trata a passagem de dezembro para janeiro dentro de um
mesmo arquivo syslog.

Na auditoria, os instantes são obtidos dos timestamps em época Unix
e representados em UTC. A comparação direta entre fontes realizada
no gate abrangeu os hosts puppet e intranet-server. As configurações
de processamento examinadas no AIT também declaram UTC; a validação
da amostra final deve preservar o escopo das verificações realizadas
em cada host.

Durante a ingestão, foram identificadas divergências entre nomes
de diretórios e nomes presentes nos logs de autenticação.
Foram aplicadas as correspondências `reposerver` → `puppet`,
restrita ao cenário CAM puppet, e `intranet_server` →
`intranet-server`, restrita a russellmitchell. O identificador
anterior foi mantido em `labels.host_original` na auditoria.

Os registros normalizados foram gravados em arquivos Parquet
separados por fonte e cenário. Uma view no DuckDB permite consultá-los
em conjunto, conciliando as colunas pelo nome. A ingestão produziu
32 registros de autenticação e 84 de auditoria no CAM, além de
29 registros de autenticação e 30 de auditoria no AIT, totalizando
175 registros. Esses totais incluem diferentes representações e
etapas de uma autenticação e não constituem uma contagem de
tentativas independentes.

A conferência agregada do ataque CAM selecionou o host puppet,
a origem `192.42.1.174` e os resultados de falha nas ações
`ssh_login` e `auditd_user_auth`, mantendo as fontes separadas.

| Fonte | Falhas | Primeiro registro UTC | Último registro UTC |
|---|---:|---|---|
| `auditd.log` | 16 | 2025-12-12 12:42:34.368 | 2025-12-12 12:42:36.864 |
| `system.auth` | 16 | 2025-12-12 12:42:35 | 2025-12-12 12:42:39 |

As diferenças entre os extremos foram de 0,632 s no início e
2,136 s no fim, compatíveis com o alinhamento temporal observado
no gate. Essa consulta confirma a concordância das contagens e
a proximidade das janelas, mas não estabelece correspondência
individual entre todos os registros.

No AIT, os rótulos são associados pelo caminho espelhado do arquivo
e pelo número original da linha. A ingestão conserva os eventos
reconhecidos; a seleção da amostra ocorre nas consultas posteriores.
O parser de auditoria não incorpora os rótulos AIT, de modo que seus
registros não são classificados automaticamente como benignos.

A consulta exploratória de russellmitchell adotou a janela
[2022-01-21T00:00:00Z, 2022-01-25T00:00:00Z), com início inclusivo
e fim exclusivo. A interpretação UTC desses limites foi registrada
como inferência apoiada nas configurações locais e no comportamento
documentado do processamento; o metadado original não informa offset
e a versão exata do processador original não foi identificada.

Nesse recorte permaneceram seis sucessos SSH sem rótulo de ataque,
três em intranet-server e três em mail, sem falhas reconhecidas.
A classificação benigna definitiva depende da análise dos papéis
de hosts e contas, dos rótulos e da cobertura observável. Dias com
eventos de autenticação não foram utilizados como denominador
automático de exposição.

A implementação foi submetida a oito testes automatizados,
todos aprovados, abrangendo classificação, conversão de fuso,
virada de ano e extração de campos de auditoria, incluindo contas
codificadas em hexadecimal. Esses testes complementam as
conferências realizadas nos dados reais.

Até esta etapa, não houve execução do motor B1/B2/B3 nem medição
de falsos positivos. A definição da amostra elegível e da exposição,
assim como a validação da telemetria de rede correspondente,
permanece necessária antes da avaliação comparativa.