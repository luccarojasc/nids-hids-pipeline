# Semana 7 — Execuções delimitadas

Data da campanha: 25/10/2026, America/Sao_Paulo.
Identificador temporal da pasta em UTC: 20261026T011425Z.

Estado: execuções, equivalência, tabelas e rastreabilidade conferidas. Consolidação documental e versionamento final em andamento.

## 1. Objetivo e protocolo

Reproduzir as configurações B1, B2 e B3 separadamente e em execução conjunta, preservando os parâmetros existentes e verificando consistência com a referência da Semana 5.

O protocolo foi registrado em `docs/protocolo-semana7.md` antes da campanha.

As quatro execuções utilizam os mesmos dados. Sua finalidade é verificar consistência operacional e isolamento entre modos; não constituem quatro amostras experimentais independentes.

Não houve nova aquisição, reingestão, alteração dos limiares ou execução de mitigação real nesta campanha.

## 2. Proveniência e congelamento

Campanha:

`out/semana7/campanha-20261026T011425Z`

Commit congelado:

`8836ef9dcd9706c43a31535262b975aceae39360`

Configuração utilizada:

`config/motor-semana5.json`

SHA-256 da configuração:

`589d1d6ceb59fd92da10cff985e071ae2ac435ec8dba46f58de411009492ada1`

SHA-256 do protocolo:

`0ed3756dcf00dec9a0ad60cb6c15252e65fc98ea0257d81ff214dd32eb9586ea`

Referência dos resultados:

`out/semana5/execucao-20261021T020309Z`

Referência do núcleo:

`out/semana4/execucao-20261018T163915Z`

Referência da política offline, verificada na retomada:

`out/semana6/execucao-20261021T111452Z`

O arquivo `freeze.json` preserva o commit e os hashes das configurações, do protocolo, das regras Sigma e dos sete módulos do motor. Os manifestos dos pacotes preservam a proveniência de cada execução.

O script de conferência foi criado após o congelamento para analisar as saídas. Ele não modifica o detector nem integra as fontes congeladas do motor; seu versionamento pertence à entrega documental e analítica da Semana 7.

## 3. Verificações realizadas

| Verificação | Resultado |
|---|---|
| Referência da Semana 5 | Status 0 |
| Referência da Semana 6 | Status 0 após repetição da consulta interrompida |
| Inspeção do motor | Status 0 |
| Execução B1 | Status 0 |
| Execução B2 | Status 0 |
| Execução B3 | Status 0 |
| Execução conjunta all | Status 0 |
| Verificação dos quatro pacotes | Status 0 em todos |
| Compilação do script de conferência | Status 0 |
| Equivalência e geração das tabelas | Status 0 |
| Leitura das decisões | Status 0 |
| Rastreabilidade dos alertas | Status 0 |

A primeira tentativa de verificar a referência da Semana 6 foi interrompida por Ctrl+C durante a importação de bibliotecas, retornando status 130. A repetição terminou com status 0. Não foi identificada corrupção do pacote nessa verificação.

A inspeção preservou 219 registros de entrada, 57 eventos selecionados e três regras. As seleções-base totalizaram 16 falhas, dez sucessos e 23 conexões curtas.

O script `scripts/semana7_conferir.py` confirmou:

- Integridade das fontes e configurações registradas no congelamento.
- Correspondência dos commits e fontes nos manifestos.
- Integridade das saídas declaradas nos manifestos.
- Equivalência de alertas, transições, decisões e verificações de criticidade entre modos separados e execução conjunta.
- Equivalência desses resultados com a referência da Semana 5.
- Equivalência das comparações por unidade.
- Manutenção das métricas desabilitadas.

Os verificadores individuais também reproduziram as decisões e conferiram os invariantes temporais de cada pacote.

## 4. Resultados por unidade

| Unidade | Classificação | Modo | Episódios abertos | Usuários |
|---|---|---|---:|---|
| CAM puppet | Sequência observada com limites operacionais | B1 | 1 | Não aplicável à chave de rede |
| CAM puppet | Sequência observada com limites operacionais | B2 | 2 | admin, root |
| CAM puppet | Sequência observada com limites operacionais | B3 | 0 | — |
| AIT intranet-server | Exploratório, sem classe benigna confirmada | B1 | 0 | — |
| AIT intranet-server | Exploratório, sem classe benigna confirmada | B2 | 0 | — |
| AIT intranet-server | Exploratório, sem classe benigna confirmada | B3 | 0 | — |
| AIT mail | Exploratório, sem classe benigna confirmada | B1 | 0 | — |
| AIT mail | Exploratório, sem classe benigna confirmada | B2 | 0 | — |
| AIT mail | Exploratório, sem classe benigna confirmada | B3 | 0 | — |

Foram produzidas nove linhas de comparação e três episódios de alerta. O número de novas amostras independentes é zero.

As nove linhas representam combinações de unidade e modo. Não são nove réplicas independentes.

B1 utiliza uma chave de rede, enquanto B2 e B3 incluem usuário na decisão. Portanto, um episódio B1 não deve ser replicado por usuário nem comparado diretamente aos dois episódios B2 como se representassem contagens de ataques distintos.

## 5. Episódios CAM

Todos os episódios ocorreram no host puppet, com origem `192.42.1.174`. Os horários abaixo são UTC, em 12/12/2025.

| Modo | Usuário | Abertura | Encerramento | Nh na abertura | Nn na abertura | Score | Crítico |
|---|---|---|---|---:|---:|---:|---|
| B1 | — | 12:42:36.403263 | 12:47:34.359848 | — | 10 | 50 | Não |
| B2 | admin | 12:42:37 | 12:47:36 | 7 | — | 50 | Não |
| B2 | root | 12:42:39 | 12:47:36 | 5 | — | 50 | Não |

O episódio B1 terminou por `network_below_threshold`. Os episódios B2 terminaram por `host_below_threshold`.

Esses encerramentos são definidos pelo estado do detector e pela expiração das evidências na janela. Não comprovam o término do ataque.

### Identificadores dos episódios

B1:

`ead84772008b615cb03ce4e5eed93a34691adbeb0b817972a3406e9658e4dda9`

B2 — admin:

`df95c3c401b1369b9b3ff23aaba5664b38182ac95b081661d5187d234e1142f7`

B2 — root:

`c611cee039a4e46c6bf58e8c37d4134b28d0458bd47c699975ab1414b54b031b`

## 6. Rastreabilidade das evidências

Todos os identificadores de evidência utilizados na abertura dos três alertas foram encontrados em `events.jsonl`. A disponibilidade de cada evidência era anterior ou igual ao instante de abertura do alerta correspondente.

### B1

Foram conferidas dez evidências de rede e nenhuma evidência de host.

Exemplo de evidência:

`06e0466813b08dbcbedad0610e2911a3d22b62d436a72fad7faa9823cb505cc2`

Origem: PCAP `log.pcap.1765542807`, sensor inetfw, stream 46.

Disponibilidade: `1765543356381927000` ns, correspondente a 12:42:36.381927 UTC de 12/12/2025.

A evidência estava disponível antes da abertura às 12:42:36.403263 UTC.

### B2 — admin

Foram conferidas sete evidências de host e nenhuma evidência de rede.

Exemplo de evidência:

`2e8edbdbbb865cadb01b8b44445deb237b9a740588ea218c52c0bc552a844c0f`

Origem: `reposerver/logs/log/auth.log`, linha 63, host normalizado como puppet.

Disponibilidade: `1765543356000000000` ns, correspondente a 12:42:36 UTC de 12/12/2025.

A evidência estava disponível antes da abertura às 12:42:37 UTC.

### B2 — root

Foram conferidas cinco evidências de host e nenhuma evidência de rede.

Exemplo de evidência:

`0de80e6012670f80c61f92cbd868f76ff8e19b2c89e42f6eccd9f97e5ab0c843`

Origem: `reposerver/logs/log/auth.log`, linha 67, host normalizado como puppet.

Disponibilidade: `1765543357000000000` ns, correspondente a 12:42:37 UTC de 12/12/2025.

A evidência estava disponível antes da abertura às 12:42:39 UTC.

Os exemplos acima não substituem os conjuntos completos de IDs preservados em `alerts.jsonl`. Os caminhos completos de origem estão em `events.jsonl`.

## 7. Não disparos e criticidade

As verificações de criticidade registraram:

| Modo | Motivo | Quantidade |
|---|---|---:|
| B2 | no_preexisting_active_alert | 10 |
| B3 | no_preexisting_active_alert | 10 |

Não houve promoção crítica. Os sucessos avaliados não encontraram alerta anterior ativo na chave correspondente. Um alerta de admin ou root não autoriza promoção de criticidade para john.

B1 não utiliza evidências de host para promoção crítica, conforme o contrato preservado.

Os snapshots B3 foram distribuídos da seguinte forma:

| Motivo | Quantidade |
|---|---:|
| both_below_threshold | 164 |
| network_below_threshold | 54 |

Essas quantidades descrevem estados avaliados pelo motor ao longo do replay, não episódios independentes.

B3 não produziu alerta porque o predicado conjunto não foi satisfeito nas avaliações registradas. O total de conexões por origem utilizado por B1 não pode ser substituído pelo contador de rede associado a usuário em B3.

O resultado B3 sem alerta foi preservado e não foi usado como justificativa para reduzir limiares.

## 8. Artefatos da campanha

Na pasta da campanha foram preservados:

- `freeze.json`.
- Logs `B1.log`, `B2.log`, `B3.log` e `all.log`.
- Pacotes `B1/`, `B2/`, `B3/` e `all/`, com manifestos e saídas.
- `conferencia/resultado.json`.
- `conferencia/unidades.csv`.
- `conferencia/episodios.csv`.

As tabelas são produtos derivados. Os arquivos JSONL, as configurações e os manifestos preservam os detalhes necessários à rastreabilidade.

As saídas em `out/semana7/` permanecem fora do Git. O protocolo, o script de conferência e os documentos integram o versionamento.

## 9. Limites e interpretação

A equivalência observada demonstra consistência entre as formas de execução e a referência preservada. Não constitui nova validação independente do detector nem amplia a amostra experimental.

O recorte CAM utiliza limites operacionais. Os instantes de abertura são resultados do replay, não MTTD. Os encerramentos dos alertas não são términos comprovados do ataque.

AIT permanece exploratório, sem classe benigna confirmada. Zero alertas não equivale a zero falsos positivos demonstrado. Não foram estimadas precisão, recall, F1, FP/host-dia, exposição observável ou redução de falsos positivos.

A ausência de alertas B3 não demonstra superioridade sobre B1 ou B2. Ela descreve o comportamento da configuração preservada neste recorte, incluindo seu não disparo na sequência CAM observada.

A demonstração de contenção da Semana 6 permanece uma evidência separada de mecanismo em laboratório. Não houve repetição de firewall ou avaliação de eficácia de mitigação nesta campanha.

Santos permanece fora da ingestão, e o item 5 do gate permanece parcial.

## 10. Estado de fechamento

As execuções, verificações dos pacotes, equivalência, tabelas, leitura dos motivos e rastreabilidade foram concluídas.

O texto de resultados foi consolidado em `docs/resultados-semana7.md`, e as notas de continuidade foram atualizadas em `docs/gate-notas.md`.

Permanecem a conferência final do commit e do envio ao repositório remoto. As saídas da campanha permanecem preservadas fora do Git.