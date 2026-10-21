# CP3 — Motor B1/B2/B3 e rastreabilidade

Data da conferência: 20/10/2026, horário de Brasília.

Status: validação do motor concluída; fechamento documental e versionamento da Semana 5 pendentes. Aprovação do orientador não presumida.

## 1. Objetivo e escopo

Concluir as três configurações do motor, seleções-base Sigma, score, criticidade, supressão e rastreabilidade, preservando a ingestão e os parâmetros da Semana 4.

A execução é offline. Mitigação e métricas de eficácia estão fora deste CP3.

## 2. Implementação e contrato

- Configuração: `config/motor-semana5.json`.
- Módulos novos: `src/motor/rules.py`, `src/motor/alerts.py` e `src/motor/detect.py`.
- Regras-base: `rules/sigma/ssh_failure.yml`, `ssh_success.yml` e `ssh_short_connection.yml`.
- Testes: `tests/test_motor_semana5.py`.
- Contrato: `docs/motor-contrato-semana5.md`.
- Seção metodológica consolidada: `docs/secao-3-2-motor.md`.

B1 conta conexões curtas independentemente do host. B2 conta falhas de autenticação por usuário independentemente da rede. B3 exige Nh ≥ 5 e Nn_associado ≥ 10 simultaneamente, para o mesmo usuário e chave de correlação.

Mantêm-se janela de 300 s, duração curta positiva e até 5 s e método `syn_to_first_fin_or_rst_v1`. Auditd permanece corroboração e não duplica Nh.

As regras Sigma descrevem seleções-base. O adaptador interpreta o subconjunto documentado; agregação temporal e estado permanecem em Python.

## 3. Execução e proveniência

Raiz do projeto: `/dados/lucca/tcc-nids-hids`.

- Execução: `out/semana5/execucao-20261021T020309Z`.
- Referência: `out/semana4/execucao-20261018T163915Z`.
- O identificador da execução usa UTC: 21/10/2026 às 02:03:09 UTC corresponde a 20/10/2026 às 23:03:09 em Brasília.
- Modos executados: B1, B2 e B3.
- Python: 3.10.12.
- pandas: 2.3.3.
- PyYAML: 6.0.3.

### Identificação por hashes

- Manifesto da referência Semana 4, SHA-256: `961c97ab2ccc5ce7fb69cd7e44d19d5f2cba942fc5628543fe7f33c32e480ffb`.
- Configuração Semana 5, SHA-256: `589d1d6ceb59fd92da10cff985e071ae2ac435ec8dba46f58de411009492ada1`.
- `git_head` registrado na execução: `99868cdc80af93dfaa283fbf2d45052f1f39668f`.

Os hashes individuais dos sete módulos constam de `sources_sha256` no manifesto desta execução. Os hashes das saídas constam de `outputs_sha256`.

O `git_head` identifica o estado do Git no momento da execução e antecede o commit desta entrega. O manifesto não será alterado para inserir o commit posterior.

### Entradas e seleções-base

A inspeção confirmou a integridade da referência, os hashes das entradas e dos módulos originais, a configuração preservada e as contagens esperadas:

| Item | Quantidade |
|---|---:|
| Registros brutos dos seis Parquets | 219 |
| Eventos selecionados | 57 |
| Eventos auth selecionados | 26 |
| Eventos de rede selecionados | 31 |
| Regras-base | 3 |
| Correspondências de falha SSH | 16 |
| Correspondências de sucesso SSH | 10 |
| Correspondências de conexão curta | 23 |

As 49 correspondências de regras-base não representam 49 alertas.

## 4. Testes e verificações

| Verificação | Resultado |
|---|---|
| Testes novos da Semana 5 | 26 aprovados em 0,40 s; status 0 |
| Suíte completa | 57 aprovados em 0,43 s; status 0 |
| Inspeção de referência, parâmetros e regras | Status 0 |
| Execução B1/B2/B3 | Status 0 |
| Verificação explícita do pacote salvo | Status 0 |
| Consulta do manifesto | Status 0 |

A suíte completa reúne oito testes de ingestão, 23 da Semana 4 e 26 da Semana 5.

Os testes cobrem independência B1/B2, disparo positivo B3 controlado, condições de não disparo, supressão, reabertura, criticidade temporal, ambiguidades e integridade.

O arquivo `SUCCESS` foi confirmado com o conteúdo:

`semana5: alertas e rastreabilidade conferidos`

A verificação confirmou hashes, reprodução das decisões e invariantes dos alertas. Essa conferência demonstra consistência com a implementação; não certifica rótulos ou eficácia experimental.

## 5. Resultados observados

| Unidade descritiva | B1: aberturas | B2: aberturas | B3: aberturas | Alertas críticos |
|---|---:|---|---:|---:|
| CAM puppet / 192.42.1.174 | 1 | 2: admin e root | 0 | 0 |
| AIT intranet-server / 172.19.131.174 | 0 | 0 | 0 | 0 |
| AIT mail / 172.19.131.174 | 0 | 0 | 0 | 0 |

Foram produzidos três episódios de alerta. Linhas de `transitions.jsonl` representam mudanças de estado e não devem ser contadas como novos alertas.

### Horários e contadores

Todos os horários abaixo são UTC, em 12/12/2025.

| Alerta | Abertura | Encerramento técnico | Nh na abertura | Nn na abertura |
|---|---|---|---:|---:|
| B1, sem usuário | 12:42:36.403263 | 12:47:34.359848 | Não aplicável | 10 |
| B2, admin | 12:42:37 | 12:47:36 | 7 | Não aplicável |
| B2, root | 12:42:39 | 12:47:36 | 5 | Não aplicável |

Identificadores completos:

- B1: `ead84772008b615cb03ce4e5eed93a34691adbeb0b817972a3406e9658e4dda9`.
- B2/admin: `df95c3c401b1369b9b3ff23aaba5664b38182ac95b081661d5187d234e1142f7`.
- B2/root: `c611cee039a4e46c6bf58e8c37d4134b28d0458bd47c699975ab1414b54b031b`.

B1 apresentou dez IDs contribuintes de rede e nenhum de host. B2 apresentou sete IDs de host para admin e cinco para root, sem contribuintes de rede. Os IDs completos estão preservados em `alerts.jsonl`.

A abertura de admin com Nh = 7 é compatível com a avaliação após o lote completo do mesmo instante lógico; o contador pode ultrapassar o limiar de cinco nesse lote.

Todos os alertas ficaram com score 50, criticidade falsa e TTL recomendado de 900 s. B1 encerrou por `network_below_threshold`; B2 por `host_below_threshold`. Esses encerramentos representam queda do predicado de detecção, não término comprovado do ataque ou expiração de bloqueio.

## 6. Não disparos e criticidade

Em B3, admin e root apresentaram avaliações com `network_below_threshold`: o requisito de host estava satisfeito, mas faltavam conexões curtas associadas suficientes. Nas demais avaliações desses usuários, ambos os contadores estavam abaixo dos limiares.

John, aecid e jhall apresentaram somente `both_below_threshold` nas avaliações listadas.

Como contexto histórico da Semana 4, os máximos Nh/Nn_associado do atacante CAM foram admin 7/7, root 5/3 e john 4/5. Nenhum usuário alcançou dez conexões curtas associadas. Máximos separados não substituem a avaliação simultânea do motor.

A criticidade produziu:

- B2: dez avaliações com `no_preexisting_active_alert`.
- B3: dez avaliações com `no_preexisting_active_alert`.

São os mesmos dez sucessos examinados em dois modos, não vinte sucessos distintos. Nenhum encontrou alerta previamente ativo na chave correspondente. Sucessos de john ou aecid não promovem alertas de admin ou root.

Contagens de snapshots representam avaliações ao longo do tempo; não são episódios de ataque, falsos negativos ou observações independentes.

## 7. Estado dos critérios de aceite

| Critério | Estado |
|---|---|
| Três modos implementados e executados | Atendido |
| Independência B1/B2 e positivo B3 controlado | Verificados pelos testes |
| Limiares e entradas preservados | Conferidos pela inspeção |
| Supressão, reabertura, criticidade e ambiguidades | Cobertos pelos testes aprovados |
| Saídas e contribuições rastreáveis | Conferidas |
| Disponibilidade temporal | Verificada pelas invariantes implementadas |
| Regras reconciliadas com o contrato | Conferidas |
| Arquivo do contrato Semana 5 | Criação confirmada |
| Seção 3.2 consolidada e notas do gate | Documentos preparados e notas atualizadas |
| Revisão dos arquivos acidentais na raiz | Quatro arquivos acidentais removidos; exclusões a registrar no commit |
| Conferência final, commit e envio da Semana 5 | Versionamento parcial realizado; entrega final pendente |

O fechamento técnico completo do CP3 será registrado após concluir a documentação e o versionamento. A aprovação do orientador permanece uma etapa distinta.

## 8. Limites mantidos

AIT permanece exploratório, sem classe benigna certificada ou exposição elegível estabelecida para FP/host-dia. Ausência de alerta não equivale a zero falsos positivos.

A unidade CAM é descritiva; seus limites operacionais não comprovam início e término exatos do ataque. O score é ordinal e não representa probabilidade calibrada. O corte de 5 s foi escolhido após inspeção, conforme já documentado.

Casos controlados validam o software e não ampliam a amostra experimental. O resultado sem disparo de B3 é admissível com os parâmetros preservados; não demonstra superioridade nem redução de falsos positivos.

O item 5 do CP1 permanece parcial. Santos continua fora da ingestão atual.

TTL de 900/1.800 s é recomendação registrada, sem aplicação de bloqueios. A continuidade prevista é a Semana 6, com interface de mitigação e eventual demonstração em VM controlada.