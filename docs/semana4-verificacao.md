# Semana 4 — verificação do núcleo

Data: 18/10/2026.
Contrato: semana4_v1.
Estado: validação técnica concluída; fechamento documental e versionamento ainda em andamento.

## 1. Identificação da execução

- Diretório: /dados/lucca/tcc-nids-hids/out/semana4/execucao-20261018T163915Z
- Git HEAD registrado na execução: 2a1e95429498ea8fb1b29f97d60a3f5475ac55d8
- Hash agregado do código: 5ddfe6a89bf996a11d953662ae874fde3ae05c43e8991f222ea812f234461660
- SHA-256 da configuração: 5b657978a3c0c40449365d18c5a1ffedc397319598b62b82bbdc4b04f9427f8b
- Python: 3.10.12.
- pandas: 2.3.3.
- Ambiente: venv do projeto em /dados/lucca/tcc-nids-hids/.venv.

O HEAD é a referência Git registrada no momento da execução, não o commit final da Semana 4. O hash agregado identifica o conteúdo dos arquivos Python do pacote motor utilizado, inclusive antes do versionamento dessas alterações. O manifesto preserva os hashes individuais.

## 2. Testes e execução

| Verificação | Resultado |
|---|---|
| Sintaxe da configuração JSON | Status 0 |
| Compilação dos módulos | Status 0 |
| Carregamento da interface | Status 0 |
| Testes do motor | 23 passed in 0.33s; status 0 |
| Suíte completa | 31 passed in 0.32s; status 0 |
| Inspeção das entradas | Status 0 |
| Execução do núcleo | Status 0 |
| Verificação das saídas gravadas | Status 0 |
| Integridade posterior das entradas | Entradas alteradas: []; status 0 |

O marcador SUCCESS contém: “semana4: contrato e replay conferidos”.

Os testes controlados verificam comportamento de software. Não constituem novos dados experimentais nem substituem a conferência dos registros reais.

## 3. Entradas e seleção

| Arquivo | Registros brutos |
|---|---:|
| authlog_camlds_puppet.parquet | 32 |
| auditd_camlds_puppet.parquet | 84 |
| authlog_ait_russellmitchell.parquet | 29 |
| auditd_ait_russellmitchell.parquet | 30 |
| tshark_camlds_puppet.parquet | 22 |
| tshark_ait_russellmitchell.parquet | 22 |
| **Total** | **219** |

Foram selecionados 57 eventos: 26 de autenticação e 31 de rede.

| Motivo de exclusão | Registros |
|---|---:|
| Ação de host fora do contador | 8 |
| Fora do mapa de alvos/sensores | 5 |
| Auditoria usada somente como corroboração | 114 |
| Fora do período pelo início | 35 |
| **Total excluído** | **162** |

Reconciliação: 219 − 162 = 57.

Nenhuma duplicata exata foi removida. Não houve interrupção por conflito de identidade ou sobreposição detectada pelas verificações implementadas. Isso não equivale a provar ausência de toda forma possível de duplicação no corpus.

Os seis Parquets permaneceram iguais aos hashes registrados no manifesto.

## 4. Contadores CAM

Alvo: puppet, 172.17.100.122:22.
Origem do atacante: 192.42.1.174.

| Usuário | Máximo Nh | Máximo Nn_associado |
|---|---:|---:|
| admin | 7 | 7 |
| root | 5 | 3 |
| john | 4 | 5 |

Máximo Nn_rede do atacante para o alvo: 19.

Os máximos são calculados separadamente e podem ocorrer em instantes diferentes. Não demonstram satisfação simultânea dos limiares nem emissão de alerta.

### 4.1 Exemplos rastreados

Log de host:
data/raw/camlds/scenario_3_ssh_puppet/scenario_3_ssh_puppet/reposerver/logs/log/auth.log

PCAP:
data/raw/camlds_pcaps/scenario_3_ssh_puppet/scenario_3_ssh_puppet/inetfw/logs/log/suricata/log.pcap.1765542807

| Usuário | Linha | Porta de origem | Stream | Horário do host em UTC | Duração da conexão |
|---|---:|---:|---:|---|---:|
| admin | 63 | 54042 | 47 | 12/12/2025 12:42:35 | 1,994366 s |
| root | 67 | 54068 | 49 | 12/12/2025 12:42:36 | 1,917692 s |

Ambas as mensagens são falhas e tiveram associação unique_at_time.

IDs do exemplo de admin:

- Host: 2e8edbdbbb865cadb01b8b44445deb237b9a740588ea218c52c0bc552a844c0f
- Rede: 867b43a10aec792034aa58bea06da0df2bcee68b532b7dfd9f574a68009ceaa6

IDs do exemplo de root:

- Host: 0de80e6012670f80c61f92cbd868f76ff8e19b2c89e42f6eccd9f97e5ab0c843
- Rede: 51012720c537b2c9f0c3ead026c182b6f40cf7e140099fd16401d090ea9b43ad

A verificação automática conferiu que contribuições de rede não precedem o fechamento e respeitam a janela. O rastreamento manual examinou exemplos selecionados, não todas as associações individualmente.

### 4.2 Composição das conexões de john

| Linha do host | Resultado | Porta | Stream | Duração |
|---|---|---:|---:|---:|
| 89 | failure | 54124 | 57 | 3,643509 s |
| 88 | failure | 54088 | 54 | 3,616857 s |
| 90 | failure | 54074 | 51 | 3,653275 s |
| 91 | success | 54130 | 60 | 0,966195 s |
| 102 | failure | 54128 | 59 | 3,507084 s |
| 108 | success | 49764 | 65 | Ausente |

As quatro falhas foram associadas a quatro conexões curtas distintas. O sucesso na porta 54130 identificou o usuário de outra conexão curta, sem incrementar Nh. O sucesso na porta 49764 foi associado a uma conexão sem encerramento observado, excluída de Nn.

Portanto, o máximo Nh = 4 e o máximo Nn_associado = 5 são coerentes com unidades distintas. O limiar host de 5 permanece inalterado; não se afirma criticidade ou disparo para john.

## 5. Associações desconhecidas

| Unidade | Estado | Quantidade |
|---|---|---:|
| Mensagens de host | unique_at_time | 24 |
| Mensagens de host | no_candidate | 2 |
| Conexões, ao final | unique | 23 |
| Conexões, ao final | unknown | 8 |

Não foram reportados estados ambíguos nesta execução.

As duas mensagens sem candidato são sucessos de aecid no puppet, origem 172.17.100.201:

- Linha 119, porta 37250.
- Linha 131, porta 33058.

Não incrementam Nh. A falta de candidato corresponde ao recorte e aos critérios implementados; não comprova ausência real de tráfego.

As oito conexões sem usuário são curtas:

- CAM puppet: portas 33976, 54086, 54100 e 54142.
- AIT intranet-server: portas 55012 e 40876.
- AIT mail: portas 59644 e 52602.

Essas conexões podem contribuir para Nn_rede quando temporalmente elegíveis, mas não para Nn_associado. Não foi atribuído usuário apenas pela coincidência do IP.

## 6. AIT russellmitchell — conferência exploratória

Foram conferidos seis sucessos de jhall, três por host, todos com associação unique_at_time.

| Host | Porta | Stream | Duração |
|---|---:|---:|---:|
| intranet-server | 38526 | 525 | 20,775692 s |
| intranet-server | 39296 | 679 | 180983,701153 s |
| intranet-server | 49828 | 1864 | Ausente |
| mail | 36256 | 2693 | 33,988347 s |
| mail | 36258 | 2792 | 125,969894 s |
| mail | 46580 | 11053 | 31,596476 s |

PCAP de intranet-server: log.pcap.1642684613.
PCAP de mail: log.pcap.1642684586.

Cinco conexões associadas são longas e uma não possui duração. Por isso, os máximos de Nh e Nn_associado de jhall foram zero em ambos os hosts. A duração longa não demonstra atividade contínua durante todo o intervalo.

O máximo Nn_rede da origem 172.19.131.174 foi 2 em cada destino. As quatro conexões curtas de 24/01 permaneceram sem usuário associado.

A correspondência técnica não certifica benignidade, cobertura contínua ou elegibilidade para métricas de falsos positivos.

## 7. Saídas e limites

A execução produziu config.json, manifest.json, events.jsonl, excluded.jsonl, trace.jsonl, links.jsonl, connections.jsonl, summary.json e SUCCESS.

O resumo registra:

- metrics_enabled: false.
- phase: semana4_contadores_sem_alertas.

Não foram calculados FP, FP/host-dia, superioridade de B3 ou eficácia de mitigação. A etapa implementa contadores e associação; não emite alertas.

Permanecem os limites do contrato: resolução temporal do host, tolerâncias operacionais de associação, conexões incompletas, ausência de remontagem entre PCAPs e fronteiras do recorte. A elegibilidade experimental do CP2 continua condicionada.

Nenhuma divergência bloqueadora permaneceu nas conferências realizadas. Associações desconhecidas foram preservadas e explicadas, sem alterar limiares para produzir correspondências.

## 8. Estado de encerramento

Validação técnica da Parte 5 concluída.

O fechamento da Semana 4 ainda depende da consolidação da redação parcial da seção 3.2, atualização de gate-notas e versionamento dos arquivos desta etapa.

A próxima fase é a Semana 5: configurações B1/B2/B3, regras e alertas, score/criticidade e conclusão do CP3.