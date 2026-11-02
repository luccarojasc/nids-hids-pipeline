# Semana 9 — Mapa de fontes do capítulo de resultados

Data: 02/11/2026.

## 1. Finalidade e estado

Este documento relaciona o capítulo 4 — Resultados e discussão — aos relatórios, contratos e artefatos que sustentam sua redação.

O capítulo foi redigido em `capitulos/cap-resultados.tex`, no projeto LaTeX do trabalho. O PDF da versão v1 foi revisado integralmente no capítulo 4. Os ajustes pontuais de precisão e redução de repetições foram informados como aplicados pelo autor; a versão recompilada após esses ajustes ainda não foi conferida nesta revisão.

Os relatórios técnicos são registros das etapas de desenvolvimento. Suas indicações históricas de pendências, implementação futura ou versionamento não devem ser transpostas automaticamente para a redação atual.

## 2. Mapeamento por seção

| Seção | Fontes documentais principais em `docs/` | Uso no trabalho |
|---|---|---|
| 4.1 — Delimitação dos resultados apresentados | `protocolo-semana7.md`, `protocolo-semana8.md`, `motor-contrato-semana5.md`, `cp1-relatorio.md` | Delimitar unidades, configurações, parâmetros e alcance da avaliação. |
| 4.2 — Validação técnica e qualidade das evidências | `semana4-verificacao.md`, `motor-contrato-semana4.md`, `cp3-relatorio.md`, `semana7-relatorio.md`, `cp5-relatorio.md` | Apresentar seleção, exclusões, associação, disponibilidade temporal, testes e reprodução. |
| 4.3 — Resultados das configurações B1, B2 e B3 | `resultados-semana7.md`, `semana7-relatorio.md`, `cp3-relatorio.md` | Apresentar episódios, usuários, horários e contadores de disparo. |
| 4.4 — Associação de evidências, não disparos e criticidade | `semana4-verificacao.md`, `motor-contrato-semana5.md`, `cp3-relatorio.md`, `resultados-semana7.md` | Explicar os contadores associados, o não disparo de B3 e a ausência de promoção crítica. |
| 4.5 — Sensibilidade à janela temporal | `analise-sensibilidade-semana8.md`, `cp5-relatorio.md`, `protocolo-semana8.md` | Comparar as janelas de 60, 300 e 600 segundos, preservando os demais parâmetros. |
| 4.6.1 — Política offline sobre os alertas observados | `mitigacao-contrato-semana6.md`, `cp4-relatorio.md`, `secao-3-3-mitigacao.md` | Apresentar aplicações, renovação, manutenção de prazo e expirações em tempo lógico. |
| 4.6.2 — Demonstração controlada em máquina virtual | `cp4-relatorio.md`, `secao-3-3-mitigacao.md` | Apresentar conectividade, estados do nftables, perfil acelerado e limites do ensaio. |
| 4.7 — Ameaças à validade e limites da avaliação | `cp1-relatorio.md`, `semana4-verificacao.md`, `cp3-relatorio.md`, `cp4-relatorio.md`, `cp5-relatorio.md`, protocolos das Semanas 7 e 8 | Consolidar limitações de dados, parâmetros, associação, exposição, generalização e mitigação. |
| 4.8 — Síntese dos achados | Seções 4.1–4.7 e respectivas fontes | Sintetizar resultados já apresentados, sem introduzir novos experimentos ou substituir a conclusão geral. |

## 3. Mapeamento das tabelas

A numeração abaixo corresponde ao PDF v1. Os identificadores LaTeX devem orientar futuras conferências, pois a numeração poderá mudar.

| Tabela atual | Identificador LaTeX | Evidência principal |
|---|---|---|
| 3 — Distribuição dos registros | `tab:selecao-evidencias` | Resumo de seleção da Semana 4 e `qualidade.json` da Semana 8. |
| 4 — Episódios por unidade e configuração | `tab:alertas-configuracoes` | `comparison.json` da execução conjunta da Semana 7 e `conferencia/unidades.csv`. |
| 5 — Abertura e contadores de disparo | `tab:abertura-alertas` | `alerts.jsonl` da execução conjunta da Semana 7 e `conferencia/episodios.csv`. |
| 6 — Máximos dos contadores por usuário | `tab:maximos-associacao` | `summary.json` da Semana 4, reproduzido em `qualidade.json` da Semana 8. Os máximos são individuais, não necessariamente simultâneos. |
| 7 — Duração dos episódios | `tab:duracao-sensibilidade` | Diferença entre `ended_ns` e `opened_ns` nos arquivos `w060/result.json`, `w300/result.json` e `w600/result.json`. |
| 8 — Operações da política offline | `tab:mitigacao-offline` | `summary.json` e `actions.jsonl` da execução da Semana 6. |
| 9 — Conectividade na VM | `tab:conectividade-vm` | `journal.jsonl` e capturas de estado do nftables da demonstração controlada. |

## 4. Localização dos pacotes de evidências

Caminhos relativos à raiz do repositório técnico:

- Núcleo e correlação:
  `out/semana4/execucao-20261018T163915Z/`
- Referência de alertas:
  `out/semana5/execucao-20261021T020309Z/`
- Política de mitigação offline:
  `out/semana6/execucao-20261021T111452Z/`
- Demonstração em VM:
  `out/semana6/evidencias-vm/out/demo-20261025T162436Z/`
- Campanha comparativa:
  `out/semana7/campanha-20261026T011425Z/`
- Campanha de sensibilidade:
  `out/semana8/campanha-20261027T004827Z/`

Os manifestos preservam os hashes e a proveniência das respectivas execuções. Não devem ser reescritos para refletir commits posteriores de documentação.

O diretório `out/` permanece ignorado pelo Git. O versionamento deste mapa não representa cópia de segurança dos pacotes de evidências.

## 5. Tratamento editorial das fontes

Foram incorporados os resultados numéricos conferidos, preservando unidades, escopo e significado. A redação foi adaptada para o trabalho concluído, removendo comandos operacionais e referências desnecessárias às semanas de execução.

Permanecem como documentação de suporte:

- Contratos do motor e da mitigação.
- Relatórios CP1, CP3, CP4 e CP5.
- Protocolos e relatórios de execução.
- Registros de integridade, extração e triagem.
- `gate-notas.md`, como histórico das decisões.

Os documentos de arquitetura, ingestão e funcionamento do motor serão utilizados na atualização metodológica. O arquivo `secao-3-2-motor-rascunho.md` é uma versão anterior e não deve prevalecer sobre o texto consolidado e os contratos vigentes.

Este mapa não substitui as referências bibliográficas dos conjuntos de dados, ferramentas e trabalhos científicos.

## 6. Limites preservados na redação

- B1 abriu um episódio e B2 abriu dois no CAM; B3 não abriu episódios.
- Os recortes AIT permaneceram exploratórios, sem classe benigna confirmada.
- Não foram estimadas métricas de eficácia ou taxas de falsos positivos.
- Reexecuções e variantes de janela não foram tratadas como amostras independentes.
- A sensibilidade alterou somente a janela dos contadores.
- A mitigação offline não executou firewall.
- A demonstração na VM utilizou solicitações controladas e prazos acelerados.
- A demonstração não comprovou contenção do ataque histórico.
- Santos permaneceu fora da ingestão das campanhas.

## 7. Pendências de integração

- Conferir o PDF recompilado após os ajustes da revisão.
- Preservar uma versão identificável do projeto LaTeX e do PDF correspondente.
- Conferir e inserir as referências bibliográficas dos conjuntos de dados.
- Atualizar os capítulos anteriores, ainda parcialmente redigidos como proposta.
- Harmonizar nomenclatura, siglas, objetivos e descrição metodológica.
- Revisar os avisos de compilação e a formatação global na etapa acordada.

A elaboração deste mapa não encerra essas pendências nem certifica conformidade normativa integral.