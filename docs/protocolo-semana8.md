# Protocolo de análise e sensibilidade — Semana 8

Versão: `semana8_sensibilidade_v1`.

## 1. Objetivo

Descrever o efeito da janela dos contadores sobre episódios, contagens e duração dos alertas, mantendo as mesmas evidências, critérios de elegibilidade e demais parâmetros.

A configuração principal permanece a de 300 segundos. Não será selecionada uma nova configuração principal após observar os resultados.

## 2. Grade fixada antes das execuções

| Parâmetro | Definição |
|---|---|
| Janela dos contadores | 60, 300 e 600 segundos |
| Janela principal | 300 segundos |
| Limiar de host | Nh ≥ 5 |
| Limiar de rede | Nn ≥ 10 |
| Duração curta | 0 < d ≤ 5 segundos |
| Método de duração | syn_to_first_fin_or_rst_v1 |
| Horizonte de criticidade | Fixo em 300 segundos |
| Idade máxima de associação | Fixa em 300 segundos |

Preservar resolução temporal, tolerância de encerramento, regras, score, TTL, destinos, unidades e recortes.

Somente `window_ns` será alterado nas cópias em memória das configurações do núcleo e da camada de alertas.

## 3. Executor e preservação das referências

O contrato histórico `semana5_v1` vincula o horizonte de criticidade à janela. A análise utilizará um executor específico para variar somente a janela dos contadores, sem alterar os validadores ou os arquivos históricos do motor.

O executor validará primeiro a referência original e reutilizará a função `build` do mesmo motor. O contrato externo da análise será identificado por `semana8_sensibilidade_v1`.

As referências das Semanas 4, 5 e 7 permanecerão intactas. Não serão sobrescritos seus arquivos, configurações, manifestos ou marcadores de sucesso.

A execução de 300 segundos deverá reproduzir integralmente os resultados de:

`out/semana7/campanha-20261026T011425Z/all`

Essa equivalência, incluindo a trilha de execução, é condição para interpretar as variantes de 60 e 600 segundos.

## 4. Unidades e denominadores

Serão preservadas as três unidades descritivas:

- CAM puppet: sequência SSH observada com limites operacionais.
- AIT intranet-server: recorte exploratório.
- AIT mail: recorte exploratório.

Cada janela produzirá nove combinações de unidade e modo, totalizando 27 linhas de comparação. Essas linhas não constituem 27 observações independentes.

A qualidade será descrita separando:

- 219 registros de entrada.
- 57 eventos selecionados.
- 26 mensagens de autenticação selecionadas.
- 31 conexões selecionadas.

As contagens deverão ser confirmadas na execução. Associações por mensagem e identidade por conexão possuem denominadores distintos. Durações ausentes não serão convertidas em zero.

A extensão entre o primeiro e o último pacote não será usada como prova de cobertura contínua ou exposição observável.

## 5. Comparações previstas

Comparar, por unidade, modo e janela:

- Quantidade de episódios abertos.
- Instantes de abertura e encerramento.
- Usuários envolvidos, quando aplicável.
- Contadores na abertura.
- Promoções críticas.
- Motivos de não disparo e encerramento.

Duração de episódio do detector não equivale à duração do ataque. Valores ausentes serão apresentados como ausentes ou não aplicáveis, nunca como zero medido.

Na janela de 600 segundos, encerramentos podem ultrapassar o limite operacional da unidade CAM. A unidade permanecerá fixa. Episódios que atravessarem seu limite serão identificados mediante consulta às saídas completas, sem ampliar o intervalo após observar os resultados.

As diferenças entre chaves B1 e B2/B3 serão consideradas. Alertas B1 não serão replicados por usuário.

## 6. Métricas e limites

Não serão estimados neste desenho:

- Falsos positivos e FP/host-dia.
- Precisão, recall, F1 e PR-AUC como métricas validadas de eficácia.
- MTTD.
- Eficácia de contenção do ataque CAM.

A indisponibilidade de cada medida será justificada separadamente, conforme ausência de classes certificadas, denominador de episódios elegíveis, exposição observável ou origem temporal defensável.

Não serão realizados testes estatísticos tratando replays, snapshots ou combinações de janela e modo como réplicas independentes.

AIT permanece exploratório, Santos permanece excluído e o item 5 do gate permanece parcial. Menor quantidade de alertas não será interpretada automaticamente como superioridade.

O limite de cinco segundos para conexão curta mantém seu caráter exploratório, definido após inspeção. Não será ajustado nesta análise.

A demonstração de contenção da Semana 6 permanece uma evidência separada de mecanismo em laboratório. Não haverá execução real de firewall nesta campanha.

## 7. Critérios de aceite

- Protocolo registrado antes das rodadas.
- Executor específico e testes versionados antes da campanha.
- Fontes e parâmetros preservados, exceto a janela declarada.
- Três janelas executadas e verificadas.
- Execução de 300 segundos idêntica à referência da Semana 7.
- Replay e integridade dos pacotes conferidos.
- Qualidade consolidada com denominadores explícitos.
- Tabelas e exemplos rastreáveis.
- Métricas indisponíveis e limitações documentadas.
- Relatório CP5 e textos de análise versionados.

Em caso de divergência, preservar a saída e suspender a conclusão até o diagnóstico. Alterações comportamentais exigem nova versão e nova campanha.

O fechamento técnico do CP5 não implica aprovação do orientador nem exige demonstrar superioridade de B3.