# Protocolo — Semana 7

Versão: semana7_v1.
Escopo: reprodução técnica e comparação descritiva das unidades existentes.

## Configuração fixa

Usar `config/motor-semana5.json` e as regras referenciadas, sem alterar o detector ou a referência da Semana 4.

Parâmetros preservados:

- Janela: 300 segundos.
- Limiar de host: Nh ≥ 5.
- Limiar de rede: Nn ≥ 10.
- Duração curta: positiva e até 5 segundos.
- Método: `syn_to_first_fin_or_rst_v1`.

Preservar associação, disponibilidade temporal, score, criticidade e convenção de episódios implementados.

Não haverá ajuste de limiares após observar resultados, novas aquisições, reingestão, expansão automática para outros hosts, dados sintéticos como amostra experimental ou mitigação real.

## Unidades e elegibilidade

| Unidade | Recorte | Uso permitido |
|---|---|---|
| cam_puppet_ssh_observado_v1 | Unidade operacional CAM definida na configuração | Descrição da sequência e dos alertas |
| ait_intranet_exploratorio_v1 | [21/01/2022, 25/01/2022), UTC, intranet-server | Exploração técnica |
| ait_mail_exploratorio_v1 | [21/01/2022, 25/01/2022), UTC, mail | Exploração técnica |

Os limites CAM são operacionais e não comprovam o término exato do ataque. Os recortes AIT não são certificados como classe benigna. Ausência de rótulo não será convertida em benignidade.

Santos permanece fora da ingestão e da campanha.

## Execuções e comparação

Executar B1, B2 e B3 separadamente e uma execução conjunta `all`, sobre a mesma configuração.

As execuções separadas verificam isolamento e equivalência; não constituem novas amostras ou réplicas independentes.

Comparar existência e quantidade de episódios por unidade, usuários quando aplicável, criticidade e instantes de abertura. B1 não será replicado por usuário. A quantidade de alertas B1 não é diretamente equivalente à quantidade de alertas por usuário em B2/B3.

Os modos usam as modalidades previstas:

- B1: rede.
- B2: auth.
- B3: correlação entre host e rede.

Mesma unidade de observação não significa mesma chave de decisão.

## Métricas e limites

`metrics_enabled` permanece `false`.

Não calcular precisão, recall, F1, FP/host-dia, redução percentual de FP, bloqueios indevidos, eficácia de mitigação ou significância estatística neste escopo.

Não usar dez hosts multiplicados por quatro dias como exposição. Não inferir cobertura contínua de captura a partir do primeiro e do último pacote. Não contar repetições de replay como novas observações.

Tempos de abertura são instantes do replay, não MTTD. Nenhum atraso será chamado de latência de detecção sem uma origem temporal elegível e documentada.

Menor quantidade de alertas não será interpretada automaticamente como superioridade de uma configuração.

## Critérios de aceite

- Referências verificadas.
- Configuração e fontes inalteradas durante a campanha.
- Quatro pacotes executados e verificados.
- Equivalência por modo entre execuções separadas e conjunta.
- Reconciliação com a referência preservada da Semana 5.
- Tabelas derivadas e rastreáveis.
- Interpretação dos não disparos e da criticidade.
- Documentação versionada.

Qualquer divergência suspende o fechamento: preservar a execução e documentar o diagnóstico.

Alterações comportamentais exigem nova versão e nova campanha, preservando a anterior.