# Resultados das execuções delimitadas

A numeração desta seção será definida na integração ao texto final do TCC.

## Desenho da reprodução

A campanha comparou as configurações B1, baseada em rede, B2, baseada em autenticação no host, e B3, baseada na correlação entre host e rede. Foram realizadas três execuções separadas e uma execução conjunta, mantendo os parâmetros, as regras e as referências previamente estabelecidos.

O protocolo foi versionado antes da campanha. O congelamento registrou o commit e os hashes das configurações, das regras Sigma, dos módulos do motor e do próprio protocolo. Foram preservados janela de 300 segundos, limiar de host Nh ≥ 5, limiar de rede Nn ≥ 10 e duração curta positiva até 5 segundos.

As execuções utilizaram os mesmos dados e não constituem réplicas experimentais independentes. Sua finalidade foi verificar equivalência entre formas de execução, preservação das decisões e rastreabilidade dos resultados.

A inspeção das entradas confirmou 219 registros de origem e 57 eventos selecionados. As seleções-base compreenderam 16 falhas de autenticação, dez sucessos e 23 conexões curtas. Essas seleções representam evidências para o motor, não alertas.

Foram mantidas três unidades de análise: a sequência SSH observada no CAM puppet e os recortes exploratórios dos hosts intranet-server e mail do AIT russellmitchell. Os recortes AIT correspondem ao intervalo de 21/01/2022, inclusive, a 25/01/2022, exclusive, em UTC.

Os limites da unidade CAM são operacionais e não representam comprovação do término exato do ataque. Os recortes AIT não foram certificados como classe benigna.

## Resultados descritivos por unidade

As quatro execuções e suas verificações terminaram com status 0. A conferência confirmou equivalência dos alertas, transições, decisões, verificações de criticidade e comparações por unidade entre os modos separados e a execução conjunta. Os resultados comparados também coincidiram com a referência preservada da Semana 5.

| Unidade | B1: episódios | B2: episódios | B3: episódios |
|---|---:|---:|---:|
| CAM puppet | 1 | 2 | 0 |
| AIT intranet-server | 0 | 0 | 0 |
| AIT mail | 0 | 0 | 0 |

As nove combinações de unidade e modo produziram três episódios de alerta, todos na sequência CAM. Não houve promoção crítica.

B1 utiliza uma chave de rede, enquanto B2 e B3 incluem usuário na decisão. Dessa forma, as contagens não representam unidades de detecção idênticas: o episódio B1 não deve ser replicado por usuário, e os dois episódios B2 não significam dois ataques independentes.

Os episódios CAM tiveram origem em `192.42.1.174` e alvo puppet. Seus instantes, em UTC de 12/12/2025, foram:

| Modo | Usuário | Abertura | Encerramento | Contador na abertura | Score |
|---|---|---|---|---|---:|
| B1 | Não aplicável | 12:42:36.403263 | 12:47:34.359848 | Nn = 10 | 50 |
| B2 | admin | 12:42:37 | 12:47:36 | Nh = 7 | 50 |
| B2 | root | 12:42:39 | 12:47:36 | Nh = 5 | 50 |

O episódio B1 encerrou quando o contador de rede ficou abaixo do limiar. Os episódios B2 encerraram quando o contador de host ficou abaixo do limiar. Esses encerramentos decorrem do estado do detector e da janela temporal; não indicam o término comprovado da atividade de ataque.

Os recortes AIT não produziram alertas em nenhum dos modos. Esse resultado descreve o comportamento do motor nas unidades selecionadas, sem caracterizar uma estimativa de falsos positivos.

## Rastreabilidade e interpretação dos não disparos

A conferência dos episódios encontrou todos os identificadores de evidência referenciados nos alertas. As evidências estavam disponíveis antes ou no instante da abertura correspondente.

O episódio B1 utilizou dez evidências de rede e nenhuma evidência de host. Os episódios B2 utilizaram sete falhas de admin e cinco de root, sem evidências de rede na decisão de abertura.

Os registros preservam a ligação entre alerta, evento normalizado e fonte de origem. Para rede, a rastreabilidade inclui o arquivo PCAP e o stream; para host, inclui o arquivo de autenticação e a linha correspondente. Os identificadores completos e exemplos estão em `docs/semana7-relatorio.md`.

B3 não produziu episódios. As decisões registraram 164 snapshots com ambos os contadores abaixo dos limiares e 54 com o contador de rede abaixo do limiar. Essas quantidades representam estados avaliados ao longo do replay, não observações independentes ou episódios adicionais.

O contador de conexões por origem utilizado por B1 não equivale ao contador de rede associado ao usuário utilizado por B3. Portanto, o disparo B1 não implica que o componente de rede do predicado B3 tenha atingido seu limiar.

As verificações de criticidade registraram dez ocorrências de ausência de alerta anterior ativo em B2 e dez em B3. Os sucessos avaliados não encontraram alerta anterior ativo na chave correspondente. Alertas de admin ou root não autorizam promoção crítica para john. B1 não utiliza evidência de host para promoção crítica.

Os limiares foram mantidos durante toda a campanha. A ausência de alertas B3 foi registrada como resultado observado, incluindo o não disparo na sequência CAM, sem alteração posterior dos parâmetros para obter um resultado desejado.

## Ameaças à validade e alcance dos resultados

A equivalência entre execuções demonstra consistência operacional sob as entradas e configurações preservadas. Não constitui validação independente da correção do detector, pois as execuções compartilham implementação, regras e dados.

Repetir o replay não aumenta a amostra experimental. As quatro execuções, as nove linhas de comparação e os snapshots internos não devem ser tratados como réplicas independentes para inferência estatística.

A comparação entre modos exige considerar suas diferentes chaves de decisão e modalidades de evidência. Menor quantidade de alertas não demonstra automaticamente maior qualidade, e o resultado B3 sem episódios não sustenta uma alegação de superioridade sobre B1 ou B2.

Os recortes AIT permanecem exploratórios, sem classe benigna confirmada e sem exposição observável estabelecida para métricas. Assim, zero alertas não permite concluir zero falsos positivos. Não foram calculados precisão, recall, F1, FP/host-dia ou redução percentual de falsos positivos.

Os instantes de abertura são resultados temporais do replay. Não foram apresentados como MTTD ou latência de detecção, pois tais medidas exigem uma origem temporal elegível e critérios próprios de avaliação.

A demonstração da Semana 6 constitui evidência separada do mecanismo de contenção em VM. Ela utilizou um serviço TCP mínimo e TTLs acelerados, sem comprovar interrupção do ataque CAM. Nenhuma ação real de firewall foi executada nesta campanha.

Santos permanece excluído da ingestão. O item 5 do gate permanece parcial, e os resultados não ampliam as conclusões para outros testbeds, cenários ou condições de operação.

A proveniência da campanha, os hashes, os identificadores dos episódios e os caminhos das evidências estão documentados em `docs/semana7-relatorio.md`. O protocolo está em `docs/protocolo-semana7.md`.