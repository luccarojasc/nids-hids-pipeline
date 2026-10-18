## 3.1 Arquitetura de coleta, normalização e armazenamento

> Rascunho de implementação atualizado em 18/10/2026.
> Descreve a ingestão efetivamente executada. O motor de correlação
> e a avaliação experimental ainda não foram executados.

A arquitetura organiza as evidências em dois planos: rede e host.
O processamento é realizado offline sobre arquivos dos datasets,
preservando as fontes brutas e produzindo representações normalizadas
para consulta e correlação posterior.

O recorte implementado compreende a variante puppet do cenário SSH
do CAM-LDS e os dados selecionados do testbed russellmitchell do
AIT-LDSv2.0. A investigação adicional de santos foi mantida como
resultado negativo documentado, sem inclusão na ingestão atual.

A implementação utiliza parsers em Python, arquivos Parquet e consultas
SQL em DuckDB. Os campos foram organizados com base no Elastic Common
Schema (ECS), acrescidos de campos de proveniência e controle do
processamento. O uso dessa nomenclatura não implica a implantação
do stack Elastic nem a validação integral de conformidade ao ECS.

### 3.1.1 Sensores e processamento do plano de rede

A representação ativa de rede é produzida pelo TShark 3.6.2, aplicado
a PCAPs previamente coletados pelos autores dos datasets. No CAM,
foram processados quatro arquivos do sensor inetfw. No AIT, foram
processados os PCAPs disponíveis nos diretórios de intranet_server
e mail.

A escolha permite aplicar o mesmo procedimento de extração aos dois
conjuntos. O processamento é exclusivamente offline, sem captura
de interfaces da máquina utilizada no desenvolvimento.

O extrator seleciona pacotes TCP associados à porta 22 com flags SYN,
FIN ou RST. Os pacotes são agrupados pelo identificador tcp.stream,
cujo escopo é o arquivo processado. A origem da conexão é definida
pelo SYN sem ACK observado. Grupos sem esse SYN inicial não produzem
um registro de conexão.

O início da conexão é armazenado em @timestamp. O campo event.end
registra o primeiro FIN ou RST observado após o início, e event.duration
armazena a diferença em nanossegundos. A conversão dos timestamps
utiliza Decimal e representação inteira em nanossegundos.

Esse intervalo corresponde à duração observada até o primeiro sinal
de encerramento. Não comprova encerramento completo da sessão TCP
nem atividade contínua durante todo o intervalo. Conexões sem FIN/RST
observado permanecem com event.end e event.duration ausentes.

O método é identificado por:

`labels.duration_method = syn_to_first_fin_or_rst_v1`

Para a avaliação exploratória, adotou-se como conexão curta aquela
destinada à porta 22 cuja duração conhecida satisfaça
0 < d ≤ 5 segundos. O corte não é aplicado durante a ingestão:
conexões longas e incompletas permanecem no Parquet.

O limite de cinco segundos constitui uma convenção de engenharia
definida após a inspeção inicial dos dados. Não representa um padrão
do protocolo, um valor demonstrado como ótimo ou uma hipótese
registrada antes da observação das durações.

O indicador success/failure atualmente emitido pelo extrator informa
se foi observado SYN+ACK no grupo. Não representa resultado de
autenticação SSH nem comprovação de handshake completo.

Os arquivos EVE fornecidos pelo AIT foram utilizados na inspeção
inicial e na validação cruzada. O parser suricata_eve.py permanece
disponível para leitura desses registros, sem exigir a execução
local do Suricata. Entretanto, o Parquet EVE foi retirado da pasta
ativa após a extração dos PCAPs, evitando a soma de duas
representações do mesmo tráfego.

A diferença entre flow.start/flow.end do EVE e o intervalo
SYN → primeiro FIN/RST motivou a uniformização da extração.
Zeek não integra a implementação atual.

### 3.1.2 Sensores e processamento do plano de host

O plano de host utiliza auth.log e audit.log. O primeiro fornece
os eventos de autenticação SSH usados no contador de falhas;
o segundo fornece evidências de auditoria para corroboração.

O parser authlog.py reconhece mensagens sshd de autenticação aceita
ou rejeitada e mensagens de usuário inválido. Eventos de login
recebem event.action = ssh_login, enquanto mensagens de usuário
inválido recebem event.action = ssh_invalid_user.

Essa distinção evita somar automaticamente mensagens de usuário
inválido às falhas de autenticação da mesma tentativa. O contador Nh
previsto para o motor utilizará eventos system.auth / ssh_login
com resultado failure.

O parser auditd.py seleciona registros relacionados ao sshd dos tipos
USER_AUTH, USER_LOGIN, USER_ACCT, USER_START e CRED_ACQ. A extração
trata campos de mensagens PAM e nomes de conta codificados em
hexadecimal quando presentes.

Os registros de auditoria não são somados ao contador Nh.
No CAM puppet, as 16 ocorrências USER_AUTH com res=failed corroboram
as 16 falhas reconhecidas em auth.log. Outros registros de auditoria,
incluindo USER_LOGIN, não são interpretados automaticamente como
novas tentativas independentes.

Os parsers percorrem os arquivos de log e suas rotações, incluindo
arquivos comprimidos compatíveis, e excluem diretórios de rótulos
e do atacante do plano de host. São preservados caminho do arquivo,
número da linha e conteúdo utilizado pelo parser, além dos campos
de usuário, processo e origem disponíveis.

Para compatibilizar os identificadores das fontes, foram aplicados
aliases restritos ao dataset e cenário:

| Identificador na auditoria | Identificador normalizado | Recorte |
|---|---|---|
| reposerver | puppet | CAM, scenario_3_ssh_puppet |
| intranet_server | intranet-server | AIT, russellmitchell |

O identificador anterior à normalização é preservado pelo parser
de auditoria em labels.host_original.

A ingestão produziu 61 eventos de auth.log e 114 registros de auditd.
Esses totais descrevem registros normalizados, não quantidades
de tentativas independentes de autenticação.

### 3.1.3 Normalização temporal e validação cruzada

Os eventos são convertidos para UTC. Nos logs syslog sem ano ou fuso
explícito, esses valores são fornecidos ao parser conforme a validação
do recorte. Foram utilizados ano 2025 e offset zero no CAM puppet,
e ano 2022 e offset zero no AIT russellmitchell.

Timestamps ISO 8601 com deslocamento explícito preservam essa
informação na conversão. O parser de auth.log também trata a
transição de dezembro para janeiro dentro de um arquivo.

Os timestamps Unix do auditd são convertidos para UTC. A validação
direta de ano e fuso foi realizada nos recortes de puppet e
intranet-server examinados. Isso não equivale a certificar
individualmente todos os relógios dos datasets.

No CAM, as 16 falhas do atacante 192.42.1.174 aparecem em auditd
entre 12:42:34.368 e 12:42:36.864 UTC de 12/12/2025. Em auth.log,
aparecem entre 12:42:35 e 12:42:39 UTC. A concordância de contagem,
host, origem e proximidade temporal fornece corroboração agregada;
não demonstra pareamento individual de todas as ocorrências.

O teste de integração também identificou 21 aberturas de rede do
atacante entre aproximadamente 12:42:33.998535 e 12:42:54.804278 UTC.
Esse resultado verifica a presença do atacante nos dois planos,
sem constituir execução da regra de correlação.

No AIT, adotou-se operacionalmente a janela
[21/01/2022, 25/01/2022), interpretada em UTC. Os metadados do
cenário não incluem fuso explícito; a interpretação permanece
documentada como inferência operacional.

Nessa janela, foram selecionados seis sucessos de auth.log sem
rótulo de ataque atribuído pelo parser: três de intranet-server
e três de mail. Todos apresentam correspondências de rede por
sensor, IP e porta de origem, com início no mesmo segundo
registrado pelo host.

A ausência de rótulo não certifica benignidade. Da mesma forma,
a correspondência desses eventos e os limites temporais dos PCAPs
não demonstram cobertura contínua dos hosts durante quatro dias.

A futura correlação deverá considerar host/destino, IP, porta de
origem e compatibilidade temporal para associar conexões a usuários.
Associações ambíguas não autorizarão distribuir automaticamente
todas as conexões de um IP entre os usuários observados.

A classificação de uma conexão como curta somente estará disponível
após a observação do primeiro FIN/RST. O motor deverá respeitar essa
disponibilidade temporal, sem antecipar a evidência ao instante
de abertura.

### 3.1.4 Armazenamento, consulta e rastreabilidade

Os registros normalizados são armazenados em Parquet, separados
por fonte e dataset. As views host e rede consultam esses arquivos
no DuckDB; a view eventos reúne os planos por UNION ALL BY NAME.

A união alinha as colunas por nome e mantém campos ausentes como
nulos. Ela não realiza deduplicação, associação entre fontes,
seleção benigna ou classificação de episódios.

A representação ativa contém:

| Plano | Fonte | Base | Registros |
|---|---|---|---:|
| Host | system.auth | CAM | 32 |
| Host | auditd.log | CAM | 84 |
| Host | system.auth | AIT | 29 |
| Host | auditd.log | AIT | 30 |
| Rede | tshark.conn | CAM | 22 |
| Rede | tshark.conn | AIT | 22 |
| **Total** | | | **219** |

Os principais campos de identificação e proveniência são:

| Campo | Utilização |
|---|---|
| @timestamp | Horário do evento de host ou abertura da conexão |
| event.end | Primeiro FIN/RST observado na representação ativa de rede |
| event.duration | Intervalo observado em nanossegundos |
| event.dataset | Fonte do registro |
| event.action / event.outcome | Tipo e resultado ou indicador específico da fonte |
| host.name | Identificador normalizado nos eventos de host |
| source.ip / source.port | Origem, quando disponível |
| destination.ip / destination.port | Destino nos registros de rede |
| user.name / process.pid | Usuário e processo, quando disponíveis no host |
| log.file.path | Arquivo de origem |
| log.file.line | Linha de origem nos logs de host |
| labels.dataset / labels.scenario | Dataset e cenário |
| labels.stream | Identificador tcp.stream, local ao PCAP |
| labels.duration_method | Convenção usada para a duração de rede |

A rastreabilidade dos registros de rede utiliza o caminho do PCAP
e o identificador de stream. Não se atribui a esses registros
um número de linha de log de host.

As saídas anteriores foram preservadas fora da pasta ativa.
A representação EVE e a representação tshark do mesmo tráfego
não são somadas na view. Sobreposições entre capturas e reutilização
de identificadores ainda exigem critérios próprios de tratamento.

### 3.1.5 Reprodutibilidade e limites desta etapa

O código de ingestão, as consultas SQL e as decisões metodológicas
são versionados em Git. As dependências Python são registradas em
env/requirements.txt. A versão utilizada do TShark é 3.6.2.

Os registros de proveniência e integridade identificam os pacotes
examinados. Uma verificação de integridade é atribuída somente
ao arquivo efetivamente conferido, sem estender sua validade
automaticamente aos demais pacotes.

A validação dos parsers de host incluiu oito testes automatizados
aprovados. O ajuste do extrator de rede foi verificado com casos
controlados de timestamp, primeiro FIN/RST e duração ausente,
além da conferência dos resultados sobre os datasets.

As contagens observadas não equivalem a resultados do motor.
No CAM, as 21 conexões do atacante incluem 19 com duração até
cinco segundos, uma acima desse limite e uma sem duração conhecida.
Esses números ainda não representam Nn por usuário e janela.

No AIT, dez aberturas estão na janela operacional selecionada:
quatro possuem duração até cinco segundos, cinco estão acima
desse limite e uma permanece sem duração conhecida. A classificação
benigna ou maliciosa dessas conexões ainda depende da seleção
por rótulos e contexto.

Permanecem necessárias a delimitação da exposição observável,
a avaliação de sobreposições e a definição dos recortes elegíveis
à comparação pareada. Ausência de telemetria não será interpretada
como ausência de conexões ou como zero falsos positivos.

O gate não encontrou falhas SSH benignas nos testbeds examinados.
Esse limite permanece explícito: a ingestão realizada não demonstra
redução de falsos positivos de B3 em relação a B2.

As configurações B1, B2 e B3 serão implementadas no mesmo motor,
em etapa posterior. A conclusão desta etapa de ingestão não
constitui execução das regras, medição de falsos positivos
ou demonstração de eficácia da mitigação.

A revisão de elegibilidade posterior à ingestão delimitou o uso
atual do AIT à validação técnica e à exploração do motor.
Não foi estabelecido um recorte pareado elegível para métricas
de falsos positivos: os rótulos examinados não classificam
diretamente as conexões curtas, e a exposição observável permanece
não demonstrada. A implementação do motor pode prosseguir,
preservando essa restrição de avaliação.