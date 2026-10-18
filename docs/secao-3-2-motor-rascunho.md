# 3.2 Motor de correlação — rascunho parcial após a Semana 4

## 3.2.1 Entrada e contrato operacional

O núcleo do motor foi implementado em Python como uma etapa offline separada da ingestão. A entrada consiste em uma lista explícita de seis arquivos Parquet, identificados por base, cenário e fonte. Antes do processamento, são verificados os campos necessários, as contagens de referência, a consistência entre início, fim e duração e as identidades dos registros.

A configuração utilizada é identificada como semana4_v1. O manifesto de cada execução registra os hashes das entradas, da configuração e dos arquivos de código, além das versões do ambiente e da referência Git disponível. As saídas permitem rastrear as contribuições dos contadores até o caminho e a linha do log de autenticação ou até o PCAP e o stream da conexão.

A seleção para esta etapa compreende o alvo puppet no CAM e os hosts intranet-server e mail no AIT russellmitchell. Os demais registros permanecem nos arquivos de ingestão, com exclusões explícitas no processamento do núcleo. No AIT, aplica-se o intervalo [21/01/2022, 25/01/2022), interpretado operacionalmente em UTC. A ausência de fuso explícito nos metadados e as limitações de cobertura continuam registradas.

## 3.2.2 Janela temporal e contadores

O núcleo utiliza uma janela deslizante de cinco minutos, representada por (t−300 s, t], com limite esquerdo aberto e direito fechado. Eventos situados exatamente no limite esquerdo deixam de contribuir. A expiração é processada mesmo quando não chegam novas observações.

São mantidos três contadores distintos:

- Nh: falhas de autenticação system.auth/ssh_login, por base, cenário, alvo, origem e usuário.
- Nn_rede: conexões curtas por base, cenário, origem e destino/serviço, independentemente da identificação de usuário.
- Nn_associado: subconjunto de Nn_rede atribuível a um único usuário com a evidência disponível naquele instante.

Registros auditd são utilizados como corroboração na ingestão, sem incrementar Nh. Mensagens ssh_invalid_user também não são somadas às falhas de autenticação, evitando contar novamente manifestações potencialmente relacionadas à mesma tentativa. Logins aceitos podem fornecer evidência de associação ao usuário, mas não incrementam Nh.

Uma conexão curta é definida operacionalmente como TCP destinado à porta 22, com SYN inicial observado e duração positiva de até cinco segundos, medida até o primeiro FIN/RST. O corte de cinco segundos foi escolhido após a inspeção inicial e possui caráter exploratório. O primeiro FIN/RST é um sinal de encerramento, não prova de conclusão completa do fechamento TCP.

Conexões sem duração permanecem com valor ausente e não são classificadas como curtas. O indicador event.outcome da rede não é interpretado como resultado de autenticação SSH.

Os limiares de cinco falhas de host e dez conexões de rede estão preservados na configuração. Nesta etapa, o núcleo calcula contadores e suas contribuições; a emissão de alertas será implementada posteriormente.

## 3.2.3 Disponibilidade da evidência e ordem lógica

A disponibilidade da evidência é representada por um relógio lógico. Mensagens de host são disponibilizadas ao fim do segundo que contém seu timestamp. Essa convenção evita tratar um horário com resolução de segundos como se tivesse precisão de nanossegundos; nesta versão, também é aplicada uniformemente às mensagens com fração de segundo.

No plano de rede, o início fica disponível no SYN, enquanto a informação de fechamento somente fica disponível no instante do primeiro FIN/RST observado. Uma conexão só pode contribuir como curta depois desse fechamento, desde que seu início ainda pertença à janela.

Essa separação impede utilizar retrospectivamente a duração final como informação conhecida no momento da abertura. O replay não representa nem mede atrasos reais de transporte, coleta ou ingestão dos sensores.

Os eventos de um mesmo instante lógico são processados em lote antes da emissão do snapshot dos contadores. A ordenação determinística preserva a reprodutibilidade. Informações posteriores podem modificar o estado corrente da associação, mas não reescrevem snapshots já emitidos.

## 3.2.4 Associação entre conexão e usuário

A associação exige correspondência de base, cenário, alvo/serviço, IP e porta de origem, além de compatibilidade temporal. O SYN deve ocorrer entre o timestamp da mensagem de host menos 300 segundos e o fim exclusivo do segundo que contém essa mensagem.

Quando o fechamento já é conhecido, admite-se que o timestamp do host seja até um segundo posterior ao fechamento. O horizonte de associação e essa tolerância são convenções operacionais da versão semana4_v1, não constantes do protocolo SSH nem correções de fuso.

Uma mensagem com apenas uma conexão candidata pode identificar o usuário dessa conexão. Ausência de candidato ou de porta de origem mantém a associação desconhecida, sem impedir a contagem da falha de host quando os demais campos necessários estão presentes.

Quando existem múltiplas conexões candidatas ou múltiplos usuários associados à mesma conexão, a associação é tratada como ambígua. A conexão não é replicada entre usuários no contador associado. Uma atribuição inicialmente única pode tornar-se ambígua diante de evidência posterior; nesse caso, sua contribuição por usuário é retirada do estado corrente.

O contador independente de rede permanece separado dessa atribuição. O nome do host utilizado nesse plano decorre do mapa de destinos configurado, não da necessidade de consultar mensagens de autenticação para detectar atividade de rede.

## 3.2.5 Identidade, duplicação e dados incompletos

Eventos de host são identificados pela combinação de base, cenário, caminho do log original e linha física. Conexões são identificadas por base, cenário, caminho do PCAP e stream. O identificador de stream é local ao arquivo e não é tratado como global.

Repetições idênticas da mesma identidade são deduplicadas. Conteúdo divergente para uma identidade, possíveis cópias entre arquivos e sobreposições conhecidas são tratados como situações que exigem revisão antes do replay. Linhas distintas de autenticação no mesmo arquivo e segundo são preservadas, pois podem representar tentativas diferentes.

A implementação não remonta conexões divididas entre PCAPs. Conexões sem SYN não foram produzidas pelo extrator utilizado; conexões sem encerramento não contribuem para o contador de curtas. Reutilização de porta com uma conexão anterior incompleta pode produzir associação ambígua.

A seleção temporal não utiliza aquecimento anterior ao recorte AIT. Suas fronteiras podem, portanto, truncar janelas ou censurar conexões. Ausência de eventos ou presença de snapshots não comprova exposição contínua.

## 3.2.6 Verificação técnica

A verificação incluiu 23 testes do núcleo, cobrindo disponibilidade temporal, limites da janela, duração ausente, associação, ambiguidades, duplicação e integridade das saídas. A suíte completa, incluindo os oito testes anteriores de host, apresentou 31 testes aprovados.

Na execução de 18/10/2026, os seis arquivos continham 219 registros brutos. Foram selecionados 57 eventos, sendo 26 de autenticação e 31 de rede. Os 162 registros excluídos foram contabilizados por motivo: 114 de auditoria, oito por ação de host fora do contador, cinco fora do mapa de alvos/sensores e 35 fora do período pelo início.

Nenhuma duplicata exata foi removida e não houve interrupção pelas verificações de conflito implementadas. A conferência posterior dos hashes confirmou a preservação dos seis arquivos de entrada.

No CAM, para a origem 192.42.1.174 e o alvo puppet, os máximos observados foram:

| Usuário | Máximo Nh | Máximo Nn_associado |
|---|---:|---:|
| admin | 7 | 7 |
| root | 5 | 3 |
| john | 4 | 5 |

O máximo Nn_rede foi 19. Os máximos por contador podem ocorrer em instantes diferentes e não demonstram, isoladamente, satisfação simultânea de uma regra.

Para john, quatro falhas foram associadas a quatro conexões curtas distintas. Um login aceito identificou o usuário de uma quinta conexão curta, sem incrementar Nh. Outro login aceito foi associado a uma conexão sem duração, excluída de Nn. Essa composição explica a diferença entre os máximos de falhas e conexões associadas.

No AIT, foram preservadas as seis correspondências de sucessos de jhall, três por host. Cinco conexões associadas tiveram duração superior a cinco segundos e uma permaneceu sem duração. Consequentemente, os máximos Nh e Nn_associado de jhall foram zero em ambos os hosts. O máximo Nn_rede foi dois em cada destino, correspondente às conexões curtas que permaneceram sem usuário associado.

No conjunto da execução, 24 mensagens tiveram candidato único no instante da associação e duas ficaram sem candidato. Ao final, 23 conexões tinham usuário único e oito permaneceram com usuário desconhecido. Não foram reportadas ambiguidades nesta execução. As duas mensagens sem candidato eram sucessos de aecid no CAM; as oito conexões sem usuário eram quatro curtas CAM e quatro curtas AIT.

O relatório docs/semana4-verificacao.md registra a identificação da execução, os hashes, os exemplos rastreados e os resultados detalhados. A validação automática das contribuições foi complementada pela inspeção manual de exemplos CAM e das seis correspondências AIT.

## 3.2.7 Alcance e continuidade

Os resultados apresentados verificam a implementação de contadores e associação sobre os recortes selecionados. Não constituem resultados de alertas B1/B2/B3, pontuação, criticidade ou mitigação.

A aplicação ao AIT permanece técnica e exploratória. Correspondência entre os planos, ausência de falhas SSH ou ausência de usuário associado não certificam benignidade. Não foram calculados falsos positivos, FP por host-dia ou redução de FP entre configurações.

As configurações finais B1/B2/B3, a emissão de alertas, as regras Sigma, a pontuação, a criticidade e a convenção de episódios serão completadas na Semana 5. Esta seção permanece como rascunho parcial até a conclusão dessas atividades e do CP3.