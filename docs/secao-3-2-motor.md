# 3.2 Motor de correlação e decisões de detecção

## 3.2.1 Arquitetura e delimitação

O motor processa offline os registros normalizados produzidos pela ingestão descrita na seção 3.1. A implementação separa seleção e validação das entradas, reprodução temporal dos contadores, seleção das evidências-base e geração de decisões. As configurações B1, B2 e B3 compartilham o núcleo determinístico e diferem pelas fontes disponibilizadas e pelo predicado de disparo. Não se utiliza um detector aprendido nem se executa mitigação durante a reprodução dos datasets.

O contrato da Semana 4 selecionou 57 eventos entre 219 registros armazenados: 26 mensagens de autenticação e 31 conexões de rede. Essa quantidade decorre do mapa de alvos e sensores, ações admitidas e intervalos selecionados, não representa número de ataques ou tamanho de amostra independente. Registros auditd corroboram o host e não duplicam as falhas contadas. A rede ativa de CAM e AIT utiliza extrações TShark com o mesmo método de duração. As saídas Suricata previamente inspecionadas permanecem como evidência histórica, sem somatória ao conjunto ativo.

## 3.2.2 Tempo, identidade e disponibilidade

Cada evento preserva identidade, dataset, cenário, alvo, serviço, origem e proveniência. O host mantém caminho e linha de log; a rede mantém caminho do PCAP e stream local. Identificadores de stream não são globais e não autorizam união automática entre arquivos. Contagens e contribuições são rastreáveis por IDs estáveis no pacote de execução.

Timestamps são representados em nanossegundos UTC. Mensagens auth com resolução de segundos representam o intervalo de um segundo iniciado no timestamp registrado e ficam disponíveis no seu limite superior. A abertura de conexão disponibiliza os elementos necessários à associação; sua condição de curta somente pode ser usada após o primeiro FIN ou RST observado. Assim, conhecer o arquivo completo no processamento offline não permite antecipar a evidência no relógio lógico.

O núcleo processa eventos em ordem determinística e produz o estado após o lote completo de cada instante. A janela é (t−300 s,t], com a fronteira inferior excluída. A contribuição é posicionada pelo início do evento, respeitando sua disponibilidade. Um registro que só se torna conhecido depois de sair da janela não é retroativamente contado. Duração ausente não é zero; primeiro FIN/RST é uma convenção observacional, não demonstra encerramento completo ou atividade contínua durante todo o intervalo.

## 3.2.3 Associação entre rede e host

A associação exige compatibilidade de dataset, cenário, alvo/serviço, IP e porta de origem, além dos critérios temporais do contrato. O início de rede deve estar dentro do limite de idade de 300 s e anteceder o limite superior do segundo do host; quando o fechamento já é conhecido, admite-se a tolerância documentada de 1 s. Essas escolhas tratam a resolução do auth.log sem atribuir um usuário diretamente a conteúdo SSH cifrado.

Uma conexão sem evidência suficiente permanece desconhecida. Múltiplos candidatos ou usuários incompatíveis tornam a atribuição ambígua e impedem a contribuição individual para B3. A evolução da associação é temporal: uma atribuição inicialmente única pode se tornar ambígua depois. O histórico de decisões não é apagado para incorporar retrospectivamente conhecimento futuro.

Sucesso de autenticação também pode associar uma conexão, mas não aumenta o contador de falhas. A conexão do sucesso não precisa ser curta para essa associação. O total de conexões do IP não é atribuído a todos os usuários.

## 3.2.4 Contadores e configurações

Nh conta mensagens ssh_login de falha por usuário. Mensagens Invalid user e eventos auditd não são somados novamente como tentativas. Nn_rede conta conexões distintas com duração observada positiva e até 5 s; Nn_associado restringe esse conjunto às conexões unicamente associadas ao usuário no instante da decisão. O corte de 5 s foi adotado após inspeção e é tratado como escolha exploratória, não como limiar calibrado independentemente.

| Configuração | Evidência disponível | Predicado |
|---|---|---|
| B1 | Rede | Nn_rede≥10 por origem/alvo/serviço |
| B2 | Auth | Nh≥5 por origem/alvo/serviço/usuário |
| B3 | Rede e auth | Nh≥5 e Nn_associado≥10 para a mesma chave e instante |

B1 é executado sem mensagens auth e B2 sem eventos de rede. Conferências de proveniência do pacote inteiro não alteram essa independência da decisão. Os limiares são preservados entre os modos, sem reduzir requisitos de B3 em função dos resultados observados.

## 3.2.5 Regras-base em Sigma

Três regras descrevem seleções de falha SSH, sucesso SSH e conexão curta. O adaptador local interpreta um subconjunto explícito de Sigma: seleção conjuntiva, igualdade de literais, comparadores gt/lte e teste de presença exists, com condition: selection. Operações sem suporte e chaves YAML duplicadas são rejeitadas. A seleção de rede inclui a fase de fechamento observado, representada pelo adaptador, e não utiliza sucesso de transporte como prova de autenticação.

As correspondências são reconciliadas com as evidências admitidas pelo núcleo. Agregação temporal, associação, contadores, supressão e criticidade são implementados em Python. Não se declara implementação de um backend Sigma geral nem portabilidade automática dessa correlação para qualquer SIEM. Os arquivos YAML e sua versão são preservados com a execução.

## 3.2.6 Score, alertas e criticidade

O score diagnóstico é uma escala ordinal: S_h=min(50,floor(50×Nh/5)) e S_n=min(50,floor(50×Nn/10)). B1 usa S_n, B2 usa S_h e B3 usa o mínimo dos dois. O disparo continua condicionado aos limiares explícitos; excesso de evidência de um plano não compensa insuficiência do outro. O alerta ordinário recebe 50 e sua promoção crítica recebe 100. Esses valores não são probabilidades e não sustentam, por si, uma curva de precisão-revocação.

Um episódio técnico abre na transição da condição de falsa para verdadeira. Enquanto verdadeira, novas aberturas da mesma chave são suprimidas. A transição para falso encerra o episódio e permite nova abertura futura. Quando a reprodução termina antes do encerramento, o fim permanece ausente, com indicação de censura. O episódio técnico não representa automaticamente um ataque ou um bloqueio.

A promoção crítica se aplica a B2/B3 e exige sucesso posterior de autenticação na mesma chave de dataset, cenário, alvo/serviço, origem e usuário. O alerta deve estar ativo antes do lote atual e sua condição-base deve continuar satisfeita. O timestamp bruto do sucesso deve ser estritamente posterior à abertura e sua disponibilidade deve ocorrer até 300 s depois dela. Empates ou sucesso no mesmo lote de abertura não bastam. Em B3, a associação do sucesso deve ser única após o lote inteiro; a duração dessa conexão pode ser longa ou ausente. Há no máximo uma promoção por episódio. B1 não recebe criticidade derivada de host.

Cada decisão registra TTL recomendado de 900 s, elevado a 1.800 s na promoção crítica. Esses campos documentam a interface prevista com a etapa de mitigação. Nesta versão não existe aplicação, renovação ou expiração real de bloqueio; encerramento do alerta e TTL são conceitos distintos.

## 3.2.7 Unidade descritiva e limites da comparação

A unidade comum é definida por dataset, cenário, alvo/serviço, origem e intervalo. Para cada modo registra-se se houve abertura no intervalo, quantidade e IDs. Os usuários são preservados nos detalhes B2/B3, sem replicar o alerta B1 para cada usuário. Contagens de alertas em chaves diferentes não são comparadas como observações independentes.

Para CAM, a versão atual adota [2025-12-12T12:42:33.203732Z,2025-12-12T12:47:56Z). O início utiliza o início registrado do passo hydra com interpretação operacional UTC; o fim é a disponibilidade do último sucesso observado de john acrescida de 300 s. A convenção foi definida depois da inspeção e não substitui um término de ataque comprovado. O começo de outro passo AttackMate não é empregado como término demonstrado do anterior. As unidades descritivas não restringem adicionalmente o replay.

AIT usa o intervalo [2022-01-21,2022-01-25) UTC para intranet-server e mail. Correlação técnica e ausência de rótulo em uma mensagem não certificam benignidade. Sem falhas SSH benignas elegíveis e exposição observável estabelecida, não se calculam FP/host-dia nem se conclui redução de falsos positivos. Também não se tratam os dois hosts como réplicas experimentais independentes.

## 3.2.8 Verificação e reprodutibilidade

A validação combina testes controlados, conferência das entradas e reprodução sobre os eventos selecionados. Testes verificam disparo/não disparo, independência de B1/B2, caso positivo B3, disponibilidade temporal, fronteiras, associação ambígua, supressão, reabertura, criticidade e integridade. Os casos controlados validam comportamento de software e não ampliam os datasets experimentais.

O pacote preserva configurações, eventos, correspondências de regras, contadores, decisões, contribuintes, alertas, transições, avaliações de criticidade, unidades descritivas e manifesto com versões e hashes. A reprodução verifica consistência das saídas com a implementação; não constitui certificação independente de rótulos ou desempenho científico. Os resultados efetivamente obtidos, caminhos de execução e limitações do aceite estão registrados em docs/cp3-relatorio.md.

O CP3 admite resultado sem disparo com os parâmetros fixados. As conclusões de eficácia e a demonstração de mitigação dependem de etapas posteriores, com escopo e elegibilidade próprios.