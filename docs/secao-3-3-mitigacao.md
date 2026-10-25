# 3.3 Política de contenção temporizada

## 3.3.1 Separação entre detecção e ação

A camada de contenção recebe transições produzidas pelo motor de detecção. A abertura de um alerta origina uma solicitação normal, enquanto uma promoção crítica posterior pode ampliar o prazo de contenção. O adaptador utiliza o score e o TTL registrados em cada transição, evitando aplicar retrospectivamente o estado final do alerta.

As configurações B1, B2 e B3 mantêm estados separados. Uma decisão de um modo não altera o estado de contenção dos demais na comparação offline.

A simulação opera em nanossegundos lógicos sobre registros preservados. Ela representa as decisões produzidas pela política, sem modificar os eventos, as conexões ou os alertas previamente calculados. Não há realimentação contrafactual: uma aplicação simulada não remove mensagens posteriores do dataset nem demonstra interrupção de um ataque.

A implementação foi dividida entre política, reprodução offline e adaptador de laboratório. Não foi implementado um serviço de resposta integrado em tempo real aos sensores.

## 3.3.2 Chave de contenção, TTL e renovação

A chave de contenção contém configuração de detecção, dataset, cenário, host, endereço IPv4 de destino, serviço TCP/22 e endereço IPv4 de origem. O usuário permanece associado ao alerta para rastreabilidade, mas não integra a chave de firewall.

Essa definição permite que alertas de usuários distintos compartilhem uma contenção quando correspondem à mesma origem, alvo e serviço dentro do mesmo escopo. O compartilhamento não funde os episódios de detecção nem altera seus identificadores.

Uma solicitação normal propõe prazo de 900 segundos a partir da decisão. Uma promoção crítica propõe prazo de 1.800 segundos a partir da promoção. Havendo contenção ativa, o novo prazo corresponde ao máximo entre o prazo existente e o instante da solicitação acrescido do TTL solicitado.

Uma solicitação com prazo candidato menor ou igual ao vigente é registrada como retenção, sem nova atualização do executor. Dessa forma, uma solicitação posterior não reduz a duração de uma contenção já estabelecida.

Cada solicitação possui identificador que permite detectar duplicações. Uma duplicata idêntica é ignorada e não renova novamente a contenção. A reutilização do mesmo identificador com conteúdo divergente é tratada como erro.

Essa garantia vale dentro da execução. O protótipo não implementa persistência de estado para recuperação automática de um serviço, coordenação distribuída ou continuidade após reinicialização.

O encerramento do episódio de alerta não cancela antecipadamente o TTL. O estado do detector e o prazo de contenção são tratados separadamente. Ao atingir o prazo, a contenção expira antes de qualquer solicitação processada no mesmo instante lógico.

A reprodução offline drena os temporizadores restantes. Expirações que ultrapassam o período dos eventos são identificadas como projeções da política, e não como observações de tráfego posterior.

## 3.3.3 Reprodução offline e rastreabilidade

A execução offline utiliza as transições preservadas da Semana 5 e mantém os parâmetros do detector. Score e TTL são obtidos da transição correspondente ao instante da decisão, sem antecipar uma promoção crítica posterior.

O pacote de execução preserva configuração, alertas, transições, solicitações derivadas, ações simuladas, resumo e manifesto. As verificações reproduzem a política e conferem a integridade dos arquivos por hashes.

As ações são identificadas pelo executor `simulation_only`. Os registros de aplicação, renovação e expiração desse pacote não correspondem à execução de comandos de firewall na Workstation2.

Na execução de referência, os alertas B2 de admin e root compartilharam uma chave de contenção. A segunda solicitação ampliou o prazo existente. O modo B3 permaneceu sem ações porque não produziu alertas nos dados de referência; os limiares não foram reduzidos para provocar contenções.

Os resultados detalhados e a proveniência dessa execução estão registrados em `docs/cp4-relatorio.md`.

## 3.3.4 Executor de laboratório

O adaptador real foi delimitado para uma VM própria, com dois namespaces de rede conectados por um par de interfaces virtuais. A regra foi aplicada no namespace do servidor, utilizando origem `192.0.2.2`, destino `192.0.2.1` e porta TCP/22.

A porta TCP/2222 foi utilizada como controle de conectividade. O servidor de teste era uma implementação TCP mínima, sem autenticação SSH. O ensaio verificou a possibilidade de estabelecer novas conexões TCP, sem reproduzir sessões SSH ou a sequência de ataque do dataset.

A aplicação insere um elemento temporizado em um conjunto nftables. A regra de descarte consulta esse conjunto e restringe a correspondência ao destino e à porta definidos para o laboratório.

A renovação remove e reinsere o elemento no mesmo lote `nft -f`. Essa operação mantém a alteração em um único lote, sem depender de uma atualização direta do elemento que possa variar entre versões.

A expiração é delegada ao mecanismo de timeout do kernel. Seu efeito é avaliado por sondas de conectividade após os prazos, em conjunto com capturas do conjunto e dos contadores da regra.

A limpeza encerra o processo servidor e remove somente os namespaces criados pela demonstração. Os resultados dessas operações são registrados. Nenhuma ação de firewall foi executada na Workstation2.

## 3.3.5 Protocolo de demonstração e escala temporal

O script admite dois perfis: `accelerated`, que divide os tempos controlados por 150 e utiliza TTLs reais de 6 e 12 segundos, e `contract`, que utiliza os prazos integrais de 900 e 1.800 segundos.

A execução realizada utilizou exclusivamente o perfil acelerado. O perfil integral não foi executado. Portanto, a demonstração avalia o mecanismo de aplicação, renovação e expiração, sem comprovar permanência física de 15 ou 30 minutos.

O ensaio controlado incluiu:

1. Verificação de conectividade nas portas 22 e 2222 antes da aplicação.
2. Aplicação de uma contenção normal.
3. Verificação de bloqueio na porta 22 e manutenção da conectividade na porta de controle.
4. Promoção crítica com ampliação do prazo.
5. Repetição idêntica da solicitação crítica para verificar deduplicação.
6. Solicitação posterior com prazo menor, sem redução do prazo vigente.
7. Encerramento dos alertas sem remoção antecipada da contenção.
8. Verificação de bloqueio após o prazo original.
9. Verificação de conectividade após o prazo renovado.
10. Limpeza dos recursos criados.

Na sonda implementada, retorno 0 representa conexão estabelecida e retorno 2 representa timeout. O script também verifica se o processo servidor permanece ativo, para evitar atribuir indisponibilidade do serviço ao bloqueio de firewall.

Os eventos são registrados com tempo monotônico relativo ao início do script. Esses valores identificam a sequência da demonstração e os instantes de registro das verificações; não determinam o instante exato em que o kernel deixou de bloquear o tráfego.

## 3.3.6 Evidências observadas e preservação

As nove sondas da execução acelerada apresentaram os retornos esperados. A porta 22 estava acessível antes da aplicação, ficou bloqueada após aplicação e renovação, permaneceu bloqueada após o prazo original e voltou a aceitar conexão após o prazo renovado. A porta 2222 permaneceu acessível nas verificações de controle.

As capturas nftables corroboraram esse comportamento. Após a aplicação, o elemento apresentava timeout de 6 segundos. Após a renovação, apresentava timeout de 12 segundos. O elemento ainda estava presente após o prazo original e não constava do conjunto na captura posterior à expiração.

O contador da regra evoluiu de zero para três pacotes e 180 bytes, permanecendo nesse valor na captura final. Esses valores representam tráfego correspondente à regra de descarte, não autenticações SSH ou episódios independentes.

O contador inicial zerado decorre da ordem do script: a primeira captura foi realizada antes da primeira sonda bloqueada. O campo `expires` representa o prazo restante exibido no momento da captura, sem fornecer uma medição exata da duração efetiva da contenção.

A remoção dos dois namespaces terminou com retorno 0. O manifesto registrou `completed: true`, e a execução produziu o marcador `SUCCESS`.

O pacote preserva diário da execução, manifesto, lotes nftables e capturas da tabela. Sua transferência entre VM, Windows e Workstation2 foi conferida por igualdade do SHA-256. Os caminhos, hashes e resultados detalhados constam do relatório CP4.

## 3.3.7 Limites de interpretação

A política offline, os testes automatizados e a demonstração em VM constituem evidências distintas. Testes com executor substituto verificam o comportamento do código, enquanto as sondas e capturas da VM documentam o efeito do mecanismo no ambiente testado.

Os casos controlados de criticidade, renovação, retenção e duplicação não ampliam a amostra experimental CAM/AIT. A demonstração não mede interrupção do ataque CAM, bloqueios corretos ou indevidos, recuperação sob carga ou eficácia comparativa das configurações de detecção.

O serviço TCP mínimo não permite avaliar autenticação SSH ou interrupção de sessões preexistentes. Os tempos de execução de comandos e sondas são observações locais do laboratório, não MTTD ou latência de contenção do dataset.

A ausência de alertas B3 nos dados de referência foi preservada. O AIT permanece exploratório e, no recorte atual, não sustenta estimativas de redução de falsos positivos ou de bloqueios indevidos.

A análise posterior deve distinguir comportamento da implementação, resultados observados nos dados e demonstração delimitada do mecanismo. Unidades ou janelas sobrepostas não devem ser tratadas como réplicas independentes.